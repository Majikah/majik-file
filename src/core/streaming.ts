/**
 * MJKB v3 streaming encryption and decryption.
 *
 * This module mirrors the Rust reader/writer contract. File bytes are consumed
 * incrementally, Zstandard uses its WASM streaming API, and every encrypted
 * record is independently authenticated before it is passed to the decoder.
 *
 * A destination can contain partial output if an operation fails. Callers
 * should write to a temporary file/object and publish it only after this
 * function resolves successfully.
 */

import { AES } from "@stablelib/aes";
import { GCM } from "@stablelib/gcm";
import { SHA256 } from "@stablelib/sha256";
import {
  createCompressStream,
  createDecompressStream,
} from "@structured-world/structured-zstd";
import type {
  CompressStream,
  DecompressStream,
} from "@structured-world/structured-zstd";

import {
  AES_KEY_LEN,
  IV_LENGTH,
  MAX_GROUP_RECIPIENTS,
} from "./crypto/constants.js";
import {
  generateRandomBytes,
  mlKemEncapsulate,
} from "./crypto/crypto-provider.js";
import { secureFill } from "./crypto/zeroize.js";
import { MajikFileError } from "./error.js";
import { resolveAesKeyFromPayload } from "./mjkb-codec.js";
import { MajikFileValidator } from "./validator.js";
import {
  arrayToBase64,
  deduplicateRecipients,
  shouldCompressMime,
} from "./utils.js";
import type {
  AnyMjkbPayload,
  MajikFileEncryptionIdentity,
  MajikFileGroupKey,
  MajikFileRecipient,
  MjkbPayloadV3,
  MajikFileIdentity,
} from "./types.js";

export const MJKB_V3_STREAM_SUITE = "AES-256-GCM-CHUNKED-1";
export const DEFAULT_STREAM_CHUNK_SIZE = 1024 * 1024;
export const MIN_STREAM_CHUNK_SIZE = 64 * 1024;
export const MAX_STREAM_CHUNK_SIZE = 8 * 1024 * 1024;

const HEADER_LENGTH = 4 + 1 + IV_LENGTH + 4;
const MANIFEST_LENGTH = 8 + 8 + 8 + 32;
const GCM_TAG_LENGTH = 16;
const MAX_PAYLOAD_LENGTH = 1024 * 1024;
const SOURCE_SLICE_SIZE = 64 * 1024;
const CHUNK_AAD_DOMAIN = new TextEncoder().encode("MJKB3-CHUNK");
const MANIFEST_AAD_DOMAIN = new TextEncoder().encode("MJKB3-MANIFEST");
const MJKB_MAGIC = new Uint8Array([0x4d, 0x4a, 0x4b, 0x42]);
const UTF8 = new TextEncoder();

export interface StreamingProgress {
  bytesProcessed: number;
  totalBytes?: number;
}

/** Shared controls for large-file streaming operations. */
export interface MajikFileStreamingOptions {
  /** Chunk size in bytes. Defaults to 1 MiB; valid range is 64 KiB–8 MiB. */
  chunkSize?: number;
  /** Override the standard MIME-based compression policy. */
  compression?: boolean;
  /** Zstandard level 1–22. Defaults to 6 to match the Rust SDK. */
  compressionLevel?: number;
  /** Expected source or plaintext size, when known. */
  totalBytes?: number;
  /** Optional byte ceiling. Unset means no size limit. */
  maxBytes?: number;
  /** Abort between source reads / encrypted records. */
  signal?: AbortSignal;
  /** Called as source or plaintext bytes are processed. */
  onProgress?: (progress: StreamingProgress) => void;
}

export type MajikFileByteSource =
  | ReadableStream<Uint8Array>
  | AsyncIterable<Uint8Array>;

export interface StreamingEncryptResult {
  originalBytes: number;
  compressedBytes: number;
  chunks: number;
  /** SHA-256 of the exact plaintext stream encrypted in this operation. */
  fileHash: string;
  encryptionIv: string;
  participants: string[];
  isGroup: boolean;
  compressionAlg: string | null;
}

export interface StreamingDecryptResult {
  originalBytes: number;
  compressedBytes: number;
  chunks: number;
  fileHash: string;
  originalName: string | null;
  mimeType: string | null;
  payload: MjkbPayloadV3;
}

export type StreamingDecryptIdentity = Pick<
  MajikFileIdentity,
  "fingerprint" | "mlKemSecretKey"
>;

function validateChunkSize(chunkSize: number): void {
  if (
    !Number.isInteger(chunkSize) ||
    chunkSize < MIN_STREAM_CHUNK_SIZE ||
    chunkSize > MAX_STREAM_CHUNK_SIZE
  ) {
    throw MajikFileError.invalidInput(
      "chunkSize must be an integer between " +
        MIN_STREAM_CHUNK_SIZE +
        " and " +
        MAX_STREAM_CHUNK_SIZE +
        " bytes",
    );
  }
}

function validateOptions(options: MajikFileStreamingOptions): void {
  const chunkSize = options.chunkSize ?? DEFAULT_STREAM_CHUNK_SIZE;
  validateChunkSize(chunkSize);

  for (const [name, value] of [
    ["totalBytes", options.totalBytes],
    ["maxBytes", options.maxBytes],
  ] as const) {
    if (
      value !== undefined &&
      (!Number.isSafeInteger(value) || value < 0)
    ) {
      throw MajikFileError.invalidInput(
        name + " must be a non-negative safe integer",
      );
    }
  }
}

function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted) {
    throw signal.reason ?? new DOMException("The operation was aborted", "AbortError");
  }
}

function toSafeNumber(value: bigint, label: string): number {
  if (value < 0n || value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw MajikFileError.formatError(
      label + " exceeds JavaScript's safe integer range",
    );
  }
  return Number(value);
}

function u32be(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw MajikFileError.formatError("Invalid uint32 value in MJKB v3 stream");
  }
  const result = new Uint8Array(4);
  new DataView(result.buffer).setUint32(0, value, false);
  return result;
}

function readU32be(bytes: Uint8Array): number {
  if (bytes.length !== 4) {
    throw MajikFileError.formatError("Expected four bytes for a uint32 value");
  }
  return new DataView(bytes.buffer, bytes.byteOffset, 4).getUint32(0, false);
}

function u64be(value: bigint): Uint8Array {
  if (value < 0n || value > 0xffff_ffff_ffff_ffffn) {
    throw MajikFileError.formatError("Integer exceeds the MJKB v3 uint64 range");
  }
  const result = new Uint8Array(8);
  new DataView(result.buffer).setBigUint64(0, value, false);
  return result;
}

function readU64be(bytes: Uint8Array, offset = 0): bigint {
  if (offset < 0 || offset + 8 > bytes.length) {
    throw MajikFileError.formatError("Truncated uint64 field in MJKB v3 manifest");
  }
  return new DataView(bytes.buffer, bytes.byteOffset + offset, 8).getBigUint64(0, false);
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const length = parts.reduce((sum, part) => sum + part.length, 0);
  const result = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

/** Rust-compatible nonce: XOR the last eight base-nonce bytes with uint64 BE. */
function nonceFor(base: Uint8Array, index: bigint): Uint8Array {
  const nonce = base.slice();
  const counter = u64be(index);
  for (let i = 0; i < counter.length; i++) {
    nonce[4 + i] ^= counter[i];
  }
  return nonce;
}

function chunkAad(
  payloadHash: Uint8Array,
  index: bigint,
  plaintextLength: number,
): Uint8Array {
  return concatBytes(
    CHUNK_AAD_DOMAIN,
    payloadHash,
    u64be(index),
    u32be(plaintextLength),
  );
}

function manifestAad(
  payloadHash: Uint8Array,
  manifest: Uint8Array,
): Uint8Array {
  return concatBytes(MANIFEST_AAD_DOMAIN, payloadHash, manifest);
}

async function* iterateSource(
  source: MajikFileByteSource,
): AsyncGenerator<Uint8Array> {
  if (
    typeof source === "object" &&
    source !== null &&
    "getReader" in source &&
    typeof source.getReader === "function"
  ) {
    const reader = source.getReader();
    try {
      while (true) {
        const result = await reader.read();
        if (result.done) return;
        if (!(result.value instanceof Uint8Array)) {
          throw MajikFileError.invalidInput(
            "Streaming source must yield Uint8Array chunks",
          );
        }
        yield result.value;
      }
    } finally {
      reader.releaseLock();
    }
    return;
  }

  for await (const chunk of source as AsyncIterable<Uint8Array>) {
    if (!(chunk instanceof Uint8Array)) {
      throw MajikFileError.invalidInput(
        "Streaming source must yield Uint8Array chunks",
      );
    }
    yield chunk;
  }
}

class AsyncByteReader {
  private readonly iterator: AsyncIterator<Uint8Array>;
  private current: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
  private offset = 0;
  private done = false;

  constructor(source: MajikFileByteSource) {
    this.iterator = iterateSource(source)[Symbol.asyncIterator]();
  }

  private async ensureByte(): Promise<boolean> {
    while (this.offset >= this.current.length && !this.done) {
      const next = await this.iterator.next();
      if (next.done) {
        this.done = true;
        this.current = new Uint8Array(0);
        this.offset = 0;
        break;
      }
      if (!(next.value instanceof Uint8Array)) {
        throw MajikFileError.invalidInput(
          "Streaming source must yield Uint8Array chunks",
        );
      }
      this.current = next.value;
      this.offset = 0;
    }
    return this.offset < this.current.length;
  }

  async readExactly(length: number, label: string): Promise<Uint8Array> {
    if (!Number.isSafeInteger(length) || length < 0) {
      throw MajikFileError.formatError("Invalid " + label + " length");
    }
    const result = new Uint8Array(length);
    let written = 0;
    while (written < length) {
      if (!(await this.ensureByte())) {
        throw MajikFileError.formatError(
          "Truncated MJKB v3 stream while reading " + label,
        );
      }
      const available = this.current.length - this.offset;
      const count = Math.min(available, length - written);
      result.set(this.current.subarray(this.offset, this.offset + count), written);
      this.offset += count;
      written += count;
    }
    return result;
  }

  async readByteOrEof(): Promise<number | null> {
    if (!(await this.ensureByte())) return null;
    return this.current[this.offset++];
  }

  async assertEof(): Promise<void> {
    if ((await this.readByteOrEof()) !== null) {
      throw MajikFileError.formatError(
        "Unexpected trailing bytes after MJKB v3 manifest",
      );
    }
  }

  async close(): Promise<void> {
    if (!this.done) {
      await this.iterator.return?.();
      this.done = true;
    }
  }
}

class ChunkEncryptWriter {
  private readonly buffer: Uint8Array;
  private buffered = 0;
  private chunkCount = 0n;
  private compressedBytes = 0n;

  constructor(
    private readonly writer: WritableStreamDefaultWriter<Uint8Array>,
    private readonly gcm: GCM,
    private readonly nonceBase: Uint8Array,
    private readonly payloadHash: Uint8Array,
    private readonly chunkSize: number,
  ) {
    this.buffer = new Uint8Array(chunkSize);
  }

  async write(input: Uint8Array): Promise<void> {
    let offset = 0;
    while (offset < input.length) {
      const count = Math.min(this.chunkSize - this.buffered, input.length - offset);
      this.buffer.set(input.subarray(offset, offset + count), this.buffered);
      this.buffered += count;
      offset += count;
      if (this.buffered === this.chunkSize) await this.flushChunk();
    }
  }

  private async flushChunk(): Promise<void> {
    if (this.buffered === 0) return;
    const plaintext = this.buffer.slice(0, this.buffered);
    const nonce = nonceFor(this.nonceBase, this.chunkCount);
    const aad = chunkAad(this.payloadHash, this.chunkCount, plaintext.length);
    const ciphertext = this.gcm.seal(nonce, plaintext, aad);

    await this.writer.write(u32be(ciphertext.length));
    await this.writer.write(ciphertext);

    this.compressedBytes += BigInt(plaintext.length);
    this.chunkCount += 1n;
    this.buffer.fill(0, 0, this.buffered);
    this.buffered = 0;
    secureFill(plaintext);
  }

  async finish(
    originalBytes: bigint,
    fileHash: Uint8Array,
  ): Promise<{ chunks: bigint; compressedBytes: bigint }> {
    await this.flushChunk();

    const manifest = concatBytes(
      u64be(this.chunkCount),
      u64be(this.compressedBytes),
      u64be(originalBytes),
      fileHash,
    );
    if (manifest.length !== MANIFEST_LENGTH) {
      throw MajikFileError.encryptionFailed();
    }

    await this.writer.write(u32be(0));
    await this.writer.write(manifest);
    const tag = this.gcm.seal(
      nonceFor(this.nonceBase, this.chunkCount),
      new Uint8Array(0),
      manifestAad(this.payloadHash, manifest),
    );
    await this.writer.write(tag);

    return {
      chunks: this.chunkCount,
      compressedBytes: this.compressedBytes,
    };
  }

  clear(): void {
    secureFill(this.buffer);
    this.buffered = 0;
  }
}

/**
 * Encrypt a ReadableStream / AsyncIterable into an MJKB v3 WritableStream.
 * The result is byte-compatible with the Rust reader/writer implementation.
 */
export async function encryptReaderToWriter(
  source: MajikFileByteSource,
  destination: WritableStream<Uint8Array>,
  identity: MajikFileEncryptionIdentity,
  recipients: MajikFileRecipient[] = [],
  originalName: string | null = null,
  mimeType: string | null = null,
  options: MajikFileStreamingOptions = {},
): Promise<StreamingEncryptResult> {
  validateOptions(options);
  const chunkSize = options.chunkSize ?? DEFAULT_STREAM_CHUNK_SIZE;
  if (!identity?.fingerprint?.trim()) {
    throw MajikFileError.invalidInput("identity.fingerprint is required");
  }
  MajikFileValidator.assertMlKemPublicKey(
    identity.mlKemPublicKey,
    "identity.mlKemPublicKey",
  );

  for (let index = 0; index < recipients.length; index++) {
    const recipient = recipients[index];
    if (!recipient.fingerprint?.trim()) {
      throw MajikFileError.invalidInput(
        "recipients[" + index + "].fingerprint is required",
      );
    }
    MajikFileValidator.assertMlKemPublicKey(
      recipient.mlKemPublicKey,
      "recipients[" + index + "].mlKemPublicKey",
    );
  }

  const cleanedRecipients = deduplicateRecipients(recipients, identity.fingerprint);
  MajikFileValidator.assertRecipientLimit(cleanedRecipients.length, MAX_GROUP_RECIPIENTS);

  const allRecipients: MajikFileRecipient[] = [
    {
      fingerprint: identity.fingerprint,
      mlKemPublicKey: identity.mlKemPublicKey,
      publicKey: identity.publicKey,
    },
    ...cleanedRecipients,
  ];
  const participants = allRecipients.map((recipient) => recipient.publicKey);
  const isGroup = allRecipients.length > 1;
  const compress = options.compression ?? shouldCompressMime(mimeType);
  const compressionLevel = Math.max(
    1,
    Math.min(22, Math.round(options.compressionLevel ?? 6)),
  );
  const nonceBase = generateRandomBytes(IV_LENGTH);
  const writer = destination.getWriter();

  let aesKey: Uint8Array | undefined;
  let chunkWriter: ChunkEncryptWriter | undefined;
  let compressor: CompressStream | undefined;
  let writerClosed = false;

  try {
    let payload: MjkbPayloadV3;
    if (!isGroup) {
      const encapsulation = mlKemEncapsulate(identity.mlKemPublicKey);
      aesKey = encapsulation.sharedSecret;
      payload = {
        mlKemCipherText: arrayToBase64(encapsulation.cipherText),
        n: originalName,
        m: mimeType,
        z: compress,
        chunkSize,
        streamSuite: MJKB_V3_STREAM_SUITE,
      };
    } else {
      aesKey = generateRandomBytes(AES_KEY_LEN);
      const keys: MajikFileGroupKey[] = [];
      for (const recipient of allRecipients) {
        const encapsulation = mlKemEncapsulate(recipient.mlKemPublicKey);
        try {
          const encryptedAesKey = new Uint8Array(AES_KEY_LEN);
          for (let index = 0; index < AES_KEY_LEN; index++) {
            encryptedAesKey[index] = aesKey[index] ^ encapsulation.sharedSecret[index];
          }
          keys.push({
            fingerprint: recipient.fingerprint,
            mlKemCipherText: arrayToBase64(encapsulation.cipherText),
            encryptedAesKey: arrayToBase64(encryptedAesKey),
          });
          secureFill(encryptedAesKey);
        } finally {
          secureFill(encapsulation.sharedSecret);
        }
      }
      payload = {
        keys,
        n: originalName,
        m: mimeType,
        z: compress,
        chunkSize,
        streamSuite: MJKB_V3_STREAM_SUITE,
      };
    }

    const payloadBytes = UTF8.encode(JSON.stringify(payload));
    if (payloadBytes.length === 0 || payloadBytes.length > MAX_PAYLOAD_LENGTH) {
      throw MajikFileError.formatError("MJKB v3 payload JSON exceeds its size limit");
    }
    const payloadHash = new SHA256().update(payloadBytes).digest();
    const header = concatBytes(
      MJKB_MAGIC,
      new Uint8Array([0x03]),
      nonceBase,
      u32be(payloadBytes.length),
    );

    await writer.write(header);
    await writer.write(payloadBytes);

    if (!aesKey) throw MajikFileError.encryptionFailed();
    const gcm = new GCM(new AES(aesKey));
    chunkWriter = new ChunkEncryptWriter(
      writer,
      gcm,
      nonceBase,
      payloadHash,
      chunkSize,
    );

    if (compress) {
      try {
        compressor = await createCompressStream(compressionLevel, false);
      } catch (error) {
        throw MajikFileError.compressionFailed(error);
      }
    }

    const hasher = new SHA256();
    let originalBytes = 0n;
    const maxBytes = options.maxBytes === undefined ? undefined : BigInt(options.maxBytes);

    for await (const sourceChunk of iterateSource(source)) {
      throwIfAborted(options.signal);
      for (let offset = 0; offset < sourceChunk.length; offset += SOURCE_SLICE_SIZE) {
        throwIfAborted(options.signal);
        const part = sourceChunk.subarray(
          offset,
          Math.min(sourceChunk.length, offset + SOURCE_SLICE_SIZE),
        );
        if (part.length === 0) continue;

        const nextBytes = originalBytes + BigInt(part.length);
        if (maxBytes !== undefined && nextBytes > maxBytes) {
          throw MajikFileError.sizeExceeded(
            toSafeNumber(nextBytes, "Input size"),
            options.maxBytes!,
          );
        }

        hasher.update(part);
        if (compressor) {
          let compressed: Uint8Array;
          try {
            compressed = compressor.push(part);
          } catch (error) {
            throw MajikFileError.compressionFailed(error);
          }
          if (compressed.length) await chunkWriter.write(compressed);
        } else {
          await chunkWriter.write(part);
        }

        originalBytes = nextBytes;
        options.onProgress?.({
          bytesProcessed: toSafeNumber(originalBytes, "Input size"),
          totalBytes: options.totalBytes,
        });
      }
    }

    if (originalBytes === 0n) {
      throw MajikFileError.invalidInput("Cannot encrypt an empty stream");
    }
    if (
      options.totalBytes !== undefined &&
      originalBytes !== BigInt(options.totalBytes)
    ) {
      throw MajikFileError.invalidInput(
        "Input stream length mismatch: expected " +
          options.totalBytes +
          " bytes, read " +
          originalBytes,
      );
    }

    if (compressor) {
      let finalBytes: Uint8Array;
      try {
        finalBytes = compressor.finish();
      } catch (error) {
        throw MajikFileError.compressionFailed(error);
      }
      if (finalBytes.length) await chunkWriter.write(finalBytes);
    }

    const fileHash = hasher.digest();
    const resultCounts = await chunkWriter.finish(originalBytes, fileHash);
    await writer.close();
    writerClosed = true;

    return {
      originalBytes: toSafeNumber(originalBytes, "Original size"),
      compressedBytes: toSafeNumber(resultCounts.compressedBytes, "Compressed size"),
      chunks: toSafeNumber(resultCounts.chunks, "Chunk count"),
      fileHash: toHex(fileHash),
      encryptionIv: toHex(nonceBase),
      participants,
      isGroup,
      compressionAlg: compress ? "zstd" : null,
    };
  } catch (error) {
    if (!writerClosed) {
      await writer.abort(error).catch(() => undefined);
    }
    if (error instanceof MajikFileError || error instanceof DOMException) throw error;
    throw MajikFileError.encryptionFailed(error);
  } finally {
    compressor?.free();
    chunkWriter?.clear();
    if (aesKey) secureFill(aesKey);
    writer.releaseLock();
  }
}

/**
 * Tracks the boundaries of one RFC 8878 Zstandard frame without buffering its
 * blocks. This rejects data that follows the Zstd frame, matching Rust.
 */
class ZstdFrameTracker {
  private phase:
    | "header-prefix"
    | "header-rest"
    | "block-header"
    | "block-body"
    | "checksum"
    | "done" = "header-prefix";
  private pending: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
  private headerLength = 5;
  private bodyRemaining = 0;
  private lastBlock = false;
  private hasChecksum = false;

  push(input: Uint8Array): void {
    let offset = 0;
    while (offset < input.length) {
      if (this.phase === "done") {
        throw MajikFileError.formatError(
          "Unexpected compressed bytes after the Zstandard frame",
        );
      }

      if (this.phase === "block-body") {
        const count = Math.min(this.bodyRemaining, input.length - offset);
        this.bodyRemaining -= count;
        offset += count;
        if (this.bodyRemaining === 0) this.finishBlock();
        continue;
      }

      const targetLength =
        this.phase === "header-prefix"
          ? 5
          : this.phase === "header-rest"
            ? this.headerLength
            : this.phase === "block-header"
              ? 3
              : 4;
      const take = Math.min(targetLength - this.pending.length, input.length - offset);
      this.pending = concatBytes(this.pending, input.subarray(offset, offset + take));
      offset += take;
      if (this.pending.length < targetLength) return;

      if (this.phase === "header-prefix") {
        if (
          this.pending[0] !== 0x28 ||
          this.pending[1] !== 0xb5 ||
          this.pending[2] !== 0x2f ||
          this.pending[3] !== 0xfd
        ) {
          throw MajikFileError.decompressionFailed(
            new Error("Invalid Zstandard frame magic"),
          );
        }
        const descriptor = this.pending[4];
        const frameContentSizeFlag = descriptor >> 6;
        const singleSegment = ((descriptor >> 5) & 1) === 1;
        this.hasChecksum = ((descriptor >> 2) & 1) === 1;
        const dictionaryIdFlag = descriptor & 0x03;
        const windowDescriptorLength = singleSegment ? 0 : 1;
        const dictionaryIdLength = [0, 1, 2, 4][dictionaryIdFlag];
        const contentSizeLength =
          frameContentSizeFlag === 0
            ? singleSegment
              ? 1
              : 0
            : frameContentSizeFlag === 1
              ? 2
              : frameContentSizeFlag === 2
                ? 4
                : 8;
        this.headerLength =
          windowDescriptorLength + dictionaryIdLength + contentSizeLength;
        this.pending = new Uint8Array(0);
        this.phase = this.headerLength === 0 ? "block-header" : "header-rest";
      } else if (this.phase === "header-rest") {
        this.pending = new Uint8Array(0);
        this.phase = "block-header";
      } else if (this.phase === "block-header") {
        const header =
          this.pending[0] |
          (this.pending[1] << 8) |
          (this.pending[2] << 16);
        this.lastBlock = (header & 1) === 1;
        const blockType = (header >> 1) & 0x03;
        const blockSize = header >> 3;
        if (blockType === 3) {
          throw MajikFileError.decompressionFailed(
            new Error("Reserved Zstandard block type"),
          );
        }
        this.bodyRemaining = blockType === 1 ? 1 : blockSize;
        this.pending = new Uint8Array(0);
        if (this.bodyRemaining === 0) this.finishBlock();
        else this.phase = "block-body";
      } else if (this.phase === "checksum") {
        this.pending = new Uint8Array(0);
        this.phase = "done";
      }
    }
  }

  assertComplete(): void {
    if (this.phase !== "done") {
      throw MajikFileError.decompressionFailed(
        new Error("Zstandard stream ended before its final block"),
      );
    }
  }

  private finishBlock(): void {
    if (!this.lastBlock) {
      this.phase = "block-header";
    } else if (this.hasChecksum) {
      this.phase = "checksum";
    } else {
      this.phase = "done";
    }
  }
}

function parseV3Payload(bytes: Uint8Array): MjkbPayloadV3 {
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    throw MajikFileError.formatError("Malformed MJKB v3 payload JSON");
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw MajikFileError.formatError("Malformed MJKB v3 payload");
  }

  const payload = value as Record<string, unknown>;
  const single =
    typeof payload.mlKemCipherText === "string" &&
    !("keys" in payload);
  const group =
    Array.isArray(payload.keys) &&
    payload.keys.length > 0 &&
    !("mlKemCipherText" in payload);
  if (
    (!single && !group) ||
    typeof payload.z !== "boolean" ||
    !Number.isInteger(payload.chunkSize) ||
    typeof payload.streamSuite !== "string" ||
    !(
      payload.n === null ||
      payload.n === undefined ||
      typeof payload.n === "string"
    ) ||
    !(
      payload.m === null ||
      payload.m === undefined ||
      typeof payload.m === "string"
    ) ||
    !(payload.ca === undefined || typeof payload.ca === "string")
  ) {
    throw MajikFileError.formatError("Malformed MJKB v3 payload fields");
  }
  return payload as unknown as MjkbPayloadV3;
}

function parseManifest(bytes: Uint8Array): {
  chunkCount: bigint;
  compressedBytes: bigint;
  originalBytes: bigint;
  fileHash: Uint8Array;
} {
  if (bytes.length !== MANIFEST_LENGTH) {
    throw MajikFileError.formatError("Invalid MJKB v3 manifest length");
  }
  return {
    chunkCount: readU64be(bytes, 0),
    compressedBytes: readU64be(bytes, 8),
    originalBytes: readU64be(bytes, 16),
    fileHash: bytes.slice(24, 56),
  };
}

/**
 * Decrypt an MJKB v3 ReadableStream / AsyncIterable into a WritableStream.
 * No complete encrypted file or plaintext file is retained by this function.
 */
export async function decryptReaderToWriter(
  source: MajikFileByteSource,
  destination: WritableStream<Uint8Array>,
  identity: StreamingDecryptIdentity,
  options: MajikFileStreamingOptions = {},
): Promise<StreamingDecryptResult> {
  validateOptions(options);
  if (!identity?.fingerprint?.trim()) {
    throw MajikFileError.invalidInput(
      "identity.fingerprint is required for decryption",
    );
  }

  const reader = new AsyncByteReader(source);
  const writer = destination.getWriter();
  let writerClosed = false;
  let decoder: DecompressStream | undefined;
  let aesKey: Uint8Array | undefined;

  try {
    const header = await reader.readExactly(HEADER_LENGTH, "MJKB header");
    if (!MJKB_MAGIC.every((byte, index) => header[index] === byte)) {
      throw MajikFileError.formatError("Missing MJKB magic bytes");
    }
    if (header[4] !== 0x03) {
      throw MajikFileError.unsupportedVersion(header[4], 3);
    }

    const nonceBase = header.slice(5, 5 + IV_LENGTH);
    const payloadLength = readU32be(header.slice(5 + IV_LENGTH));
    if (payloadLength === 0 || payloadLength > MAX_PAYLOAD_LENGTH) {
      throw MajikFileError.formatError("Invalid MJKB v3 payload length");
    }
    const payloadBytes = await reader.readExactly(payloadLength, "MJKB v3 payload");
    const payload = parseV3Payload(payloadBytes);

    validateChunkSize(payload.chunkSize);
    if (payload.streamSuite !== MJKB_V3_STREAM_SUITE) {
      throw MajikFileError.formatError("Unsupported MJKB v3 stream suite");
    }
    if (payload.ca !== undefined && payload.ca !== "zstd") {
      throw MajikFileError.unsupportedCompressionAlg(payload.ca);
    }

    const payloadHash = new SHA256().update(payloadBytes).digest();
    aesKey = resolveAesKeyFromPayload(
      payload as unknown as AnyMjkbPayload,
      identity,
    );
    const gcm = new GCM(new AES(aesKey));
    const frameTracker = payload.z ? new ZstdFrameTracker() : undefined;
    if (payload.z) {
      try {
        decoder = await createDecompressStream();
      } catch (error) {
        throw MajikFileError.decompressionFailed(error);
      }
    }

    const hasher = new SHA256();
    let outputBytes = 0n;
    let chunkCount = 0n;
    let compressedBytes = 0n;
    const maxBytes = options.maxBytes === undefined ? undefined : BigInt(options.maxBytes);

    const writePlaintext = async (bytes: Uint8Array): Promise<void> => {
      if (!bytes.length) return;
      const nextBytes = outputBytes + BigInt(bytes.length);
      if (maxBytes !== undefined && nextBytes > maxBytes) {
        throw MajikFileError.sizeExceeded(
          toSafeNumber(nextBytes, "Decrypted output size"),
          options.maxBytes!,
        );
      }
      hasher.update(bytes);
      await writer.write(bytes);
      outputBytes = nextBytes;
      options.onProgress?.({
        bytesProcessed: toSafeNumber(outputBytes, "Decrypted output size"),
        totalBytes: options.totalBytes,
      });
    };

    while (true) {
      throwIfAborted(options.signal);
      const length = readU32be(await reader.readExactly(4, "chunk record length"));

      if (length === 0) {
        const manifestBytes = await reader.readExactly(MANIFEST_LENGTH, "final manifest");
        const tag = await reader.readExactly(GCM_TAG_LENGTH, "manifest authentication tag");
        const manifestNonce = nonceFor(nonceBase, chunkCount);
        const authenticated = gcm.open(
          manifestNonce,
          tag,
          manifestAad(payloadHash, manifestBytes),
        );
        if (authenticated === null) {
          throw MajikFileError.decryptionFailed(
            "MJKB v3 manifest authentication failed",
          );
        }
        if (authenticated.length !== 0) {
          throw MajikFileError.formatError(
            "MJKB v3 manifest plaintext must be empty",
          );
        }

        const manifest = parseManifest(manifestBytes);
        if (
          manifest.chunkCount !== chunkCount ||
          manifest.compressedBytes !== compressedBytes
        ) {
          throw MajikFileError.decryptionFailed(
            "MJKB v3 manifest does not match the authenticated chunk stream",
          );
        }
        await reader.assertEof();

        if (decoder) {
          try {
            const finalPlaintext = decoder.finish();
            await writePlaintext(finalPlaintext);
          } catch (error) {
            if (error instanceof MajikFileError) throw error;
            throw MajikFileError.decompressionFailed(error);
          }
          frameTracker!.assertComplete();
        }

        const digest = hasher.digest();
        if (
          manifest.originalBytes !== outputBytes ||
          !digest.every((byte, index) => byte === manifest.fileHash[index])
        ) {
          throw MajikFileError.decryptionFailed(
            "MJKB v3 plaintext length or SHA-256 does not match its authenticated manifest",
          );
        }
        if (
          options.totalBytes !== undefined &&
          outputBytes !== BigInt(options.totalBytes)
        ) {
          throw MajikFileError.invalidInput(
            "Output stream length mismatch: expected " +
              options.totalBytes +
              " bytes, wrote " +
              outputBytes,
          );
        }
        await writer.close();
        writerClosed = true;

        return {
          originalBytes: toSafeNumber(outputBytes, "Original size"),
          compressedBytes: toSafeNumber(compressedBytes, "Compressed size"),
          chunks: toSafeNumber(chunkCount, "Chunk count"),
          fileHash: toHex(digest),
          originalName: payload.n ?? null,
          mimeType: payload.m ?? null,
          payload,
        };
      }

      if (length <= GCM_TAG_LENGTH || length > payload.chunkSize + GCM_TAG_LENGTH) {
        throw MajikFileError.formatError("Invalid MJKB v3 ciphertext chunk length");
      }
      const ciphertext = await reader.readExactly(length, "encrypted chunk");
      const plaintextLength = length - GCM_TAG_LENGTH;
      const nonce = nonceFor(nonceBase, chunkCount);
      const plaintext = gcm.open(
        nonce,
        ciphertext,
        chunkAad(payloadHash, chunkCount, plaintextLength),
      );
      if (plaintext === null) {
        throw MajikFileError.decryptionFailed("MJKB v3 chunk authentication failed");
      }
      if (plaintext.length === 0 || plaintext.length > payload.chunkSize) {
        throw MajikFileError.formatError("Invalid MJKB v3 plaintext chunk size");
      }

      compressedBytes += BigInt(plaintext.length);
      if (decoder) {
        frameTracker!.push(plaintext);
        let decoded: Uint8Array;
        try {
          decoded = decoder.push(plaintext);
        } catch (error) {
          throw MajikFileError.decompressionFailed(error);
        }
        await writePlaintext(decoded);
      } else {
        await writePlaintext(plaintext);
      }
      chunkCount += 1n;
      secureFill(plaintext);
    }
  } catch (error) {
    if (!writerClosed) await writer.abort(error).catch(() => undefined);
    if (error instanceof MajikFileError || error instanceof DOMException) throw error;
    throw MajikFileError.decryptionFailed("MJKB v3 decryption failed", error);
  } finally {
    decoder?.free();
    if (aesKey) secureFill(aesKey);
    await reader.close();
    writer.releaseLock();
  }
}

/** Internal in-memory adapter used by MajikFile.create(). */
export async function encryptBytesToMjkbV3(
  data: Uint8Array,
  identity: MajikFileEncryptionIdentity,
  recipients: MajikFileRecipient[],
  originalName: string | null,
  mimeType: string | null,
  compression: boolean,
  compressionLevel?: number,
): Promise<{ binary: Uint8Array; result: StreamingEncryptResult }> {
  const chunks: Uint8Array[] = [];
  let total = 0;
  const output = new WritableStream<Uint8Array>({
    write(chunk) {
      chunks.push(chunk.slice());
      total += chunk.length;
    },
  });
  async function* input(): AsyncGenerator<Uint8Array> {
    for (let offset = 0; offset < data.length; offset += SOURCE_SLICE_SIZE) {
      yield data.subarray(offset, Math.min(data.length, offset + SOURCE_SLICE_SIZE));
    }
  }

  const result = await encryptReaderToWriter(
    input(),
    output,
    identity,
    recipients,
    originalName,
    mimeType,
    {
      compression,
      compressionLevel,
      totalBytes: data.length,
    },
  );
  const binary = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    binary.set(chunk, offset);
    offset += chunk.length;
  }
  return { binary, result };
}

/** Internal buffer adapter for the existing MajikFile.decrypt() API. */
export async function decryptMjkbV3ToBuffer(
  binary: Uint8Array,
  identity: StreamingDecryptIdentity,
  options: MajikFileStreamingOptions = {},
): Promise<{ bytes: Uint8Array; result: StreamingDecryptResult }> {
  const chunks: Uint8Array[] = [];
  let total = 0;
  const output = new WritableStream<Uint8Array>({
    write(chunk) {
      chunks.push(chunk.slice());
      total += chunk.length;
    },
  });
  async function* input(): AsyncGenerator<Uint8Array> {
    for (let offset = 0; offset < binary.length; offset += SOURCE_SLICE_SIZE) {
      yield binary.subarray(offset, Math.min(binary.length, offset + SOURCE_SLICE_SIZE));
    }
  }

  const result = await decryptReaderToWriter(input(), output, identity, options);
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  return { bytes, result };
}
