import { beforeAll, describe, expect, it } from "vitest";
import {
  decryptReaderToWriter,
  encryptReaderToWriter,
  MIN_STREAM_CHUNK_SIZE,
} from "../src/core/streaming";
import type {
  MajikFileEncryptionIdentity,
  MajikFileIdentity,
  MajikFileRecipient,
} from "../src/core/types";
import { getTestKey } from "./helpers/crypto";

interface TestIdentity {
  identity: MajikFileIdentity;
  recipient: MajikFileRecipient;
}

async function createIdentity(): Promise<TestIdentity> {
  const key = await getTestKey();
  const publicKey = key.publicKeyBase64;
  const fingerprint = key.fingerprint;
  return {
    identity: {
      publicKey,
      fingerprint,
      mlKemPublicKey: key.mlKemPublicKey,
      mlKemSecretKey: key.mlKemSecretKey!,
    },
    recipient: {
      publicKey,
      fingerprint,
      mlKemPublicKey: key.mlKemPublicKey,
    },
  };
}

function collector() {
  const chunks: Uint8Array[] = [];
  let length = 0;
  const writable = new WritableStream<Uint8Array>({
    write(chunk) {
      chunks.push(chunk.slice());
      length += chunk.length;
    },
  });
  return {
    writable,
    bytes(): Uint8Array {
      const result = new Uint8Array(length);
      let offset = 0;
      for (const chunk of chunks) {
        result.set(chunk, offset);
        offset += chunk.length;
      }
      return result;
    },
  };
}

async function* sourceOf(bytes: Uint8Array): AsyncGenerator<Uint8Array> {
  for (let offset = 0; offset < bytes.length; offset += 17_321) {
    yield bytes.subarray(offset, Math.min(bytes.length, offset + 17_321));
  }
}

function deterministicBytes(length: number): Uint8Array {
  return Uint8Array.from({ length }, (_, index) => (index * 73 + 19) & 0xff);
}

describe("MJKB v3 streaming", () => {
  let alice: TestIdentity;
  let bob: TestIdentity;

  beforeAll(async () => {
    [alice, bob] = await Promise.all([createIdentity(), createIdentity()]);
  }, 120_000);

  it("streams Zstandard-compressed single-recipient files", async () => {
    const plaintext = new TextEncoder().encode(
      "Majik v3 interoperable streaming payload. ".repeat(12_000),
    );
    const encrypted = collector();
    const encryptedResult = await encryptReaderToWriter(
      sourceOf(plaintext),
      encrypted.writable,
      alice.identity,
      [],
      "stream.txt",
      "text/plain",
      {
        chunkSize: MIN_STREAM_CHUNK_SIZE,
        compression: true,
        totalBytes: plaintext.length,
      },
    );

    const binary = encrypted.bytes();
    expect(binary[4]).toBe(0x03);
    expect(encryptedResult.compressionAlg).toBe("zstd");

    const decrypted = collector();
    const decryptedResult = await decryptReaderToWriter(
      sourceOf(binary),
      decrypted.writable,
      alice.identity,
      { totalBytes: plaintext.length },
    );

    expect(decrypted.bytes()).toEqual(plaintext);
    expect(decryptedResult.fileHash).toBe(encryptedResult.fileHash);
    expect(decryptedResult.originalBytes).toBe(plaintext.length);
    expect(decryptedResult.chunks).toBe(encryptedResult.chunks);
  }, 120_000);

  it("splits uncompressed data into bounded authenticated chunks", async () => {
    const plaintext = deterministicBytes(180_123);
    const encrypted = collector();
    const encryptedResult = await encryptReaderToWriter(
      sourceOf(plaintext),
      encrypted.writable,
      alice.identity,
      [],
      "large.bin",
      "application/octet-stream",
      {
        chunkSize: MIN_STREAM_CHUNK_SIZE,
        compression: false,
      },
    );

    expect(encryptedResult.chunks).toBe(3);
    expect(encryptedResult.compressedBytes).toBe(plaintext.length);

    const decrypted = collector();
    await decryptReaderToWriter(
      sourceOf(encrypted.bytes()),
      decrypted.writable,
      alice.identity,
    );
    expect(decrypted.bytes()).toEqual(plaintext);
  }, 120_000);

  it("supports group recipients with the same wrapped AES key", async () => {
    const plaintext = deterministicBytes(90_000);
    const encrypted = collector();
    await encryptReaderToWriter(
      sourceOf(plaintext),
      encrypted.writable,
      alice.identity,
      [bob.recipient],
      "group.bin",
      "application/octet-stream",
      { chunkSize: MIN_STREAM_CHUNK_SIZE, compression: false },
    );

    const decrypted = collector();
    await decryptReaderToWriter(
      sourceOf(encrypted.bytes()),
      decrypted.writable,
      bob.identity,
    );
    expect(decrypted.bytes()).toEqual(plaintext);
  }, 120_000);

  it("rejects a tampered authenticated chunk", async () => {
    const plaintext = deterministicBytes(80_000);
    const encrypted = collector();
    await encryptReaderToWriter(
      sourceOf(plaintext),
      encrypted.writable,
      alice.identity,
      [],
      "tamper.bin",
      "application/octet-stream",
      { chunkSize: MIN_STREAM_CHUNK_SIZE, compression: false },
    );

    const binary = encrypted.bytes();
    const payloadLength = new DataView(
      binary.buffer,
      binary.byteOffset + 17,
      4,
    ).getUint32(0, false);
    const firstRecord = 21 + payloadLength;
    const tampered = binary.slice();
    tampered[firstRecord + 4] ^= 0x01;

    const destination = collector();
    await expect(
      decryptReaderToWriter(
        sourceOf(tampered),
        destination.writable,
        alice.identity,
      ),
    ).rejects.toMatchObject({ code: "DECRYPTION_FAILED" });
  }, 120_000);

  it("rejects a truncated final manifest", async () => {
    const plaintext = deterministicBytes(70_000);
    const encrypted = collector();
    await encryptReaderToWriter(
      sourceOf(plaintext),
      encrypted.writable,
      alice.identity,
      [],
      "truncated.bin",
      "application/octet-stream",
      { chunkSize: MIN_STREAM_CHUNK_SIZE, compression: false },
    );

    const truncated = encrypted.bytes().slice(0, -5);
    await expect(
      decryptReaderToWriter(
        sourceOf(truncated),
        collector().writable,
        alice.identity,
      ),
    ).rejects.toMatchObject({ code: "FORMAT_ERROR" });
  }, 120_000);
});
