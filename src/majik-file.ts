import {
  aesGcmEncrypt,
  aesGcmDecrypt,
  generateRandomBytes,
  mlKemEncapsulate,
} from "./core/crypto/crypto-provider";
import {
  IV_LENGTH,
  AES_KEY_LEN,
  MAX_FILE_SIZE_BYTES,
  MAX_GROUP_RECIPIENTS,
  FILE_SCHEMA_VERSION,
  CRYPTO_SUITE,
  MJKS_OVERHEAD,
  MJKS_MAGIC_LEN,
  MJKS_MAGIC,
} from "./core/crypto/constants";
import { MajikFileError } from "./core/error";
import { MajikFileValidator } from "./core/validator";
import { secureFill, withZeroize } from "./core/crypto/zeroize";
import {
  sha256Hex,
  formatBytes,
  arrayToBase64,
  generateUUID,
  normaliseToUint8Array,
  normaliseToUint8ArrayAsync,
  isMimeTypeInlineViewable,
  inferMimeTypeFromFilename,
  deriveFilename,
  deduplicateRecipients,
  shouldCompressMime,
  sha256Base64,
} from "./core/utils";
import {
  encodeMjkb,
  decodeMjkb,
  resolveAesKeyFromPayload,
} from "./core/mjkb-codec";
import { MajikCompressor } from "./core/compressor/majik-compressor";
import { isMjkbGroupPayload, hasCompressionFlag } from "./core/types";
import type {
  MajikFileJSON,
  MajikFileCreateOptions,
  MajikFileIdentity,
  MajikFileRecipient,
  MajikFileGroupKey,
  MjkbPayload,
  AnyMjkbPayload,
  MajikFileStats,
  MajikFileDecryptIdentity,
  FileSignature,
} from "./core/types";
import {
  MajikSignature,
  type MajikSignerPublicKeys,
  type VerificationResult,
} from "@majikah/majik-signature";
import {
  MajikKey,
  MajikKeyAddress,
  MajikKeyError,
  MajikKeyFingerprint,
} from "@majikah/majik-key";

/**
 * MajikFile
 * ----------------
 * Post-quantum binary file encryption. Platform-agnostic — this class
 * knows nothing about chat, threads, or storage backends. It owns exactly
 * what's needed to identify, describe, encrypt, and decrypt a file.
 *
 * For Majikah messaging-specific fields (R2 key, storage type, context,
 * chat/thread bindings, sharing), see MajikMessageFile, which extends this
 * class rather than duplicating any of its crypto logic.
 *
 * ─── Extensibility ───────────────────────────────────────────────────────
 *   Subclasses compose rather than override the crypto pipeline:
 *     - `_encryptCore()` (protected static) does hash → preprocess →
 *       compress → encrypt → encode, and is called directly by a
 *       subclass's own `create()` rather than inherited through it —
 *       subclasses have their own extra fields to layer on afterward.
 *     - `_preProcess()` and `_resolveCompressionPolicy()` are protected
 *       static hooks with generic no-op/mime-only defaults. A subclass
 *       overrides them (e.g. MajikMessageFile overrides `_preProcess` to
 *       convert certain FileContexts to WebP). Because `_encryptCore` calls
 *       `this._preProcess(...)` internally, and static `this` is late-bound
 *       to whichever class the method was actually invoked on, calling
 *       `MajikMessageFile._encryptCore(...)` correctly dispatches to
 *       MajikMessageFile's override — ordinary JS static polymorphism, no
 *       extra plumbing required.
 *   decrypt/sign/verify/encode/decode never need subclass awareness at
 *   all — they operate purely on bytes + identity.
 *
 * ─── Immutability ────────────────────────────────────────────────────────
 *   Instances are built exclusively through static factories (`create()`,
 *   `fromJSON()`, `fromJSONWithBlob()`) which call `_sealInstance()` as the
 *   last step. `Object.seal()` — not `freeze()` — is used deliberately:
 *   mutator methods (attachSignature, toggleSharing-style methods in the
 *   subclass, etc.) still need to reassign *existing* private fields; seal
 *   blocks adding or deleting properties (no prototype pollution / injected
 *   fields) while permitting exactly that. Sealing happens in the factory,
 *   not the constructor, so a subclass constructor has already set all of
 *   its own fields (via `super()` then its own assignments) before the
 *   object becomes sealed — no `new.target` gymnastics needed.
 *
 * ─── Versioning ──────────────────────────────────────────────────────────
 *   Two independent version axes:
 *     - MJKB_VERSION: the .mjkb binary wire format (see mjkb-codec.ts).
 *     - schema_version (FILE_SCHEMA_VERSION): the JSON record shape. A
 *       record with no schema_version at all is legacy (pre-refactor) —
 *       see MajikMessageFile.isLegacyJSON() / fromLegacyJSON().
 *   kem_alg / cipher_alg are stamped on every new record (CRYPTO_SUITE) so
 *   a future suite change is a detectable, migratable fact.
 *
 * ─── .mjkb binary format (v2) ────────────────────────────────────────────
 *   [4   magic "MJKB"]
 *   [1   version]
 *   [12  AES-GCM IV]
 *   [4   payload JSON length (big-endian uint32)]
 *   [N   payload JSON — { n, m, z, mlKemCipherText } | { n, m, z, keys }]
 *   [M   AES-GCM ciphertext]
 *   `z` is an explicit "was this zstd-compressed" flag set at encrypt time —
 *   decrypt reads it directly instead of re-deriving a policy decision from
 *   context, which is what made the pre-refactor binary format secretly
 *   depend on a messaging-specific concept (FileContext). v1 binaries
 *   (which used `c` instead of `z`) remain readable — see decodeMjkb() and
 *   _decryptCore()'s legacy fallback.
 */

// ── Batch / stats types ───────────────────────────────────────────────────

export interface BatchDecryptResult<T extends MajikFile = MajikFile> {
  success: boolean;
  decrypted: T[];
  errors: Array<{ id: string; reason: string }>;
}

export interface BatchLockResult {
  locked: number;
  skipped: number; // signed-only files
}

/** Internal shape returned by _encryptCore() — consumed by create() in this class and its subclasses. */
export interface EncryptCoreResult {
  binary: Uint8Array;
  ivHex: string;
  fileHash: string;
  sizeOriginal: number;
  sizeStored: number;
  resolvedMimeType: string | null;
  participants: MajikKeyAddress[];
  isGroup: boolean;
}

/** Input shape for _encryptCore() — the crypto-pipeline-only subset of a create() call. */
export interface EncryptCoreInput {
  data: Uint8Array | ArrayBuffer;
  identity: MajikFileIdentity;
  recipients: MajikFileRecipient[];
  originalName: string | null;
  mimeType: string | null;
  bypassSizeLimit: boolean;
  compressionLevel?: number;
  /**
   * Opaque passthrough to `_preProcess()`. Base ignores it entirely. A
   * subclass that overrides `_preProcess()` and needs extra platform data
   * to decide how to preprocess (e.g. MajikMessageFile needs FileContext
   * to decide whether to convert an image to WebP) passes it here and
   * casts it back inside its own override. Kept as `unknown` rather than
   * a generic type parameter to avoid threading generics through the
   * entire static method hierarchy for a single, rarely-needed hook.
   */
  preProcessExtra?: unknown;
}

export class MajikFile {
  // ── Metadata ─────────────────────────────────────────────────────────────

  protected readonly _id: string;
  protected readonly _schemaVersion: number;
  protected readonly _kind: string;
  protected readonly _userId: string;
  protected readonly _originalName: string | null;
  protected readonly _mimeType: string | null;
  protected readonly _sizeOriginal: number;
  protected readonly _sizeStored: number;
  protected readonly _fileHash: string;
  protected readonly _encryptionIv: string;
  protected readonly _participants: MajikKeyAddress[];
  protected readonly _kemAlg: string;
  protected readonly _cipherAlg: string;
  protected readonly _timestamp: string | null;
  protected _lastUpdate: string | null;
  protected readonly _isGroup: boolean;

  protected _signature: string | null;

  /** Encrypted .mjkb binary. NOT serialised via toJSON() — lives wherever the caller stores it. */
  protected _binary: Uint8Array | null;

  /** Runtime-only decrypted cache. Zeroized (not just dropped) on secureLock(). */
  protected _decrypted?: Uint8Array;

  // ── Constructor ────────────────────────────────────────────────────────────

  /**
   * Protected — instances are built through static factories (create(),
   * fromJSON(), fromJSONWithBlob()) so `_sealInstance()` can run only once
   * every field, base and subclass, has actually been assigned.
   */
  protected constructor(
    json: MajikFileJSON,
    binary: Uint8Array | null,
    isGroup: boolean,
  ) {
    this._id = json.id;
    this._schemaVersion = json.schema_version;
    this._kind = json.kind;
    this._userId = json.user_id;
    this._originalName = json.original_name;
    this._mimeType = json.mime_type;
    this._sizeOriginal = json.size_original;
    this._sizeStored = json.size_stored;
    this._fileHash = json.file_hash;
    this._encryptionIv = json.encryption_iv;
    this._participants = json.participants;
    this._kemAlg = json.kem_alg;
    this._cipherAlg = json.cipher_alg;
    this._timestamp = json.timestamp;
    this._lastUpdate = json.last_update;
    this._binary = binary;
    this._isGroup = isGroup;
    this._signature = json.signature;
  }

  /**
   * Seals the instance so no new properties can be added/removed. Called
   * as the last step of every static factory — see class-level doc comment
   * for why this lives here instead of the constructor.
   */
  protected _sealInstance(): this {
    Object.seal(this);
    return this;
  }

  // ── Getters ───────────────────────────────────────────────────────────────

  get id(): string {
    return this._id;
  }
  get schemaVersion(): number {
    return this._schemaVersion;
  }
  get kind(): string {
    return this._kind;
  }
  get userId(): string {
    return this._userId;
  }
  get originalName(): string | null {
    return this._originalName;
  }
  get mimeType(): string | null {
    return this._mimeType;
  }
  get sizeOriginal(): number {
    return this._sizeOriginal;
  }
  get sizeStored(): number {
    return this._sizeStored;
  }
  get fileHash(): string {
    return this._fileHash;
  }
  get sizeKB(): number {
    return Math.round((this._sizeOriginal / 1024) * 1000) / 1000;
  }
  get sizeMB(): number {
    return Math.round((this._sizeOriginal / 1024 ** 2) * 1000) / 1000;
  }
  get sizeGB(): number {
    return Math.round((this._sizeOriginal / 1024 ** 3) * 1000) / 1000;
  }
  get sizeTB(): number {
    return Math.round((this._sizeOriginal / 1024 ** 4) * 1000) / 1000;
  }
  get encryptionIv(): string {
    return this._encryptionIv;
  }
  get kemAlg(): string {
    return this._kemAlg;
  }
  get cipherAlg(): string {
    return this._cipherAlg;
  }
  get participants(): MajikKeyAddress[] {
    return this._participants;
  }
  get timestamp(): string | null {
    return this._timestamp;
  }
  get lastUpdate(): string | null {
    return this._lastUpdate;
  }
  /** True if the encrypted .mjkb binary is loaded in memory. */
  get hasBinary(): boolean {
    return this._binary !== null;
  }
  /** True if this file was encrypted for multiple recipients. */
  get isGroup(): boolean {
    return this._isGroup;
  }
  /** True if this file was encrypted for a single recipient (the owner). */
  get isSingle(): boolean {
    return !this._isGroup;
  }
  get hasDecryptedFile(): boolean {
    return this._decrypted !== undefined;
  }
  /** The cached decrypted file, if decryptHydrate() has run this session. */
  get decryptedFile(): Uint8Array | undefined {
    return this._decrypted;
  }

  // ── SIGNATURE ─────────────────────────────────────────────────────────────

  /** Serialized base64 signature string. Stored as a plain text column. Null when unsigned. */
  get signatureRaw(): string | null {
    return this._signature;
  }

  /**
   * Deserialize and return the attached MajikSignature instance.
   * Returns null if no signature is attached or the stored value is malformed.
   */
  get signature(): MajikSignature | null {
    if (!this._signature?.trim()) return null;
    try {
      return MajikSignature.deserialize(this._signature);
    } catch {
      return null;
    }
  }

  /** True if a structurally valid signature is attached. Does NOT cryptographically verify. */
  get isSigned(): boolean {
    return this._signature?.trim() ? true : false;
  }

  // ── EXTENSIBILITY HOOKS (overridden by subclasses) ────────────────────────

  /**
   * No-op by default — returns the input unchanged. MajikMessageFile
   * overrides this to convert certain FileContexts to WebP before
   * compression/encryption. See class-level doc comment for the dispatch
   * mechanism (late-bound static `this`).
   */
  protected static async _preProcess(
    raw: Uint8Array,
    mimeType: string | null,
    _extra?: unknown,
  ): Promise<{ bytes: Uint8Array; mimeType: string | null }> {
    return { bytes: raw, mimeType };
  }

  /**
   * Mime-only compression policy by default. A subclass may override to
   * fold in additional context, but the base default alone is what makes
   * legacy v1 binaries (which lack the `z` flag) decodable without the
   * base layer needing to know what a FileContext is.
   */
  protected static _resolveCompressionPolicy(mimeType: string | null): boolean {
    return shouldCompressMime(mimeType);
  }

  // ── ENCRYPT CORE (shared by create() here and in every subclass) ─────────

  /**
   * Hash → preprocess (hook) → compress (policy hook) → encrypt →
   * encode .mjkb. Called directly (not inherited via create()) by every
   * subclass's own create() implementation, since each layers different
   * extra fields on top of the result.
   *
   * Zeroization: every derived secret (ML-KEM shared secrets, the random
   * group AES key) is wiped immediately after use via withZeroize()/
   * secureFill(), in a `finally` so cleanup survives an early throw.
   *
   * @throws MajikFileError on validation or crypto failure.
   */
  protected static async _encryptCore(
    input: EncryptCoreInput,
  ): Promise<EncryptCoreResult> {
    const raw = normaliseToUint8Array(input.data);

    MajikFileValidator.assertNonEmptyData(raw.byteLength);
    MajikFileValidator.assertSizeWithinLimit(
      raw.byteLength,
      MAX_FILE_SIZE_BYTES,
      input.bypassSizeLimit,
    );
    if (!input.identity?.fingerprint?.trim()) {
      throw MajikFileError.invalidInput("identity.fingerprint is required");
    }
    MajikFileValidator.assertMlKemPublicKey(
      input.identity.mlKemPublicKey,
      "identity.mlKemPublicKey",
    );
    for (let i = 0; i < input.recipients.length; i++) {
      const r = input.recipients[i];
      if (!r.fingerprint?.trim()) {
        throw MajikFileError.invalidInput(
          `recipients[${i}].fingerprint is required`,
        );
      }
      MajikFileValidator.assertMlKemPublicKey(
        r.mlKemPublicKey,
        `recipients[${i}].mlKemPublicKey`,
      );
    }

    try {
      // Hash the ORIGINAL bytes — before any preprocessing/compression —
      // so dedup stays stable regardless of what a subclass's preprocess
      // hook does to the bytes downstream.
      const fileHash = sha256Hex(raw);

      const { bytes: processedBytes, mimeType: resolvedMimeType } =
        await this._preProcess(raw, input.mimeType, input.preProcessExtra);

      const compress = this._resolveCompressionPolicy(resolvedMimeType);
      const compressed = compress
        ? await MajikCompressor.compress(processedBytes, input.compressionLevel)
        : processedBytes;

      const iv = generateRandomBytes(IV_LENGTH);
      const ivHex = Array.from(iv)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");

      const cleanedRecipients = deduplicateRecipients(
        input.recipients,
        input.identity.fingerprint,
      );
      MajikFileValidator.assertRecipientLimit(
        cleanedRecipients.length,
        MAX_GROUP_RECIPIENTS,
      );

      const allRecipients: MajikFileRecipient[] = [
        {
          fingerprint: input.identity.fingerprint,
          mlKemPublicKey: input.identity.mlKemPublicKey,
          publicKey: input.identity.publicKey,
        },
        ...cleanedRecipients,
      ];
      const participantPubKeys = allRecipients.map((r) => r.publicKey);
      const isGroupFile = cleanedRecipients.length > 0;

      let ciphertext: Uint8Array;
      let payload: MjkbPayload;

      if (!isGroupFile) {
        const { sharedSecret, cipherText: mlKemCT } = mlKemEncapsulate(
          input.identity.mlKemPublicKey,
        );
        ciphertext = withZeroize([sharedSecret], () =>
          aesGcmEncrypt(sharedSecret, iv, compressed),
        );
        payload = {
          mlKemCipherText: arrayToBase64(mlKemCT),
          n: input.originalName ?? null,
          m: resolvedMimeType ?? null,
          z: compress,
        };
      } else {
        const aesKey = generateRandomBytes(AES_KEY_LEN);
        try {
          ciphertext = aesGcmEncrypt(aesKey, iv, compressed);
          const keys: MajikFileGroupKey[] = allRecipients.map((r) => {
            const { sharedSecret, cipherText: mlKemCT } = mlKemEncapsulate(
              r.mlKemPublicKey,
            );
            return withZeroize([sharedSecret], () => {
              const encryptedAesKey = new Uint8Array(AES_KEY_LEN);
              for (let i = 0; i < AES_KEY_LEN; i++) {
                encryptedAesKey[i] = aesKey[i] ^ sharedSecret[i];
              }
              return {
                fingerprint: r.fingerprint,
                mlKemCipherText: arrayToBase64(mlKemCT),
                encryptedAesKey: arrayToBase64(encryptedAesKey),
              };
            });
          });
          payload = {
            keys,
            n: input.originalName ?? null,
            m: resolvedMimeType ?? null,
            z: compress,
          };
        } finally {
          secureFill(aesKey);
        }
      }

      const mjkbBytes = encodeMjkb(iv, payload, ciphertext);

      return {
        binary: mjkbBytes,
        ivHex,
        fileHash,
        sizeOriginal: raw.byteLength,
        sizeStored: mjkbBytes.byteLength,
        resolvedMimeType,
        participants: participantPubKeys,
        isGroup: isGroupFile,
      };
    } catch (err) {
      if (err instanceof MajikFileError) throw err;
      throw MajikFileError.encryptionFailed(err);
    }
  }

  // ── CREATE ────────────────────────────────────────────────────────────────

  /**
   * Encrypt a raw binary file and produce a base MajikFile instance. Use
   * this directly for a generic encrypted-file use case; for Majikah
   * messaging fields use MajikMessageFile.create() (or its quick-create
   * wrappers) instead — they share this same crypto pipeline via
   * _encryptCore(), not by inheriting this method.
   */
  static async create(options: MajikFileCreateOptions): Promise<MajikFile> {
    const {
      data,
      identity,
      recipients = [],
      originalName = null,
      mimeType: rawMimeType = null,
      id = generateUUID(),
      bypassSizeLimit = false,
      compressionLevel,
      userId,
    } = options;

    MajikFileValidator.assertUserId(userId);
    if (!identity) throw MajikFileError.invalidInput("identity is required");

    const mimeType =
      rawMimeType ??
      (originalName ? inferMimeTypeFromFilename(originalName) : null);

    const core = await MajikFile._encryptCore({
      data,
      identity,
      recipients,
      originalName,
      mimeType,
      bypassSizeLimit,
      compressionLevel,
    });

    const now = new Date().toISOString();
    const json: MajikFileJSON = {
      id,
      schema_version: FILE_SCHEMA_VERSION,
      kind: "file",
      user_id: userId,
      original_name: originalName,
      mime_type: core.resolvedMimeType,
      size_original: core.sizeOriginal,
      size_stored: core.sizeStored,
      file_hash: core.fileHash,
      encryption_iv: core.ivHex,
      participants: core.participants,
      kem_alg: CRYPTO_SUITE.kemAlg,
      cipher_alg: CRYPTO_SUITE.cipherAlg,
      timestamp: now,
      last_update: now,
      signature: null,
    };

    const instance = new MajikFile(json, core.binary, core.isGroup);
    instance.validate();
    return instance._sealInstance();
  }

  // ── CREATE AND SIGN ───────────────────────────────────────────────────────

  static async createAndSign(
    options: MajikFileCreateOptions,
    key: MajikKey,
    signOptions?: { contentType?: string; timestamp?: string },
  ): Promise<MajikFile> {
    const file = await MajikFile.create(options);
    await file.sign(key, signOptions);
    return file;
  }

  // ── IDENTITY RESOLUTION (decrypt-related methods) ─────────────────────────

  private static _isMajikKey<T>(v: MajikKey | T): v is MajikKey {
    return v instanceof MajikKey;
  }

  /**
   * Resolve any accepted decrypt-identity shape down to the minimal
   * { fingerprint, mlKemSecretKey } pair, validating along the way.
   * Every decrypt-related method funnels through this.
   *
   * @throws MajikFileError if identity is missing or the ML-KEM secret key
   *         is the wrong length.
   * @throws MajikKeyError if a MajikKey input is locked or has no ML-KEM
   *         secret key loaded.
   */
  private static _resolveDecryptIdentity(
    input: MajikFileDecryptIdentity,
  ): Pick<MajikFileIdentity, "fingerprint" | "mlKemSecretKey"> {
    if (!input) {
      throw MajikFileError.invalidInput("identity is required for decryption");
    }

    let fingerprint: MajikKeyFingerprint;
    let mlKemSecretKey: Uint8Array | undefined;

    if (MajikFile._isMajikKey(input)) {
      if (input.isLocked || !input.mlKemSecretKey) {
        throw new MajikKeyError("Key is locked", "MajikKey");
      }
      fingerprint = input.fingerprint;
      mlKemSecretKey = input.mlKemSecretKey;
    } else {
      fingerprint = input.fingerprint;
      mlKemSecretKey = input.mlKemSecretKey;
    }

    MajikFileValidator.assertMlKemSecretKey(
      mlKemSecretKey,
      "identity.mlKemSecretKey",
    );
    return { fingerprint, mlKemSecretKey: mlKemSecretKey! };
  }

  // ── DECRYPT (static) ──────────────────────────────────────────────────────

  /**
   * Core decrypt routine shared by decrypt() and decryptWithMetadata().
   * Decodes the .mjkb binary, recovers the AES key (single or group path),
   * authenticates + decrypts, and decompresses using the `z` flag when
   * present (v2) or the mime-only fallback policy for legacy v1 binaries.
   *
   * Zeroization: the derived AES key is wiped in a `finally` immediately
   * after the decrypt attempt, regardless of success. If decompression
   * runs, the pre-decompression compressed buffer is wiped once the final
   * plaintext exists — it's a redundant copy of sensitive data at that point.
   *
   * Note: ML-KEM decapsulation NEVER throws on a wrong key — it returns a
   * garbage shared secret. AES-GCM authentication catches this silently
   * (aesGcmDecrypt returns null), surfaced here as decryptionFailed().
   */
  private static async _decryptCore(
    source: Blob | Uint8Array | ArrayBuffer,
    identity: MajikFileDecryptIdentity,
  ): Promise<{ bytes: Uint8Array; payload: AnyMjkbPayload }> {
    const resolved = MajikFile._resolveDecryptIdentity(identity);

    try {
      const raw = MajikFile.stripMjksTrailer(
        await normaliseToUint8ArrayAsync(source),
      );
      const { iv, payload, ciphertext } = decodeMjkb(raw);

      const aesKey = resolveAesKeyFromPayload(payload, resolved);
      let decrypted: Uint8Array | null;
      try {
        decrypted = aesGcmDecrypt(aesKey, iv, ciphertext);
      } finally {
        secureFill(aesKey);
      }

      if (!decrypted) {
        throw MajikFileError.decryptionFailed(
          "Decryption failed — wrong key or corrupted .mjkb file",
        );
      }

      const shouldDecompress = hasCompressionFlag(payload)
        ? payload.z
        : shouldCompressMime(payload.m); // legacy v1 fallback — mime-only, no context needed

      const bytes = shouldDecompress
        ? await MajikCompressor.decompress(decrypted)
        : decrypted;

      if (shouldDecompress) {
        // `decrypted` (the compressed intermediate) is now a redundant copy
        // of sensitive content once `bytes` holds the decompressed result.
        secureFill(decrypted);
      }

      return { bytes, payload };
    } catch (err) {
      if (err instanceof MajikFileError) throw err;
      throw MajikFileError.decryptionFailed("File decryption failed", err);
    }
  }

  /**
   * Decrypt a .mjkb Blob, Uint8Array, or ArrayBuffer.
   * @throws MajikFileError on wrong key, missing key entry, corrupt data, or format errors.
   * @throws MajikKeyError if a MajikKey input is locked.
   */
  static async decrypt(
    source: Blob | Uint8Array | ArrayBuffer,
    identity: MajikFileDecryptIdentity,
  ): Promise<Uint8Array> {
    const { bytes } = await MajikFile._decryptCore(source, identity);
    return bytes;
  }

  /**
   * Decrypt a .mjkb binary and return the raw bytes together with the
   * original filename, MIME type, and any attached signature.
   * Does NOT verify the signature — pass it to file.verify() for that.
   */
  static async decryptWithMetadata(
    source: Blob | Uint8Array | ArrayBuffer,
    identity: MajikFileDecryptIdentity,
    signatureRaw?: string | null,
  ): Promise<{
    bytes: Uint8Array;
    originalName: string | null;
    mimeType: string | null;
    signature: MajikSignature | null;
  }> {
    const { bytes, payload } = await MajikFile._decryptCore(source, identity);

    let signature: MajikSignature | null = null;
    if (signatureRaw?.trim()) {
      try {
        signature = MajikSignature.deserialize(signatureRaw);
      } catch {
        signature = null;
      }
    }

    return { bytes, originalName: payload.n, mimeType: payload.m, signature };
  }

  /**
   * Instance wrapper — automatically passes the attached signature.
   * @throws MajikFileError if _binary is not loaded or decryption fails.
   */
  async decryptWithMetadata(identity: MajikFileDecryptIdentity): Promise<{
    bytes: Uint8Array;
    originalName: string | null;
    mimeType: string | null;
    signature: MajikSignature | null;
  }> {
    if (!this._binary) throw MajikFileError.missingBinary();
    return MajikFile.decryptWithMetadata(
      this._binary,
      identity,
      this._signature,
    );
  }

  /**
   * Decrypt the .mjkb binary already loaded on this instance.
   * @throws MajikFileError if _binary is not loaded or decryption fails.
   */
  async decryptBinary(identity: MajikFileDecryptIdentity): Promise<Uint8Array> {
    if (!this._binary) throw MajikFileError.missingBinary();
    return MajikFile.decrypt(this._binary, identity);
  }

  /**
   * Decrypt the loaded binary and cache the plaintext on `_decrypted`.
   * Any stale cache is zeroized before being replaced. Returns `this`.
   */
  async decryptHydrate(identity: MajikFileDecryptIdentity): Promise<this> {
    if (!this._binary) throw MajikFileError.missingBinary();
    if (this._decrypted) secureFill(this._decrypted);
    const { bytes } = await MajikFile._decryptCore(this._binary, identity);
    this._decrypted = bytes;
    return this;
  }

  /**
   * Check whether a given key can decrypt this file by verifying recipient capability.
   */
  canDecrypt(key: MajikKey | Partial<MajikFileIdentity>): boolean {
    // _participants stores public keys (MajikKeyAddress strings).
    // Extract the public key depending on whether a MajikKey or MajikFileIdentity was passed.
    const pubKey =
      (key as MajikKey).publicKeyBase64 || (key as MajikFileIdentity).publicKey;

    if (pubKey) {
      return this._participants.includes(pubKey);
    }

    // Fallback check just in case
    if (key.fingerprint) {
      return this._participants.includes(key.fingerprint);
    }

    return false;
  }

  // ==========================================================================
  // ── Batch Operations ──────────────────────────────────────────────────────
  // ==========================================================================

  /**
   * Decrypt an array of MajikFile (or subclass) instances concurrently.
   * Always attempts to hydrate/unlock the file directly. Files that cannot be
   * decrypted are collected in `errors` and excluded from `decrypted`.
   */
  static async batchDecrypt<T extends MajikFile>(
    files: T[],
    key: MajikKey | MajikFileDecryptIdentity,
  ): Promise<BatchDecryptResult<T>> {
    MajikFile._resolveDecryptIdentity(key);

    const errors: BatchDecryptResult<T>["errors"] = [];

    const results = await Promise.allSettled(
      files.map(async (file) => {
        if (file.hasDecryptedFile) return file;
        if (!file.canDecrypt(key)) {
          throw new Error(
            `Key "${key.fingerprint}" is not a participant of this file.`,
          );
        }
        await file.decryptHydrate(key);
        return file;
      }),
    );

    const decrypted: T[] = [];
    results.forEach((result, i) => {
      if (result.status === "fulfilled") {
        decrypted.push(result.value);
      } else {
        errors.push({
          id: files[i].id,
          reason:
            result.reason instanceof Error
              ? result.reason.message
              : String(result.reason),
        });
      }
    });

    return { success: errors.length === 0, decrypted, errors };
  }

  /** Zeroizes and clears the in-memory decrypted cache from all encrypted files in the batch. */
  static batchLock<T extends MajikFile>(files: T[]): BatchLockResult {
    let locked = 0;
    let skipped = 0;
    for (const file of files) {
      if (!file.hasDecryptedFile) {
        skipped++;
        continue;
      }
      file.secureLock();
      locked++;
    }
    return { locked, skipped };
  }

  /** Zeroizes and clears the runtime-only decrypted cache. */
  secureLock(): this {
    if (this._decrypted) secureFill(this._decrypted);
    this._decrypted = undefined;
    return this;
  }

  // ── SERIALISATION ─────────────────────────────────────────────────────────

  /**
   * Serialise metadata to a plain object. The encrypted binary (_binary)
   * AND the in-memory decrypted cache (_decrypted) are intentionally
   * excluded — use toDangerousJSON() if you explicitly need the plaintext.
   */
  toJSON(): MajikFileJSON {
    this.validate();
    return {
      id: this._id,
      schema_version: this._schemaVersion,
      kind: this._kind,
      user_id: this._userId,
      original_name: this._originalName,
      mime_type: this._mimeType,
      size_original: this._sizeOriginal,
      size_stored: this._sizeStored,
      file_hash: this._fileHash,
      encryption_iv: this._encryptionIv,
      participants: this._participants,
      kem_alg: this._kemAlg,
      cipher_alg: this._cipherAlg,
      timestamp: this._timestamp,
      last_update: this._lastUpdate,
      signature: this._signature ?? null,
    };
  }

  /**
   * Like toJSON(), but also includes the in-memory decrypted plaintext
   * (base64-encoded) if decryptHydrate() has populated it this session.
   *
   * ⚠️ DANGEROUS: exposes plaintext file contents in the serialised output.
   * Never persist the result to any shared/long-lived store.
   */
  toDangerousJSON(): MajikFileJSON & { decrypted_base64: string | null } {
    return {
      ...this.toJSON(),
      decrypted_base64: this._decrypted ? arrayToBase64(this._decrypted) : null,
    };
  }

  /**
   * Restore a MajikFile from its serialised JSON representation.
   * @param json   MajikFileJSON — must carry schema_version FILE_SCHEMA_VERSION or lower.
   * @param binary Optional encrypted .mjkb bytes.
   */
  /**
   * Peek at a binary's payload (if provided) to detect single vs group
   * mode. Shared by fromJSON() here and in every subclass's own fromJSON()
   * override, so this parsing logic exists exactly once.
   */
  protected static _detectIsGroupFromBinary(
    binaryBytes: Uint8Array | null,
  ): boolean {
    if (!binaryBytes) return false;
    try {
      const { payload } = decodeMjkb(binaryBytes);
      return isMjkbGroupPayload(payload);
    } catch {
      // Binary is malformed — let validate() / downstream use catch it.
      return false;
    }
  }

  static fromJSON(
    json: MajikFileJSON,
    binary?: Uint8Array | ArrayBuffer | null,
  ): MajikFile {
    if (!json || typeof json !== "object") {
      throw MajikFileError.invalidInput(
        "fromJSON: json must be a non-null object",
      );
    }
    MajikFileValidator.assertSchemaVersion(
      json.schema_version,
      FILE_SCHEMA_VERSION,
    );

    const binaryBytes = binary != null ? normaliseToUint8Array(binary) : null;
    const isGroup = MajikFile._detectIsGroupFromBinary(binaryBytes);

    const instance = new MajikFile(json, binaryBytes, isGroup);
    instance.validate();
    return instance._sealInstance();
  }

  static async fromJSONWithBlob(
    json: MajikFileJSON,
    binary: Blob,
  ): Promise<MajikFile> {
    const bytes = new Uint8Array(await binary.arrayBuffer());
    return MajikFile.fromJSON(json, bytes);
  }

  // ── toMJKB / toBinaryBytes ────────────────────────────────────────────────

  toMJKB(): Blob {
    if (!this._binary) throw MajikFileError.missingBinary();
    return new Blob([this._binary as BlobPart], {
      type: "application/vnd.majikah.bundle",
    });
  }

  static hasMjksTrailer(data: Uint8Array): boolean {
    if (data.length < MJKS_OVERHEAD + 23) return false;
    const tail = data.subarray(data.length - MJKS_MAGIC_LEN);
    return (
      tail[0] === MJKS_MAGIC[0] &&
      tail[1] === MJKS_MAGIC[1] &&
      tail[2] === MJKS_MAGIC[2] &&
      tail[3] === MJKS_MAGIC[3]
    );
  }

  static extractMjksSignature(data: Uint8Array): MajikSignature | null {
    if (!MajikFile.hasMjksTrailer(data)) return null;
    try {
      const lengthOffset = data.length - MJKS_OVERHEAD;
      const sigLen =
        (data[lengthOffset] << 24) |
        (data[lengthOffset + 1] << 16) |
        (data[lengthOffset + 2] << 8) |
        data[lengthOffset + 3];

      if (sigLen <= 0 || sigLen > data.length - MJKS_OVERHEAD) return null;

      const sigStart = data.length - MJKS_OVERHEAD - sigLen;
      const sigBytes = data.subarray(sigStart, sigStart + sigLen);
      const sigJson = new TextDecoder().decode(sigBytes);
      return MajikSignature.fromJSON(JSON.parse(sigJson));
    } catch {
      return null;
    }
  }

  static stripMjksTrailer(data: Uint8Array): Uint8Array {
    if (!MajikFile.hasMjksTrailer(data)) return data;
    const lengthOffset = data.length - MJKS_OVERHEAD;
    const sigLen =
      (data[lengthOffset] << 24) |
      (data[lengthOffset + 1] << 16) |
      (data[lengthOffset + 2] << 8) |
      data[lengthOffset + 3];
    return data.subarray(0, data.length - MJKS_OVERHEAD - sigLen);
  }

  /**
   * Export the encrypted binary with the attached MajikSignature appended
   * as a MJKS trailer — offline recipients can verify without a database
   * round-trip. Format: [.mjkb bytes][sig JSON][uint32 BE len]["MJKS"].
   */
  toSignedMJKB(): Blob {
    if (!this._binary) throw MajikFileError.missingBinary();
    if (!this._signature?.trim()) {
      throw MajikFileError.invalidInput(
        "toSignedMJKB: no signature attached — call sign() or createAndSign() first",
      );
    }

    const sigBytes = new TextEncoder().encode(
      JSON.stringify(MajikSignature.deserialize(this._signature).toJSON()),
    );

    const trailer = new Uint8Array(sigBytes.length + MJKS_OVERHEAD);
    trailer.set(sigBytes, 0);
    const len = sigBytes.length;
    trailer[len] = (len >>> 24) & 0xff;
    trailer[len + 1] = (len >>> 16) & 0xff;
    trailer[len + 2] = (len >>> 8) & 0xff;
    trailer[len + 3] = len & 0xff;
    trailer.set(MJKS_MAGIC, len + 4);

    return new Blob([this._binary as BlobPart, trailer], {
      type: "application/vnd.majikah.bundle",
    });
  }

  toBinaryBytes(): Uint8Array {
    if (!this._binary) throw MajikFileError.missingBinary();
    return this._binary;
  }

  // ── VALIDATE ──────────────────────────────────────────────────────────────

  /**
   * Collects (without throwing) every base-level validation error. Exposed
   * as `protected` so MajikMessageFile.validate() can call
   * `super._collectErrors()`, append its own context/storage errors, and
   * throw exactly once with the full combined list — rather than the base
   * and subclass validating in two separate throwing passes.
   */
  protected _collectErrors(): string[] {
    const errors: string[] = [];
    const push = (err: string | null) => {
      if (err) errors.push(err);
    };

    push(MajikFileValidator.checkId(this._id));
    push(MajikFileValidator.checkUserId(this._userId));
    push(MajikFileValidator.checkFileHash(this._fileHash));
    push(MajikFileValidator.checkEncryptionIv(this._encryptionIv));
    push(
      MajikFileValidator.checkNonNegativeSize(
        this._sizeOriginal,
        "size_original",
      ),
    );
    push(
      MajikFileValidator.checkNonNegativeSize(this._sizeStored, "size_stored"),
    );
    push(
      MajikFileValidator.checkSchemaVersion(
        this._schemaVersion,
        FILE_SCHEMA_VERSION,
      ),
    );

    return errors;
  }

  /**
   * Validate all required base properties, throwing once with every error
   * found. Subclasses override this to combine `super._collectErrors()`
   * with their own rules — see MajikMessageFile.validate().
   */
  validate(): void {
    MajikFileValidator.assertAll(this._collectErrors());
  }

  // ── OWNERSHIP ─────────────────────────────────────────────────────────────

  userIsOwner(userId: string): boolean {
    if (!userId?.trim()) return false;
    return this._userId === userId;
  }

  // ── BINARY MANAGEMENT ─────────────────────────────────────────────────────

  attachBinary(binary: Uint8Array | ArrayBuffer): void {
    this._binary = normaliseToUint8Array(binary);
  }

  clearBinary(): void {
    this._binary = null;
  }

  // ── PARTICIPANT ACCESS ────────────────────────────────────────────────────

  /**
   * True if the given public key string is in the participants list.
   * Note: participants are the *recipients'* public keys — the owner's key
   * is not included (owner self-encrypts via identity). For owner checks
   * use userIsOwner().
   */
  hasParticipantAccess(publicKey: MajikKeyAddress): boolean {
    if (!publicKey?.trim()) return false;
    return this._participants.includes(publicKey);
  }

  /**
   * Lightweight fingerprint check — true if publicKey hashes (SHA-256
   * base64) to ownerFingerprint. Does NOT attempt decryption.
   */
  static hasPublicKeyAccess(
    publicKey: Uint8Array,
    ownerFingerprint: MajikKeyFingerprint,
  ): boolean {
    MajikFileValidator.assertMlKemPublicKey(publicKey, "publicKey");
    if (!ownerFingerprint?.trim()) {
      throw MajikFileError.invalidInput(
        "hasPublicKeyAccess: ownerFingerprint is required",
      );
    }
    return sha256Base64(publicKey) === ownerFingerprint;
  }

  // ── MIME / FORMAT HELPERS ─────────────────────────────────────────────────

  get isInlineViewable(): boolean {
    return isMimeTypeInlineViewable(this._mimeType);
  }

  get safeFilename(): string {
    return deriveFilename(this._fileHash, this._originalName);
  }

  // ── SIZE CHECK ────────────────────────────────────────────────────────────

  exceedsSize(limitMB: number): boolean {
    if (typeof limitMB !== "number" || limitMB <= 0 || !isFinite(limitMB)) {
      throw MajikFileError.invalidInput(
        `exceedsSize: limitMB must be a positive finite number (got ${limitMB})`,
      );
    }
    return this._sizeOriginal > limitMB * 1024 * 1024;
  }

  // ── STATS ─────────────────────────────────────────────────────────────────

  getStats(): MajikFileStats {
    return {
      id: this._id,
      originalName: this._originalName,
      mimeType: this._mimeType,
      sizeOriginalHuman: formatBytes(this._sizeOriginal),
      sizeStoredHuman: formatBytes(this._sizeStored),
      compressionRatioPct: MajikCompressor.compressionRatioPct(
        this._sizeOriginal,
        this._sizeStored,
      ),
      fileHash: this._fileHash,
      isGroup: this._isGroup,
      isSigned: this.isSigned,
    };
  }

  // ── DUPLICATE DETECTION ───────────────────────────────────────────────────

  isDuplicateOf(other: MajikFile): boolean {
    return this._fileHash === other._fileHash;
  }

  static wouldBeDuplicate(rawBytes: Uint8Array, existingHash: string): boolean {
    return sha256Hex(rawBytes) === existingHash;
  }

  // ── STATIC HELPERS ────────────────────────────────────────────────────────

  static isMjkbCandidate(data: Uint8Array | ArrayBuffer): boolean {
    const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
    if (bytes.length < 5) return false;
    return (
      bytes[0] === 0x4d &&
      bytes[1] === 0x4a &&
      bytes[2] === 0x4b &&
      bytes[3] === 0x42
    );
  }

  static formatBytes(bytes: number): string {
    return formatBytes(bytes);
  }

  static inferMimeType(filename: string): string | null {
    return inferMimeTypeFromFilename(filename);
  }

  toString(): string {
    return (
      `${this.constructor.name} { ` +
      `id: ${this._id}, ` +
      `hash: ${this._fileHash.slice(0, 8)}…, ` +
      `size: ${formatBytes(this._sizeOriginal)}, ` +
      `type: ${this._isGroup ? "group" : "single"}, ` +
      `signed: ${this.isSigned}` +
      ` }`
    );
  }

  /**
   * Fully validate a .mjkb binary beyond the quick magic-byte check.
   * Version-agnostic on payload shape — accepts either v1 (`c`) or v2
   * (`z`) payloads, as long as the single/group crypto material is present.
   * Does NOT attempt decryption.
   */
  static isValidMJKB(data: Uint8Array | ArrayBuffer): boolean {
    try {
      const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
      if (bytes.length < 23) return false;
      if (
        bytes[0] !== 0x4d ||
        bytes[1] !== 0x4a ||
        bytes[2] !== 0x4b ||
        bytes[3] !== 0x42
      ) {
        return false;
      }

      const version = bytes[4];
      const payloadLenOffset = 17; // 4 magic + 1 version + 12 IV
      const payloadLen =
        (bytes[payloadLenOffset] << 24) |
        (bytes[payloadLenOffset + 1] << 16) |
        (bytes[payloadLenOffset + 2] << 8) |
        bytes[payloadLenOffset + 3];
      if (payloadLen <= 0) return false;

      const payloadStart = payloadLenOffset + 4;
      const ciphertextStart = payloadStart + payloadLen;
      if (ciphertextStart >= bytes.length) return false;

      let payload: unknown;
      try {
        payload = JSON.parse(
          new TextDecoder().decode(bytes.slice(payloadStart, ciphertextStart)),
        );
      } catch {
        return false;
      }
      if (!payload || typeof payload !== "object") return false;

      const isSingle =
        "mlKemCipherText" in (payload as object) &&
        !("keys" in (payload as object));
      const isGroup =
        "keys" in (payload as object) &&
        Array.isArray((payload as { keys: unknown }).keys) &&
        (payload as { keys: unknown[] }).keys.length > 0;
      if (!isSingle && !isGroup) return false;

      if (bytes.length <= ciphertextStart) return false;

      void version; // version itself isn't part of the structural check — decodeMjkb() enforces it
      return true;
    } catch {
      return false;
    }
  }

  static getRawFileSize(data: Uint8Array | ArrayBuffer): number {
    return data instanceof Uint8Array ? data.byteLength : data.byteLength;
  }

  // ── SIGNING ──────────────────────────────────────────────────────────────

  attachSignature(signature: MajikSignature | string): void {
    if (typeof signature === "string") {
      if (!signature.trim()) {
        throw MajikFileError.invalidInput(
          "attachSignature: signature string must be non-empty",
        );
      }
      try {
        MajikSignature.deserialize(signature);
      } catch (err) {
        throw MajikFileError.invalidInput(
          `attachSignature: signature string is not a valid serialized MajikSignature — ${
            err instanceof Error ? err.message : String(err)
          }`,
        );
      }
      this._signature = signature;
    } else {
      this._signature = signature.serialize();
    }
    this._lastUpdate = new Date().toISOString();
  }

  removeSignature(): void {
    if (this._signature === null) return;
    this._signature = null;
    this._lastUpdate = new Date().toISOString();
  }

  /**
   * Sign the loaded .mjkb binary and attach the resulting signature. The
   * signature covers the encrypted binary — verification never requires
   * decryption. Replaces any existing signature.
   */
  async sign(
    key: MajikKey,
    options?: { contentType?: string; timestamp?: string },
  ): Promise<MajikSignature> {
    if (!this._binary) throw MajikFileError.missingBinary();
    const sig = await MajikSignature.sign(this._binary, key, {
      contentType: options?.contentType ?? this._mimeType ?? undefined,
      timestamp: options?.timestamp,
    });
    this.attachSignature(sig);
    return sig;
  }

  /**
   * Verify the attached signature against the loaded .mjkb binary.
   * Returns null if unsigned or the binary isn't loaded — check isSigned
   * first to distinguish "unsigned" from "binary not loaded."
   */
  verify(
    keyOrPublicKeys: MajikKey | MajikSignerPublicKeys,
  ): VerificationResult | null {
    if (!this._signature?.trim()) return null;
    if (!this._binary) return null;

    let sig: MajikSignature;
    try {
      sig = MajikSignature.deserialize(this._signature);
    } catch {
      return null;
    }

    if (MajikFile._isMajikKey(keyOrPublicKeys)) {
      return MajikSignature.verifyWithKey(this._binary, sig, keyOrPublicKeys);
    }
    return MajikSignature.verify(this._binary, sig, keyOrPublicKeys);
  }

  /**
   * Decrypt (as a correctness gate — proves the given identity can access
   * this file and the ciphertext is well-formed), then verify the attached
   * signature against the same encrypted binary that sign()/verify() use.
   */
  async verifyBinary(
    identity: MajikFileDecryptIdentity,
    keyOrPublicKeys: MajikKey | MajikSignerPublicKeys,
  ): Promise<VerificationResult> {
    if (!this._binary) throw MajikFileError.missingBinary();
    if (!this._signature?.trim()) {
      throw MajikFileError.invalidInput(
        "verifyBinary: this file has no attached signature",
      );
    }

    let sig: MajikSignature;
    try {
      sig = MajikSignature.deserialize(this._signature);
    } catch (err) {
      throw MajikFileError.invalidInput(
        `verifyBinary: stored signature is corrupt — ${
          err instanceof Error ? err.message : String(err)
        }`,
      );
    }

    await MajikFile.decrypt(this._binary, identity);

    if (MajikFile._isMajikKey(keyOrPublicKeys)) {
      return MajikSignature.verifyWithKey(this._binary, sig, keyOrPublicKeys);
    }
    return MajikSignature.verify(this._binary, sig, keyOrPublicKeys);
  }

  /**
   * Verify the MJKS trailer signature on a signed .mjkb binary in one
   * call — no database round-trip needed. Verifies the encrypted binary,
   * not the plaintext (proves the ciphertext hasn't been tampered with).
   */
  static async verifySignedMJKB(
    source: Blob | Uint8Array | ArrayBuffer,
    keyOrPublicKeys: MajikKey | MajikSignerPublicKeys,
  ): Promise<VerificationResult> {
    const data = await normaliseToUint8ArrayAsync(source);

    if (!MajikFile.hasMjksTrailer(data)) {
      throw MajikFileError.invalidInput(
        "verifySignedMJKB: no MJKS trailer found — use toSignedMJKB() to export a signed file",
      );
    }

    const sig = MajikFile.extractMjksSignature(data);
    if (!sig) {
      throw MajikFileError.invalidInput(
        "verifySignedMJKB: MJKS trailer present but signature could not be parsed",
      );
    }

    const mjkbBytes = MajikFile.stripMjksTrailer(data);

    if (MajikFile._isMajikKey(keyOrPublicKeys)) {
      return MajikSignature.verifyWithKey(mjkbBytes, sig, keyOrPublicKeys);
    }
    return MajikSignature.verify(mjkbBytes, sig, keyOrPublicKeys);
  }

  /**
   * Extract envelope metadata from the attached signature without full
   * cryptographic verification — for UI display before deciding whether
   * to run the more expensive verify() call.
   */
  getSignatureInfo(): FileSignature | null {
    if (!this._signature?.trim()) return null;
    try {
      const sig = MajikSignature.deserialize(this._signature);
      return {
        signerId: sig.signerId,
        timestamp: sig.timestamp,
        contentType: sig.contentType,
        contentHash: sig.contentHash,
      };
    } catch {
      return null;
    }
  }
}
