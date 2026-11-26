/**
 * core/types/base.ts
 *
 * Types for the base, platform-agnostic MajikFile. Nothing in here knows
 * about chat, threads, R2, or any other Majikah-specific concept — that
 * all lives in core/types/message.ts, layered on top via MajikMessageFile.
 */

import type { CompressionLevel } from "./compressor/majik-compressor.js";
import type {
  MajikKey,
  MajikKeyAddress,
  MajikKeyFingerprint,
  MLKEM768RawPublicKey,
} from "@majikah/majik-key";
import { CRYPTO_SUITE, COMPRESSION_SUITE } from "./crypto/constants.js";

// ─── Compression Codec (pluggable compression) ─────────────────────────────

/**
 * Pluggable compression implementation. When supplied to create() (as
 * `compressor`), replaces the built-in MajikCompressor/zstd for that one
 * encryption. `alg` is stamped into both the .mjkb payload (`ca` field —
 * added in a follow-up step) and the JSON record (`compression_alg` —
 * also a follow-up step) so a file compressed with a custom codec is
 * self-describing on both the wire and the row, the same way CRYPTO_SUITE
 * makes kem_alg/cipher_alg self-describing.
 *
 * Omitting `compressor` on create() defaults to ZSTD_CODEC (see
 * majik-compressor.ts) — every existing call site is unaffected.
 *
 * `alg` must be stable for a given codec's output: it's the key used to
 * look the same codec back up on decrypt (see DecryptCompressionOptions).
 */
export interface CompressionCodec {
  /** Identifier stamped into payload.ca / json.compression_alg (e.g. "zstd", "brotli", "my-custom-alg"). */
  alg: string;
  compress(
    bytes: Uint8Array,
    level?: CompressionLevel | number,
  ): Promise<Uint8Array> | Uint8Array;
  decompress(bytes: Uint8Array): Promise<Uint8Array> | Uint8Array;
}

/**
 * Optional bag accepted by every decrypt-family method (decrypt(),
 * decryptWithMetadata(), decryptBinary(), decryptHydrate(), verifyBinary(),
 * batchDecrypt(), canDecryptMJKB()). The built-in zstd codec is always
 * tried first and needs no entry here — `compressors` is only consulted
 * when a payload's `ca` names something else. An unmatched non-zstd `ca`
 * throws MajikFileError.unsupportedCompressionAlg().
 */
export interface DecryptCompressionOptions {
  compressors?: CompressionCodec[];
}

// ─── Identities & Recipients ────────────────────────────────────────────────

/**
 * Public identity material sufficient to create an encrypted .mjkb.
 *
 * Encryption never needs the sender's ML-KEM secret key. Keeping this
 * contract separate lets issuers encrypt for pinned MUID recipients without
 * unlocking or copying any private key material into the encryption flow.
 */
export interface MajikFileEncryptionIdentity {
  publicKey: MajikKeyAddress;
  /** Base64 SHA-256 of the ML-KEM public key — used to identify key entries. */
  fingerprint: MajikKeyFingerprint;
  /** ML-KEM-768 public key (1184 bytes) — used during encryption. */
  mlKemPublicKey: MLKEM768RawPublicKey;
}

/**
 * Full identity material for operations that require decryption.
 * The secret ML-KEM key remains local to the account and must never be
 * persisted in session metadata or sent to a storage service.
 */
export interface MajikFileIdentity extends MajikFileEncryptionIdentity {
  /** ML-KEM-768 secret key (2400 bytes) — used only during decryption. */
  mlKemSecretKey: Uint8Array;
}

/**
 * A recipient who can decrypt the file. Carries only the public key — the
 * secret key never leaves the recipient's device.
 */
export interface MajikFileRecipient {
  /** Base64 SHA-256 of the ML-KEM public key — used to locate the key entry on decrypt. */
  fingerprint: MajikKeyFingerprint;
  publicKey: MajikKeyAddress;
  /** ML-KEM-768 public key (1184 bytes). */
  mlKemPublicKey: MLKEM768RawPublicKey;
}

/**
 * Union accepted by every decrypt-related method on MajikFile (decrypt(),
 * decryptWithMetadata(), decryptBinary(), decryptHydrate(), verifyBinary(),
 * batchDecrypt()). Callers may pass either a full (unlocked) MajikKey
 * instance, or the bare minimal identity shape.
 */
export type MajikFileDecryptIdentity =
  | MajikKey
  | Pick<MajikFileIdentity, "fingerprint" | "mlKemSecretKey">;

// ─── Per-recipient key entry (group .mjkb) ──────────────────────────────────

/**
 * Per-recipient encrypted key entry stored inside a group .mjkb binary.
 * encryptedAesKey = groupAesKey XOR mlKemSharedSecret (32-byte XOR one-time-pad).
 */
export interface MajikFileGroupKey {
  fingerprint: MajikKeyFingerprint;
  /** Base64-encoded ML-KEM-768 ciphertext (1088 bytes) for this recipient. */
  mlKemCipherText: string;
  /** Base64-encoded 32-byte encrypted AES key (groupAesKey XOR sharedSecret). */
  encryptedAesKey: string;
}

// ─── .mjkb Payload Types ─────────────────────────────────────────────────────
//
// Three payload generations coexist so existing files remain readable:
//
// v1 is legacy and infers compression from the old context + MIME policy.
// v2 uses the explicit z flag and the original whole-buffer AES-GCM layout.
// v3 retains the same recipient key material and adds the streaming suite,
// chunk size, and authenticated final-manifest contract.

export interface MjkbSinglePayloadV1 {
  mlKemCipherText: string;
  n: string | null;
  m: string | null;
  c: string | null;
}
export interface MjkbGroupPayloadV1 {
  keys: MajikFileGroupKey[];
  n: string | null;
  m: string | null;
  c: string | null;
}
export type MjkbPayloadV1 = MjkbSinglePayloadV1 | MjkbGroupPayloadV1;

export interface MjkbSinglePayloadV2 {
  mlKemCipherText: string;
  n: string | null;
  m: string | null;
  z: boolean;
  ca?: string;
}
export interface MjkbGroupPayloadV2 {
  keys: MajikFileGroupKey[];
  n: string | null;
  m: string | null;
  z: boolean;
  ca?: string;
}
export type MjkbPayloadV2 = MjkbSinglePayloadV2 | MjkbGroupPayloadV2;

/** v3 single-recipient stream payload. Property order mirrors Rust serde. */
export interface MjkbSinglePayloadV3 {
  mlKemCipherText: string;
  n: string | null;
  m: string | null;
  z: boolean;
  /** Omitted for the standard Zstandard streaming codec. */
  ca?: string;
  chunkSize: number;
  streamSuite: string;
}

/** v3 group stream payload. Property order mirrors Rust serde. */
export interface MjkbGroupPayloadV3 {
  keys: MajikFileGroupKey[];
  n: string | null;
  m: string | null;
  z: boolean;
  /** Omitted for the standard Zstandard streaming codec. */
  ca?: string;
  chunkSize: number;
  streamSuite: string;
}
export type MjkbPayloadV3 = MjkbSinglePayloadV3 | MjkbGroupPayloadV3;

/** Legacy v2 payload alias retained for the compatibility encoder. */
export type MjkbPayload = MjkbPayloadV2;

/** Any payload shape decodeMjkb() may return. */
export type AnyMjkbPayload = MjkbPayloadV1 | MjkbPayloadV2 | MjkbPayloadV3;

// ─── Decoded .mjkb Binary ────────────────────────────────────────────────────

/**
 * Parsed .mjkb header and body. For v1/v2, ciphertext is the single AES-GCM
 * ciphertext+tag. For v3, ciphertext is the chunk-record stream and final
 * authenticated manifest; use the streaming reader to decrypt it.
 */
export interface DecodedMjkb {
  version: number;
  /** Nonce / IV extracted from the binary header. */
  iv: Uint8Array;
  /** Single ciphertext for v1/v2; the complete record section for v3. */
  ciphertext: Uint8Array;
  payload: AnyMjkbPayload;
}

// ─── Record schema / kind ────────────────────────────────────────────────────

/**
 * Discriminator for polymorphic reads. Base MajikFile always stamps "file"
 * on records it creates directly; it's exported here as a named constant
 * for that purpose. The JSON field itself (MajikFileJSON.kind, below) is
 * typed as plain `string` rather than this literal — that's deliberate:
 * it lets MajikMessageFileJSON (and any future subclass JSON type) declare
 * its own narrower literal ("message_file", etc.) while still being
 * structurally assignable to MajikFileJSON when a subclass constructor
 * calls super(json, ...).
 */
export type MajikFileKind = "file";

// ─── MajikFileJSON ────────────────────────────────────────────────────────────

/**
 * Serialised representation of the base MajikFile. Contains only what's
 * needed to identify, describe, and decrypt the file — no storage/platform
 * fields. NOTE: the encrypted binary (_binary) is intentionally excluded;
 * it's a separate artifact (R2, disk, IndexedDB — base doesn't care).
 */
export interface MajikFileJSON {
  id: string;
  /**
   * Record schema version (see FILE_SCHEMA_VERSION). Always present on
   * records produced by this SDK. Legacy rows never had this field at
   * all — MajikFile.isLegacyJSON() checks for its absence.
   */
  schema_version: number;
  /** "file" on base records; subclasses stamp their own literal (e.g. "message_file"). */
  kind: string;
  /** Owner's user id. Ownership is a generic concept; kept in the base. */
  user_id: string;
  original_name: string | null;
  mime_type: string | null;
  /** Byte length of the raw plaintext before compression/encryption. */
  size_original: number;
  /** Byte length of the final encrypted .mjkb binary. */
  size_stored: number;
  /** SHA-256 hex digest of the original raw bytes (pre-compression) — dedup key. */
  file_hash: string;
  /**
   * Hex-encoded 12-byte AES-GCM IV — secondary record for audit/key-rotation;
   * decryption reads the authoritative IV from the .mjkb binary header.
   */
  encryption_iv: string;
  participants: MajikKeyAddress[];
  /** Self-describing crypto suite — see CRYPTO_SUITE. */
  kem_alg: string;
  cipher_alg: string;

  compression_level?: CompressionLevel | number;
  /**
   * Self-describing compression algorithm — see COMPRESSION_SUITE, and the
   * `ca` field on MjkbPayloadV2 (the binary carries the authoritative copy
   * of this; this JSON field exists for introspection/UI without needing
   * to decode the .mjkb binary). Absent on legacy/pre-existing records
   * means "zstd" — the only algorithm that existed before CompressionCodec.
   */
  compression_alg?: string;

  timestamp: string | null;
  last_update: string | null;
  /** base64 — MajikSignature.serialize() output. */
  signature: string | null;
}

/** Convenience default used when stamping new records. */
export const DEFAULT_CRYPTO_SUITE_FIELDS = {
  kem_alg: CRYPTO_SUITE.kemAlg,
  cipher_alg: CRYPTO_SUITE.cipherAlg,
} as const;

/** Convenience default used when stamping new records — mirrors DEFAULT_CRYPTO_SUITE_FIELDS. */
export const DEFAULT_COMPRESSION_SUITE_FIELDS = {
  compression_alg: COMPRESSION_SUITE.alg,
} as const;

// ─── CreateOptions ────────────────────────────────────────────────────────────

export interface MajikFileCreateOptions {
  /** Raw binary content of the file to encrypt. */
  data: Uint8Array | ArrayBuffer;
  /** Owner user id — used for ownership checks. */
  userId: string;
  /**
   * Identity of the file owner. For single-recipient files this is the
   * only recipient (self-encryption); for group files this is the sender.
   */
  identity: MajikFileEncryptionIdentity;
  /**
   * Additional recipients beyond the owner. When provided (length ≥ 1),
   * a group .mjkb is produced. When omitted/empty, single-recipient.
   */
  recipients?: MajikFileRecipient[];
  originalName?: string;
  mimeType?: string;
  /** Pre-computed UUID for the record. If omitted, a new UUID is generated. */
  id?: string;
  /** Bypass the MAX_FILE_SIZE_BYTES limit. @default false */
  bypassSizeLimit?: boolean;
  /**
   * Zstd compression level. MJKB v3 defaults to level 6 to match the Rust
   * streaming SDK. Explicit createV2() retains the legacy adaptive level.
   */
  compressionLevel?: CompressionLevel | number;
  /**
   * Custom compression codec. Since the v3 stream contract standardizes
   * Zstandard only, supplying a custom codec automatically uses v2.
   */
  compressor?: CompressionCodec;
}

// ─── File Stats ───────────────────────────────────────────────────────────────

/** Human-readable stats returned by MajikFile.getStats(). */
export interface MajikFileStats {
  id: string;
  originalName: string | null;
  mimeType: string | null;
  sizeOriginalHuman: string;
  sizeStoredHuman: string;
  /** Compression ratio as a percentage reduction. Clamped to 0 minimum. */
  compressionRatioPct: number;
  fileHash: string;
  isGroup: boolean;
  isSigned: boolean;
}

export interface FileSignature {
  signerId: string;
  timestamp: string;
  contentType?: string;
  contentHash: string;
}
