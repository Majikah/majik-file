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
 * The file owner's full identity. Carries both keys — public for
 * encryption, secret for decryption.
 */
export interface MajikFileIdentity {
  publicKey: MajikKeyAddress;
  /** Base64 SHA-256 of the ML-KEM public key — used to look up key entries. */
  fingerprint: MajikKeyFingerprint;
  /** ML-KEM-768 public key (1184 bytes) — used during encryption. */
  mlKemPublicKey: MLKEM768RawPublicKey;
  /** ML-KEM-768 secret key (2400 bytes) — used during decryption. */
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
// Two payload generations coexist so old binaries stay readable:
//
//   v1 (legacy, MJKB_VERSION_LEGACY): payload.c embedded the FileContext, and
//     decrypt-time decompression was *inferred* from context + mime. That's
//     a platform-specific heuristic living inside what should be a generic
//     binary format — fixed in v2. `c` is typed as `string | null` here
//     rather than FileContext, since the base layer doesn't know that type.
//
//   v2 (current, MJKB_VERSION): drops `c` entirely, adds an explicit `z`
//     compression flag set once at encrypt time. Decrypt just reads it —
//     no context lookup needed anywhere in the base decode path.
//
//     `ca` (compression algorithm) is an additive optional field on top of
//     `z`, populated once a CompressionCodec other than the built-in zstd
//     one is used at encrypt time (see CompressionCodec, ZSTD_CODEC).
//     It's only meaningful when `z === true`. Absence means "zstd" — this
//     covers every v2 payload ever produced before CompressionCodec
//     existed, so no migration or MJKB_VERSION bump is needed; decodeMjkb()
//     doesn't care how many keys a payload has. See hasCompressionAlg() in
//     mjkb-codec.ts and COMPRESSION_SUITE in constants.ts.

/**
 * @deprecated
 */
export interface MjkbSinglePayloadV1 {
  mlKemCipherText: string;
  n: string | null;
  m: string | null;
  c: string | null;
}

/**
 * @deprecated
 */
export interface MjkbGroupPayloadV1 {
  keys: MajikFileGroupKey[];
  n: string | null;
  m: string | null;
  c: string | null;
}

/**
 * @deprecated
 */
export type MjkbPayloadV1 = MjkbSinglePayloadV1 | MjkbGroupPayloadV1;

export interface MjkbSinglePayloadV2 {
  mlKemCipherText: string;
  n: string | null;
  m: string | null;
  /** True if the plaintext was compressed before encryption. */
  z: boolean;
  /** Compression algorithm identifier (e.g. "zstd"). Only meaningful when z === true. Absent means "zstd". */
  ca?: string;
}
export interface MjkbGroupPayloadV2 {
  keys: MajikFileGroupKey[];
  n: string | null;
  m: string | null;
  z: boolean;
  /** Compression algorithm identifier (e.g. "zstd"). Only meaningful when z === true. Absent means "zstd". */
  ca?: string;
}
export type MjkbPayloadV2 = MjkbSinglePayloadV2 | MjkbGroupPayloadV2;

/** "Current" payload shape — what encodeMjkb() always produces going forward. */
export type MjkbPayload = MjkbPayloadV2;

/** Any payload shape decodeMjkb() might hand back, legacy or current. */
export type AnyMjkbPayload = MjkbPayloadV1 | MjkbPayloadV2;

// ─── Decoded .mjkb Binary ────────────────────────────────────────────────────

/**
 * Internal representation of a fully parsed .mjkb binary. `version` drives
 * dispatch between the v1 legacy decode/decompress path and the v2 current
 * one — see decodeMjkb() in majik-file.ts.
 */
export interface DecodedMjkb {
  version: number;
  /** IV extracted from the binary header — authoritative source for decryption. */
  iv: Uint8Array;
  /** AES-GCM ciphertext (compressed plaintext, if applicable + 16-byte auth tag). */
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
  identity: MajikFileIdentity;
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
   * Zstd compression level or preset. Always run through
   * MajikCompressor.adaptiveLevel() before use. Defaults to the max level.
   * Ignored if a custom `compressor` is supplied and that codec doesn't
   * use numeric levels — it's simply passed through as-is.
   */
  compressionLevel?: CompressionLevel | number;
  /**
   * Custom compression codec to use in place of the built-in
   * MajikCompressor/zstd for this encryption. Wiring into _encryptCore()
   * lands in a follow-up step — declared here now so the option surface
   * is stable. @default ZSTD_CODEC
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
