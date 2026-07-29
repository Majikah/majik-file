/**
 * core/types/base.ts
 *
 * Types for the base, platform-agnostic MajikFile. Nothing in here knows
 * about chat, threads, R2, or any other Majikah-specific concept — that
 * all lives in core/types/message.ts, layered on top via MajikMessageFile.
 */

import type { CompressionLevel } from "./compressor/majik-compressor";
import type {
  MajikKey,
  MajikKeyAddress,
  MajikKeyFingerprint,
} from "@majikah/majik-key";
import { CRYPTO_SUITE } from "./crypto/constants";

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
  mlKemPublicKey: Uint8Array;
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
  mlKemPublicKey: Uint8Array;
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
  /** True if the plaintext was zstd-compressed before encryption. */
  z: boolean;
}
export interface MjkbGroupPayloadV2 {
  keys: MajikFileGroupKey[];
  n: string | null;
  m: string | null;
  z: boolean;
}
export type MjkbPayloadV2 = MjkbSinglePayloadV2 | MjkbGroupPayloadV2;

/** "Current" payload shape — what encodeMjkb() always produces going forward. */
export type MjkbPayload = MjkbPayloadV2;

/** Any payload shape decodeMjkb() might hand back, legacy or current. */
export type AnyMjkbPayload = MjkbPayloadV1 | MjkbPayloadV2;

export function isMjkbGroupPayload<T extends AnyMjkbPayload>(
  p: T,
): p is Extract<T, { keys: MajikFileGroupKey[] }> {
  return "keys" in p && Array.isArray((p as { keys: unknown }).keys);
}

export function isMjkbSinglePayload<T extends AnyMjkbPayload>(
  p: T,
): p is Exclude<T, { keys: MajikFileGroupKey[] }> {
  return "mlKemCipherText" in p && !("keys" in p);
}

/** True if this payload is the v2 shape (has the explicit compression flag). */
export function hasCompressionFlag(p: AnyMjkbPayload): p is MjkbPayloadV2 {
  return "z" in p;
}

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
   */
  compressionLevel?: CompressionLevel | number;
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
