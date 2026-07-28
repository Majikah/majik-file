/**
 * constants.ts
 *
 * Shared constants for the MajikFile crypto/binary format layer.
 *
 * NOTE: Values for ML-KEM/AES/MJKS below were reconstructed from usage and
 * JSDoc references in the pre-refactor majik-file.ts / crypto-provider.ts
 * you shared. Sizes are the standard ML-KEM-768 + AES-256-GCM sizes, but
 * diff this against your real constants.ts before merging in case anything
 * drifted (e.g. R2 prefix strings, which are inferred/guessed below and
 * MUST be confirmed).
 *
 * R2_PREFIX intentionally does NOT live here — it's a storage-platform
 * concern and belongs to the MajikMessageFile layer, not the base file.
 * It'll land in core/message/r2-constants.ts later in the refactor.
 */

// ─── AES-256-GCM ────────────────────────────────────────────────────────────

export const AES_KEY_LEN = 32; // 256-bit key
export const IV_LENGTH = 12; // 96-bit GCM nonce

// ─── ML-KEM-768 (FIPS-203) ──────────────────────────────────────────────────

export const ML_KEM_PK_LEN = 1184;
export const ML_KEM_SK_LEN = 2400;
export const ML_KEM_CT_LEN = 1088;

// ─── File size limits ───────────────────────────────────────────────────────

export const MAX_FILE_SIZE_BYTES = 100 * 1024 * 1024; // 100 MB

/**
 * Max recipients (beyond the owner) for a group .mjkb. Generic concept —
 * any encrypted group file needs a ceiling regardless of platform.
 */
export const MAX_GROUP_RECIPIENTS = 32;

// ─── .mjkb binary format ────────────────────────────────────────────────────

/**
 * v1 (legacy): [magic][version][iv][payloadLen][payload{n,m,c,...}][ciphertext]
 *   - payload.c (FileContext) was baked directly into the binary, and
 *     decrypt-time decompression was *inferred* from context + mime — a
 *     platform-specific heuristic living inside a supposedly-generic binary
 *     format. Fixed in v2.
 *
 * v2 (current): payload drops `c` entirely and gains an explicit
 *   `z: boolean` compression flag, set once at encrypt time.
 *   - decrypt no longer needs to know anything about FileContext — the
 *     binary is now genuinely self-describing and platform-agnostic.
 *   - v1 binaries remain readable via a clearly-marked legacy decode path
 *     in decodeMjkb() (see majik-file.ts).
 */
export const MJKB_VERSION = 0x02;
export const MJKB_VERSION_LEGACY = 0x01;
export const MJKB_SUPPORTED_VERSIONS = [
  MJKB_VERSION_LEGACY,
  MJKB_VERSION,
] as const;

// ─── MJKS signed trailer ────────────────────────────────────────────────────
// Layout: [.mjkb bytes][sig JSON UTF-8][uint32 BE sig length]["MJKS" magic]

export const MJKS_MAGIC = new Uint8Array([0x4d, 0x4a, 0x4b, 0x53]); // "MJKS"
export const MJKS_MAGIC_LEN = 4;
export const MJKS_OVERHEAD = 8; // 4-byte length + 4-byte magic

// ─── JSON record schema version ─────────────────────────────────────────────

/**
 * Versions the *shape* of MajikFileJSON / MajikMessageFileJSON — completely
 * independent of MJKB_VERSION, which only versions the encrypted binary
 * layout. A record and its binary can be on different version tracks
 * (e.g. a v2 binary wrapped in a schema v1 JSON row is perfectly valid).
 *
 *   0 = legacy — pre-refactor flat shape. The `schema_version` field is
 *       simply absent on these rows; absence IS the version-0 marker.
 *   1 = current split base/subclass shape (MajikFile + MajikMessageFile).
 */
export const FILE_SCHEMA_VERSION = 1;
export const LEGACY_SCHEMA_VERSION = 0;

// ─── Crypto suite metadata ───────────────────────────────────────────────────

/**
 * Self-describing crypto suite recorded on every new record so a future
 * suite change (different KEM, different AEAD) is a migratable, detectable
 * fact rather than a silent assumption baked into the code.
 *
 * Legacy records (schema_version 0) are always this suite — it's the only
 * one that ever existed prior to this refactor, so migration can stamp it
 * unconditionally.
 */
export const CRYPTO_SUITE = {
  kemAlg: "ML-KEM-768",
  cipherAlg: "AES-256-GCM",
} as const;

export type CryptoSuite = typeof CRYPTO_SUITE;
