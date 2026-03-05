// ─── Domain Types ─────────────────────────────────────────────────────────────

export type FileContext =
  | "user_upload"
  | "chat_attachment"
  | "chat_image" // rasterised WebP image sent in a chat conversation
  | "thread_attachment";

export type StorageType = "permanent" | "temporary";

// ─── Identities & Recipients ──────────────────────────────────────────────────

/**
 * The file owner's full identity.
 * Carries both keys — public for encryption, secret for decryption.
 */
export interface MajikFileIdentity {
  /** UUID from auth.users — used for R2 key construction and ownership checks. */
  userId: string;
  /** Base64 SHA-256 of the ML-KEM public key — used to look up key entries. */
  fingerprint: string;
  /** ML-KEM-768 public key (1184 bytes) — used during encryption. */
  mlKemPublicKey: Uint8Array;
  /** ML-KEM-768 secret key (2400 bytes) — used during decryption. */
  mlKemSecretKey: Uint8Array;
}

/**
 * A recipient who can decrypt the file.
 * Carries only the public key — the secret key never leaves the recipient's device.
 *
 * In a single-recipient file, this is typically the owner themselves.
 * In a group file (e.g. a shared chat attachment), this is every participant
 * who should be able to download and decrypt the file.
 */
export interface MajikFileRecipient {
  /** Base64 SHA-256 of the ML-KEM public key — used to locate the key entry on decrypt. */
  fingerprint: string;
  /** ML-KEM-768 public key (1184 bytes). */
  mlKemPublicKey: Uint8Array;
}

// ─── Per-recipient key entry (group .mjkb) ────────────────────────────────────

/**
 * Per-recipient encrypted key entry stored inside a group .mjkb binary.
 * Mirrors MajikEnvelope's GroupKey but for file payloads.
 *
 * encryptedAesKey = groupAesKey XOR mlKemSharedSecret  (32-byte XOR one-time-pad)
 */
export interface MajikFileGroupKey {
  /** Base64 SHA-256 fingerprint — identifies which recipient this entry belongs to. */
  fingerprint: string;
  /** Base64-encoded ML-KEM-768 ciphertext (1088 bytes) for this recipient. */
  mlKemCipherText: string;
  /** Base64-encoded 32-byte encrypted AES key (groupAesKey XOR sharedSecret). */
  encryptedAesKey: string;
}

// ─── .mjkb Payload Types ─────────────────────────────────────────────────────

/**
 * JSON payload embedded in a single-recipient .mjkb binary.
 * The ML-KEM shared secret is used directly as the AES-256-GCM key.
 */
export interface MjkbSinglePayload {
  /** Base64-encoded ML-KEM-768 ciphertext (1088 bytes). */
  mlKemCipherText: string;
  /** Original filename (e.g. "photo.png"). Short key keeps the binary compact. */
  n?: string | null;
  /** Original MIME type (e.g. "image/png"). Short key keeps the binary compact. */
  m?: string | null;
}

/**
 * JSON payload embedded in a group .mjkb binary.
 * The file is encrypted once with a random AES key; each recipient gets their
 * own ML-KEM encapsulation of that AES key.
 */
export interface MjkbGroupPayload {
  /** Per-recipient key entries. */
  keys: MajikFileGroupKey[];
  /** Original filename (e.g. "photo.png"). Short key keeps the binary compact. */
  n?: string | null;
  /** Original MIME type (e.g. "image/png"). Short key keeps the binary compact. */
  m?: string | null;
}

export type MjkbPayload = MjkbSinglePayload | MjkbGroupPayload;

export function isMjkbGroupPayload(p: MjkbPayload): p is MjkbGroupPayload {
  return "keys" in p && Array.isArray((p as MjkbGroupPayload).keys);
}

export function isMjkbSinglePayload(p: MjkbPayload): p is MjkbSinglePayload {
  return "mlKemCipherText" in p && !("keys" in p);
}

// ─── MajikFileJSON ────────────────────────────────────────────────────────────

/**
 * Serialised representation of a MajikFile.
 * Maps 1-to-1 with the `majikah.majik_files` Supabase table.
 *
 * NOTE: The encrypted binary (_binary) is intentionally excluded — it lives
 * in R2 storage, not in Supabase.
 *
 * NOTE: encryption_iv is stored here as a hex string matching Supabase's `bytea`
 * column. The IV is also embedded in the .mjkb binary header, so decryption
 * uses the binary — this column exists for audit / key-rotation purposes.
 */
export interface MajikFileJSON {
  /** UUID primary key — matches gen_random_uuid() from Supabase. */
  id: string;
  /** auth.users UUID of the file owner. */
  user_id: string;
  /** R2 object key — unique path within the bucket. */
  r2_key: string;
  /** Original filename supplied by the uploader (e.g. "resume.pdf"). */
  original_name: string | null;
  /** MIME type (e.g. "application/pdf", "image/png"). */
  mime_type: string | null;
  /** Byte length of the raw plaintext file before compression or encryption. */
  size_original: number;
  /** Byte length of the final encrypted .mjkb binary stored in R2. */
  size_stored: number;
  /**
   * SHA-256 hex digest of the original raw bytes (pre-compression).
   * Used for duplicate detection across the user's files.
   */
  file_hash: string;
  /**
   * Hex-encoded 12-byte AES-GCM IV, matching Supabase `bytea` storage.
   * This is a secondary record for audit/key-rotation; decryption reads the
   * IV from the .mjkb binary header where it is authoritative.
   */
  encryption_iv: string;
  /** Whether this file is permanently retained or auto-deleted after expiry. */
  storage_type: StorageType;
  /** Whether the file can be shared via share_token. */
  is_shared: boolean;
  /** Opaque token for shareable public links. */
  share_token: string | null;
  /** Usage context — determines downstream UX and access control. */
  context: FileContext | null;
  /** Foreign key → majik_message_chat.id (mutually exclusive with thread_message_id). */
  chat_message_id: string | null;
  /** Foreign key → majik_message_thread.id (mutually exclusive with chat_message_id). */
  thread_message_id: string | null;
  /**
   * Conversation (channel / DM) ID.
   * Required when context is "chat_image" — used to scope the R2 key:
   *   images/chats/<conversationId>/<userId>_<fileHash>.mjkb
   * Null for all other contexts.
   */
  conversation_id: string | null;
  /** ISO-8601 expiry timestamp. Required for temporary files. */
  expires_at: string | null;
  /** ISO-8601 creation timestamp. */
  timestamp: string | null;
  /** ISO-8601 last-update timestamp. Updated on any mutation (e.g. toggleSharing). */
  last_update: string | null;
}

// ─── CreateOptions ────────────────────────────────────────────────────────────

export interface CreateOptions {
  /** Raw binary content of the file to encrypt. */
  data: Uint8Array | ArrayBuffer;
  /**
   * Identity of the file owner.
   * For single-recipient files, this is the only recipient (self-encryption).
   * For group files, this is the sender — additional recipients are supplied
   * via the `recipients` array.
   */
  identity: MajikFileIdentity;
  /**
   * Additional recipients beyond the owner.
   * When provided (length ≥ 1), a group .mjkb is produced: the file is
   * encrypted once with a random AES key and each recipient (including the
   * owner, automatically prepended) gets their own ML-KEM key entry.
   * When omitted or empty, a single-recipient .mjkb is produced.
   */
  recipients?: MajikFileRecipient[];
  /** File context — affects storage routing and downstream UX. */
  context: FileContext;
  /** Original filename (e.g. "photo.jpg"). Optional but recommended. */
  originalName?: string;
  /** MIME type string (e.g. "image/jpeg"). Optional. */
  mimeType?: string;
  /**
   * If true, the file is stored under files/public/ and auto-deleted
   * by the bucket lifecycle policy after ~15 days.
   * Requires expiresAt to be set.
   * @default false
   */
  isTemporary?: boolean;
  /**
   * If true, a share_token can be generated to allow public access.
   * @default false
   */
  isShared?: boolean;
  /**
   * Pre-computed UUID for the record. If omitted, a new UUID is generated.
   */
  id?: string;
  /**
   * Bypass the MAX_FILE_SIZE_BYTES (100 MB) limit.
   * @default false
   */
  bypassSizeLimit?: boolean;
  /**
   * ISO-8601 expiry datetime. Required when isTemporary = true.
   */
  expiresAt?: string;
  /** Associate this file with a chat message (mutually exclusive with threadMessageId). */
  chatMessageId?: string;
  /** Associate this file with a thread message (mutually exclusive with chatMessageId). */
  threadMessageId?: string;
  /**
   * Conversation (channel / DM) ID.
   * Required when context is "chat_image".
   * Determines the R2 key prefix: images/chats/<conversationId>/
   */
  conversationId?: string;
}

// ─── Decoded .mjkb Binary ─────────────────────────────────────────────────────

/**
 * Internal representation of a fully parsed .mjkb binary.
 * The payload JSON (single or group) is embedded after the IV.
 */
export interface DecodedMjkb {
  version: number;
  /** IV extracted from the binary header — authoritative source for decryption. */
  iv: Uint8Array;
  /** AES-GCM ciphertext (Zstd-compressed plaintext + 16-byte auth tag). */
  ciphertext: Uint8Array;
  /** Parsed payload — discriminate with isMjkbGroupPayload / isMjkbSinglePayload. */
  payload: MjkbPayload;
}

// ─── File Stats ───────────────────────────────────────────────────────────────

/**
 * Human-readable stats returned by MajikFile.getStats().
 */
export interface MajikFileStats {
  id: string;
  originalName: string | null;
  mimeType: string | null;
  /** Human-readable original size (e.g. "4.2 MB") */
  sizeOriginalHuman: string;
  /** Human-readable stored size (e.g. "1.1 MB") */
  sizeStoredHuman: string;
  /** Compression ratio as a percentage reduction (e.g. 73.4). Clamped to 0 minimum. */
  compressionRatioPct: number;
  fileHash: string;
  storageType: StorageType;
  isGroup: boolean;
  context: FileContext | null;
  isShared: boolean;
  isExpired: boolean;
  expiresAt: string | null;
  timestamp: string | null;
  r2Key: string;
}
