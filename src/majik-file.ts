import {
  aesGcmEncrypt,
  aesGcmDecrypt,
  generateRandomBytes,
  mlKemEncapsulate,
  mlKemDecapsulate,
  IV_LENGTH,
  AES_KEY_LEN,
} from "./core/crypto/crypto-provider";
import {
  ML_KEM_SK_LEN,
  ML_KEM_PK_LEN,
  MAX_FILE_SIZE_BYTES,
  R2_PREFIX,
} from "./core/crypto/constants";
import {
  sha256Hex,
  sha256Base64,
  generateUUID,
  formatBytes,
  buildPermanentR2Key,
  buildTemporaryR2Key,
  buildChatImageR2Key,
  encodeMjkb,
  decodeMjkb,
  normaliseToUint8Array,
  normaliseToUint8ArrayAsync,
  isMimeTypeInlineViewable,
  inferMimeTypeFromFilename,
  deriveFilename,
  isExpired,
  buildExpiryDate,
  arrayToBase64,
  base64ToUint8Array,
  convertImageToWebP,
  shouldCompress,
  deduplicateRecipients,
  assertRecipientLimit,
} from "./core/utils";
import { MajikCompressor } from "./core/compressor/majik-compressor";
import { MajikFileError } from "./core/error";
import type {
  MajikFileJSON,
  CreateOptions,
  MajikFileIdentity,
  MajikFileRecipient,
  MajikFileGroupKey,
  MjkbSinglePayload,
  MjkbGroupPayload,
  MajikFileStats,
  FileContext,
  StorageType,
  TempFileDuration,
} from "./core/types";
import { isMjkbGroupPayload, isMjkbSinglePayload } from "./core/types";

/**
 * MajikFile
 * ----------------
 * Post-quantum binary file encryption for Majik Message.
 *
 * Mirrors MajikEnvelope's single/group encryption model, but operates on raw
 * binary blobs rather than plaintext strings.
 *
 * Single-recipient ────────────────────────────────────────────────────────
 * ----------------
 *   ML-KEM encapsulate → 32-byte sharedSecret used directly as AES-256-GCM key.
 *   Payload JSON: { mlKemCipherText }
 *
 * Group (2+ recipients) ───────────────────────────────────────────────────
 * ----------------
 *   Generate random 32-byte AES key → encrypt file once.
 *   Per recipient: ML-KEM encapsulate → encryptedAesKey = aesKey XOR sharedSecret.
 *   Payload JSON: { keys: [{ fingerprint, mlKemCipherText, encryptedAesKey }] }
 *
 * The owner is always included as the first recipient automatically.
 * Duplicate recipients are silently removed; if the deduplicated list is empty
 * after stripping the owner's own key, single-recipient mode is used.
 *
 * ─── Immutability ────────────────────────────────────────────────────────────
 *   MajikFile binaries are write-once. A file cannot be patched or replaced
 *   in place — callers must delete the existing record + R2 object and call
 *   create() again. This is enforced by the absence of any update/patch method
 *   on the encrypted fields.
 *
 * ─── Encrypt pipeline ────────────────────────────────────────────────────────
 *   raw bytes
 *     → SHA-256 hash       (for dedup, computed pre-compression)
 *     → image/webp convert (chat_image always; chat_attachment for images only)
 *     → Zstd compress      (compressible formats only; skipped for already-
 *                           compressed images JPEG/WebP/AVIF and video/audio/archives)
 *     → [single] ML-KEM encapsulate → sharedSecret = AES key
 *       [group]  random AES key; per recipient: ML-KEM encapsulate → XOR wrap
 *     → AES-256-GCM encrypt
 *     → .mjkb binary       (stored in R2)
 *
 * ─── .mjkb binary format ─────────────────────────────────────────────────────
 *   [4   magic "MJKB"]
 *   [1   version]
 *   [12  AES-GCM IV]
 *   [4   payload JSON length (big-endian uint32)]
 *   [N   payload JSON — MjkbSinglePayload | MjkbGroupPayload]
 *   [M   AES-GCM ciphertext (Zstd-compressed file + 16-byte auth tag)]
 */

export class MajikFile {
  // ── Metadata ─────────────────────────────────────────────────────────────

  private readonly _id: string;
  private readonly _userId: string;
  private _r2Key: string;
  private readonly _originalName: string | null;
  private readonly _mimeType: string | null;
  private readonly _sizeOriginal: number;
  private readonly _sizeStored: number;
  private readonly _fileHash: string;
  private readonly _encryptionIv: string; // hex, mirrors .mjkb IV for audit only
  private _storageType: StorageType;
  private _isShared: boolean;
  private _shareToken: string | null;
  private readonly _context: FileContext | null;
  private readonly _chatMessageId: string | null;
  private readonly _threadMessageId: string | null;
  private readonly _conversationId: string | null;
  private _expiresAt: string | null;
  private readonly _timestamp: string | null;
  private _lastUpdate: string | null; // mutable — updated on mutations
  private readonly _isGroup: boolean; // derived from payload type at create/parse time

  /**
   * Encrypted .mjkb binary.
   * NOT serialised to JSON / Supabase — lives in R2 storage only.
   */
  private _binary: Uint8Array | null;

  // ── Private constructor ───────────────────────────────────────────────────

  private constructor(
    json: MajikFileJSON,
    binary: Uint8Array | null,
    isGroup: boolean,
  ) {
    this._id = json.id;
    this._userId = json.user_id;
    this._r2Key = json.r2_key;
    this._originalName = json.original_name;
    this._mimeType = json.mime_type;
    this._sizeOriginal = json.size_original;
    this._sizeStored = json.size_stored;
    this._fileHash = json.file_hash;
    this._encryptionIv = json.encryption_iv;
    this._storageType = json.storage_type;
    this._isShared = json.is_shared;
    this._shareToken = json.share_token;
    this._context = json.context;
    this._chatMessageId = json.chat_message_id;
    this._threadMessageId = json.thread_message_id;
    this._conversationId = json.conversation_id;
    this._expiresAt = json.expires_at;
    this._timestamp = json.timestamp;
    this._lastUpdate = json.last_update;
    this._binary = binary;
    this._isGroup = isGroup;
  }

  // ── Getters ───────────────────────────────────────────────────────────────

  get id(): string {
    return this._id;
  }
  get userId(): string {
    return this._userId;
  }
  get r2Key(): string {
    return this._r2Key;
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
  /** Original file size in kilobytes (3 decimal places). */
  get sizeKB(): number {
    return Math.round((this._sizeOriginal / 1024) * 1000) / 1000;
  }
  /** Original file size in megabytes (3 decimal places). */
  get sizeMB(): number {
    return Math.round((this._sizeOriginal / 1024 ** 2) * 1000) / 1000;
  }
  /** Original file size in gigabytes (3 decimal places). */
  get sizeGB(): number {
    return Math.round((this._sizeOriginal / 1024 ** 3) * 1000) / 1000;
  }
  /** Original file size in terabytes (3 decimal places). */
  get sizeTB(): number {
    return Math.round((this._sizeOriginal / 1024 ** 4) * 1000) / 1000;
  }
  get encryptionIv(): string {
    return this._encryptionIv;
  }
  get storageType(): StorageType {
    return this._storageType;
  }
  get isShared(): boolean {
    return this._isShared;
  }
  get shareToken(): string | null {
    return this._shareToken;
  }
  get context(): FileContext | null {
    return this._context;
  }
  get chatMessageId(): string | null {
    return this._chatMessageId;
  }
  get threadMessageId(): string | null {
    return this._threadMessageId;
  }
  /** Conversation ID — only populated for chat_image context files. */
  get conversationId(): string | null {
    return this._conversationId;
  }
  get expiresAt(): string | null {
    return this._expiresAt;
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

  // ── CREATE ────────────────────────────────────────────────────────────────

  /**
   * Encrypt a raw binary file and produce a MajikFile instance.
   *
   * Single-recipient (no `recipients` supplied or empty array):
   *   ML-KEM encapsulate → sharedSecret → AES-256-GCM key.
   *
   * Group (one or more entries in `recipients`):
   *   Random 32-byte AES key encrypts the file once.
   *   The owner + every recipient each get their own ML-KEM key entry.
   *   encryptedAesKey = aesKey XOR sharedSecret  (safe one-time-pad).
   *
   * Steps:
   *  1. Validate inputs and enforce size limit
   *  2. Infer MIME type from filename if not provided
   *  3. Compute SHA-256 file_hash (original bytes, pre-compression)
   *  4. Zstd compress at level 22
   *  5. Encrypt (single or group path)
   *  6. Encode to .mjkb binary → store in _binary
   *  7. Build metadata + validate
   *
   * @throws MajikFileError on validation or crypto failure
   */
  static async create(options: CreateOptions): Promise<MajikFile> {
    const {
      data,
      identity,
      context,
      recipients = [],
      originalName = null,
      mimeType: rawMimeType = null,
      isTemporary = false,
      isShared = false,
      id = generateUUID(),
      bypassSizeLimit = false,
      expiresAt = 15,
      chatMessageId = null,
      threadMessageId = null,
      conversationId = null,
      userId,
    } = options;

    // ── Input validation ─────────────────────────────────────────────────

    if (!data) throw MajikFileError.invalidInput("data is required");
    if (!identity) throw MajikFileError.invalidInput("identity is required");
    if (!userId?.trim())
      throw MajikFileError.invalidInput("userId is required");
    if (!identity.fingerprint?.trim())
      throw MajikFileError.invalidInput("identity.fingerprint is required");
    if (
      !(identity.mlKemPublicKey instanceof Uint8Array) ||
      identity.mlKemPublicKey.length !== ML_KEM_PK_LEN
    ) {
      throw MajikFileError.invalidInput(
        `identity.mlKemPublicKey must be a ${ML_KEM_PK_LEN}-byte Uint8Array`,
      );
    }
    if (
      ![
        "user_upload",
        "chat_attachment",
        "chat_image",
        "thread_attachment",
      ].includes(context)
    ) {
      throw MajikFileError.invalidInput(`Invalid context: "${context}"`);
    }
    if (context === "chat_image" && !conversationId?.trim()) {
      throw MajikFileError.invalidInput(
        'conversationId is required when context is "chat_image"',
      );
    }
    if (chatMessageId && threadMessageId) {
      throw MajikFileError.invalidInput(
        "chatMessageId and threadMessageId are mutually exclusive",
      );
    }
    if (isTemporary && !expiresAt) {
      throw MajikFileError.invalidInput(
        "expiresAt is required for temporary files. Use MajikFile.buildExpiryDate() to generate one.",
      );
    }

    // Validate extra recipients' public keys
    for (let i = 0; i < recipients.length; i++) {
      const r = recipients[i];
      if (!r.fingerprint?.trim()) {
        throw MajikFileError.invalidInput(
          `recipients[${i}].fingerprint is required`,
        );
      }
      if (
        !(r.mlKemPublicKey instanceof Uint8Array) ||
        r.mlKemPublicKey.length !== ML_KEM_PK_LEN
      ) {
        throw MajikFileError.invalidInput(
          `recipients[${i}].mlKemPublicKey must be a ${ML_KEM_PK_LEN}-byte Uint8Array`,
        );
      }
    }

    const raw = normaliseToUint8Array(data);

    if (raw.byteLength === 0)
      throw MajikFileError.invalidInput("data must not be empty");
    if (!bypassSizeLimit && raw.byteLength > MAX_FILE_SIZE_BYTES) {
      throw MajikFileError.sizeExceeded(raw.byteLength, MAX_FILE_SIZE_BYTES);
    }

    // ── Infer MIME type from filename if not provided ─────────────────────
    const mimeType =
      rawMimeType ??
      (originalName ? inferMimeTypeFromFilename(originalName) : null);

    try {
      // ── 1. Hash (pre-compression, for dedup) ──────────────────────────
      // Always hash the raw original bytes — before any image conversion or
      // compression — so the hash is stable regardless of context.
      const fileHash = sha256Hex(raw);

      // ── 2. Image conversion (chat_attachment only) ────────────────────
      // For chat attachments, all browser-convertible images are re-encoded
      // to WebP (quality 0.88) before compression. This normalises delivery
      // format and reduces size for PNG/BMP sources.
      // The file_hash above already captures the *original* bytes, so dedup
      // across contexts still works correctly.
      let processedBytes = raw;
      let resolvedMimeType = mimeType;

      // chat_image: always convert (the entire context is for images)
      // chat_attachment: convert if the attached file happens to be an image
      if (
        (context === "chat_image" || context === "chat_attachment") &&
        mimeType?.startsWith("image/")
      ) {
        const result = await convertImageToWebP(raw, mimeType);
        processedBytes = result.bytes;
        resolvedMimeType = result.mimeType; // "image/webp" on success, original on fallback
      }

      // ── 3. Compress (compressible formats only) ───────────────────────
      // shouldCompress() returns false for JPEG/WebP/AVIF/video/audio/archives.
      // After the WebP conversion step above, chat images will typically be
      // WebP and therefore skipped here — WebP is already codec-compressed.
      // For user_upload and thread_attachment, compressible images (PNG, BMP,
      // TIFF, SVG, etc.) are Zstd-compressed at level 22.
      const compressible =
        context === "user_upload" || context === "thread_attachment"
          ? true
          : shouldCompress(resolvedMimeType);
      const compressed = compressible
        ? await MajikCompressor.compress(processedBytes)
        : processedBytes;

      // ── 4. IV ─────────────────────────────────────────────────────────
      const iv = generateRandomBytes(IV_LENGTH);
      const ivHex = Array.from(iv)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");

      // ── 5. Encrypt ────────────────────────────────────────────────────
      // cleanedRecipients has the owner's key removed and duplicates stripped.
      // If it is empty after cleaning, treat as single-recipient.

      const cleanedRecipients = deduplicateRecipients(
        recipients,
        identity.fingerprint,
      );
      assertRecipientLimit(cleanedRecipients);

      const isGroupFile = cleanedRecipients.length > 0;

      let ciphertext: Uint8Array;
      let payload: MjkbSinglePayload | MjkbGroupPayload;

      if (!isGroupFile) {
        // ── Single ───────────────────────────────────────────────────────
        const { sharedSecret, cipherText: mlKemCT } = mlKemEncapsulate(
          identity.mlKemPublicKey,
        );
        ciphertext = aesGcmEncrypt(sharedSecret, iv, compressed);

        payload = {
          mlKemCipherText: arrayToBase64(mlKemCT),
          n: originalName ?? null,
          m: resolvedMimeType ?? null,
          c: context ?? null,
        } satisfies MjkbSinglePayload;
      } else {
        // ── Group ─────────────────────────────────────────────────────────
        // Random group AES key encrypts the file once
        const aesKey = generateRandomBytes(AES_KEY_LEN);
        ciphertext = aesGcmEncrypt(aesKey, iv, compressed);

        // Owner is always the first key entry
        const allRecipients: MajikFileRecipient[] = [
          {
            fingerprint: identity.fingerprint,
            mlKemPublicKey: identity.mlKemPublicKey,
          },
          ...recipients,
        ];

        const keys: MajikFileGroupKey[] = allRecipients.map((r) => {
          const { sharedSecret, cipherText: mlKemCT } = mlKemEncapsulate(
            r.mlKemPublicKey,
          );
          // One-time-pad: safe because sharedSecret is 32 uniformly random bytes
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

        payload = {
          keys,
          n: originalName ?? null,
          m: resolvedMimeType ?? null,
          c: context ?? null,
        } satisfies MjkbGroupPayload;
      }

      // ── 6. Encode .mjkb ───────────────────────────────────────────────
      const mjkbBytes = encodeMjkb(iv, payload, ciphertext);

      // ── 7. R2 key ─────────────────────────────────────────────────────
      // chat_image gets its own conversation-scoped prefix, enabling efficient
      // batch-deletion when a conversation is removed (single R2 prefix scan).
      let r2Key: string;
      if (context === "chat_image") {
        r2Key = buildChatImageR2Key(conversationId!, userId, fileHash);
      } else if (isTemporary) {
        r2Key = buildTemporaryR2Key(userId, fileHash, expiresAt); // default TTL at creation time
      } else {
        r2Key = buildPermanentR2Key(userId, fileHash);
      }

      const now = new Date().toISOString();

      const json: MajikFileJSON = {
        id,
        user_id: userId,
        r2_key: r2Key,
        original_name: originalName,
        mime_type: resolvedMimeType,
        size_original: raw.byteLength,
        size_stored: mjkbBytes.byteLength,
        file_hash: fileHash,
        encryption_iv: ivHex,
        storage_type: isTemporary ? "temporary" : "permanent",
        is_shared: isShared,
        share_token: null,
        context,
        chat_message_id: chatMessageId,
        thread_message_id: threadMessageId,
        conversation_id: conversationId,
        expires_at: buildExpiryDate(expiresAt),
        timestamp: now,
        last_update: now,
      };

      const instance = new MajikFile(json, mjkbBytes, isGroupFile);
      instance._validateCreate();
      return instance;
    } catch (err) {
      if (err instanceof MajikFileError) throw err;
      throw MajikFileError.encryptionFailed(err);
    }
  }

  // ── DECRYPT (static) ──────────────────────────────────────────────────────

  /**
   * Decrypt a .mjkb Blob, Uint8Array, or ArrayBuffer.
   *
   * Single:
   *   Decapsulate → sharedSecret → AES-256-GCM key → decompress → raw bytes.
   *
   * Group:
   *   Find key entry by `identity.fingerprint` → decapsulate → XOR to recover
   *   group AES key → AES-256-GCM decrypt → decompress → raw bytes.
   *
   * Note: ML-KEM decapsulation NEVER throws on a wrong key — it returns a garbage
   * shared secret. AES-GCM authentication catches this silently (returns null).
   *
   * @throws MajikFileError on wrong key, missing key entry, corrupt data, or format errors.
   */
  static async decrypt(
    source: Blob | Uint8Array | ArrayBuffer,
    identity: Pick<MajikFileIdentity, "fingerprint" | "mlKemSecretKey">,
  ): Promise<Uint8Array> {
    if (!identity)
      throw MajikFileError.invalidInput("identity is required for decryption");
    if (
      !(identity.mlKemSecretKey instanceof Uint8Array) ||
      identity.mlKemSecretKey.length !== ML_KEM_SK_LEN
    ) {
      throw MajikFileError.invalidInput(
        `identity.mlKemSecretKey must be ${ML_KEM_SK_LEN} bytes (got ${
          (identity.mlKemSecretKey as any)?.length ?? "undefined"
        })`,
      );
    }

    try {
      const raw = await normaliseToUint8ArrayAsync(source);
      const { iv, payload, ciphertext } = decodeMjkb(raw);

      let aesKey: Uint8Array;

      if (isMjkbSinglePayload(payload)) {
        // ── Single ─────────────────────────────────────────────────────
        const mlKemCT = base64ToUint8Array(payload.mlKemCipherText);
        aesKey = mlKemDecapsulate(mlKemCT, identity.mlKemSecretKey);
      } else if (isMjkbGroupPayload(payload)) {
        // ── Group ──────────────────────────────────────────────────────
        if (!identity.fingerprint?.trim()) {
          throw MajikFileError.invalidInput(
            "identity.fingerprint is required to decrypt group files",
          );
        }
        const entry = payload.keys.find(
          (k) => k.fingerprint === identity.fingerprint,
        );
        if (!entry) {
          throw MajikFileError.decryptionFailed(
            `No key entry found for fingerprint "${identity.fingerprint}" — this identity does not have access to this file`,
          );
        }
        const mlKemCT = base64ToUint8Array(entry.mlKemCipherText);
        const sharedSecret = mlKemDecapsulate(mlKemCT, identity.mlKemSecretKey);
        const encAesKey = base64ToUint8Array(entry.encryptedAesKey);

        // Recover group AES key: aesKey = encryptedAesKey XOR sharedSecret
        aesKey = new Uint8Array(AES_KEY_LEN);
        for (let i = 0; i < AES_KEY_LEN; i++) {
          aesKey[i] = encAesKey[i] ^ sharedSecret[i];
        }
      } else {
        throw MajikFileError.formatError(
          ".mjkb payload JSON is neither a single nor group payload",
        );
      }

      const decrypted = aesGcmDecrypt(aesKey, iv, ciphertext);
      if (!decrypted) {
        throw MajikFileError.decryptionFailed(
          "Decryption failed — wrong key or corrupted .mjkb file",
        );
      }

      const compressible =
        payload.c === "user_upload" || payload.c === "thread_attachment"
          ? true
          : shouldCompress(payload.m);
      const returnData = compressible
        ? await MajikCompressor.decompress(decrypted)
        : decrypted;

      return returnData;
    } catch (err) {
      if (err instanceof MajikFileError) throw err;
      throw MajikFileError.decryptionFailed("File decryption failed", err);
    }
  }

  /**
   * Decrypt a .mjkb binary and return the raw bytes together with the
   * original filename and MIME type that were embedded in the payload at
   * encryption time.
   *
   * This is the preferred method for the File Vault UI because it avoids a
   * second parse of the binary — everything comes from the single decodeMjkb
   * call that decryption already performs.
   *
   * @returns `{ bytes, originalName, mimeType }` where `originalName` and
   *          `mimeType` may be null if the file was encrypted without metadata.
   */
  static async decryptWithMetadata(
    source: Blob | Uint8Array | ArrayBuffer,
    identity: Pick<MajikFileIdentity, "fingerprint" | "mlKemSecretKey">,
  ): Promise<{
    bytes: Uint8Array;
    originalName: string | null;
    mimeType: string | null;
  }> {
    if (!identity)
      throw MajikFileError.invalidInput("identity is required for decryption");
    if (
      !(identity.mlKemSecretKey instanceof Uint8Array) ||
      identity.mlKemSecretKey.length !== ML_KEM_SK_LEN
    ) {
      throw MajikFileError.invalidInput(
        `identity.mlKemSecretKey must be ${ML_KEM_SK_LEN} bytes (got ${
          (identity.mlKemSecretKey as any)?.length ?? "undefined"
        })`,
      );
    }

    try {
      const raw = await normaliseToUint8ArrayAsync(source);
      const { iv, payload, ciphertext } = decodeMjkb(raw);

      let aesKey: Uint8Array;

      if (isMjkbSinglePayload(payload)) {
        const mlKemCT = base64ToUint8Array(payload.mlKemCipherText);
        aesKey = mlKemDecapsulate(mlKemCT, identity.mlKemSecretKey);
      } else if (isMjkbGroupPayload(payload)) {
        if (!identity.fingerprint?.trim()) {
          throw MajikFileError.invalidInput(
            "identity.fingerprint is required to decrypt group files",
          );
        }
        const entry = payload.keys.find(
          (k) => k.fingerprint === identity.fingerprint,
        );
        if (!entry) {
          throw MajikFileError.decryptionFailed(
            `No key entry found for fingerprint "${identity.fingerprint}"`,
          );
        }
        const mlKemCT = base64ToUint8Array(entry.mlKemCipherText);
        const sharedSecret = mlKemDecapsulate(mlKemCT, identity.mlKemSecretKey);
        const encAesKey = base64ToUint8Array(entry.encryptedAesKey);
        aesKey = new Uint8Array(AES_KEY_LEN);
        for (let i = 0; i < AES_KEY_LEN; i++) {
          aesKey[i] = encAesKey[i] ^ sharedSecret[i];
        }
      } else {
        throw MajikFileError.formatError(
          ".mjkb payload JSON is neither a single nor group payload",
        );
      }

      const decrypted = aesGcmDecrypt(aesKey, iv, ciphertext);
      if (!decrypted) {
        throw MajikFileError.decryptionFailed(
          "Decryption failed — wrong key or corrupted .mjkb file",
        );
      }

      const compressible =
        payload.c === "user_upload" || payload.c === "thread_attachment"
          ? true
          : shouldCompress(payload.m);
      const bytes = compressible
        ? await MajikCompressor.decompress(decrypted)
        : decrypted;

      // Extract original filename and MIME type from the payload.
      // Written at encryption time as short keys n/m to keep the binary compact.
      // Older .mjkb files without these fields return null — callers should fall
      // back to stripping ".mjkb" from the filename and using "application/octet-stream".
      const originalName = payload.n;
      const mimeType = payload.m;

      return { bytes, originalName, mimeType };
    } catch (err) {
      if (err instanceof MajikFileError) throw err;
      throw MajikFileError.decryptionFailed("File decryption failed", err);
    }
  }

  /**
   * Decrypt the .mjkb binary already loaded on this instance.
   * Convenience wrapper around MajikFile.decrypt() — avoids re-fetching from R2.
   *
   * @throws MajikFileError if _binary is not loaded or decryption fails.
   */
  async decryptBinary(
    identity: Pick<MajikFileIdentity, "fingerprint" | "mlKemSecretKey">,
  ): Promise<Uint8Array> {
    if (!this._binary) throw MajikFileError.missingBinary();
    return MajikFile.decrypt(this._binary, identity);
  }

  // ── STORAGE TYPE MUTATION ─────────────────────────────────────────────────

  /**
   * Mutate the storage type in-place and rebuild the R2 key to match.
   *
   * This is intentionally a low-level escape hatch. Prefer the convenience
   * wrappers `setPermanent()` and `setTemporary(days?)` which enforce the
   * required invariants automatically.
   *
   * @throws MajikFileError when switching to temporary without an expiresAt,
   *         or if the instance has no userId / fileHash yet.
   */
  setStorageType(
    type: StorageType,
    expiresAt: string | null,
    duration: TempFileDuration = 15,
  ): void {
    if (!["permanent", "temporary"].includes(type)) {
      throw MajikFileError.invalidInput(
        `setStorageType: type must be "permanent" or "temporary" (got "${type}")`,
      );
    }
    if (type === "temporary" && !expiresAt) {
      throw MajikFileError.invalidInput(
        "setStorageType: expiresAt is required when switching to temporary. " +
          "Use setTemporary(days?) instead.",
      );
    }
    if (this._context === "chat_image") {
      throw MajikFileError.invalidInput(
        "setStorageType: chat_image files are conversation-scoped and cannot change storage type.",
      );
    }

    const newR2Key =
      type === "temporary"
        ? buildTemporaryR2Key(this._userId, this._fileHash, duration)
        : buildPermanentR2Key(this._userId, this._fileHash);

    this._storageType = type;
    this._expiresAt = type === "temporary" ? expiresAt : null;
    this._r2Key = newR2Key;
    this._lastUpdate = new Date().toISOString();
  }
  /**
   * Switch to permanent storage. Clears any expiry date and updates the R2 key.
   */
  setPermanent(): void {
    this.setStorageType("permanent", null);
  }

  /**
   * Switch to temporary storage with a typed TTL duration.
   * The duration determines both the R2 prefix bucket and the expiry date.
   *
   * @param duration  Days until expiry. Must be one of: 1 | 2 | 3 | 5 | 7 | 15.
   *                  Defaults to 15 to match the R2 lifecycle policy.
   */
  setTemporary(duration: TempFileDuration = 15): void {
    this.setStorageType(
      "temporary",
      MajikFile.buildExpiryDate(duration),
      duration,
    );
  }

  // ── SERIALISATION ─────────────────────────────────────────────────────────

  /**
   * Serialise metadata to a plain object matching the `majik_files` Supabase table.
   * The encrypted binary (_binary) is intentionally excluded.
   */
  toJSON(): MajikFileJSON {
    this.validate();
    return {
      id: this._id,
      user_id: this._userId,
      r2_key: this._r2Key,
      original_name: this._originalName,
      mime_type: this._mimeType,
      size_original: this._sizeOriginal,
      size_stored: this._sizeStored,
      file_hash: this._fileHash,
      encryption_iv: this._encryptionIv,
      storage_type: this._storageType,
      is_shared: this._isShared,
      share_token: this._shareToken,
      context: this._context,
      chat_message_id: this._chatMessageId,
      thread_message_id: this._threadMessageId,
      conversation_id: this._conversationId,
      expires_at: this._expiresAt,
      timestamp: this._timestamp,
      last_update: this._lastUpdate,
    };
  }

  /**
   * Restore a MajikFile from its serialised JSON representation.
   *
   * The R2 prefix check is intentionally NOT performed here — rows restored
   * from Supabase may have been written by earlier code or migrations and
   * should not be rejected at read time.
   *
   * @param json   MajikFileJSON — typically a Supabase row.
   * @param binary Optional encrypted .mjkb bytes. When provided the instance is
   *               immediately ready for toMJKB() / decryptBinary().
   */
  static fromJSON(
    json: MajikFileJSON,
    binary?: Uint8Array | ArrayBuffer | null,
  ): MajikFile {
    if (!json || typeof json !== "object") {
      throw MajikFileError.invalidInput(
        "fromJSON: json must be a non-null object",
      );
    }

    const binaryBytes = binary != null ? normaliseToUint8Array(binary) : null;

    // Derive isGroup by peeking at the binary payload if available;
    // fall back to false (single) for metadata-only restores.
    let isGroup = false;
    if (binaryBytes) {
      try {
        const { payload } = decodeMjkb(binaryBytes);
        isGroup = isMjkbGroupPayload(payload);
      } catch {
        // Binary is malformed — let validate() catch it later
      }
    }

    const instance = new MajikFile(json, binaryBytes, isGroup);
    instance.validate();
    return instance;
  }

  /**
   * Async variant of fromJSON that accepts a Blob for the binary parameter.
   */
  static async fromJSONWithBlob(
    json: MajikFileJSON,
    binary: Blob,
  ): Promise<MajikFile> {
    const bytes = new Uint8Array(await binary.arrayBuffer());
    return MajikFile.fromJSON(json, bytes);
  }

  // ── toMJKB / toBinaryBytes ────────────────────────────────────────────────

  /**
   * Export the encrypted binary as a .mjkb Blob for upload to R2.
   * @throws MajikFileError if _binary is not loaded.
   */
  toMJKB(): Blob {
    if (!this._binary) throw MajikFileError.missingBinary();
    return new Blob([this._binary as BlobPart], {
      type: "application/octet-stream",
    });
  }

  /**
   * Export the encrypted binary as a raw Uint8Array.
   * @throws MajikFileError if _binary is not loaded.
   */
  toBinaryBytes(): Uint8Array {
    if (!this._binary) throw MajikFileError.missingBinary();
    return this._binary;
  }

  // ── VALIDATE ──────────────────────────────────────────────────────────────

  /**
   * Validate all required properties against business invariants.
   * Collects ALL errors before throwing so the full list is visible at once.
   *
   * NOTE: R2 prefix structure is only checked during create(), not here.
   * This keeps fromJSON() tolerant of rows written by other services.
   *
   * @throws MajikFileError
   */
  validate(): void {
    const errors: string[] = [];

    if (!this._id?.trim()) errors.push("id is required");
    if (!this._userId?.trim()) errors.push("user_id is required");
    if (!this._r2Key?.trim()) errors.push("r2_key is required");
    if (typeof this._sizeOriginal !== "number" || this._sizeOriginal < 0) {
      errors.push("size_original must be a non-negative number");
    }
    if (typeof this._sizeStored !== "number" || this._sizeStored < 0) {
      errors.push("size_stored must be a non-negative number");
    }
    if (!this._fileHash?.trim()) errors.push("file_hash is required");
    if (!this._encryptionIv?.trim()) errors.push("encryption_iv is required");
    if (!["permanent", "temporary"].includes(this._storageType)) {
      errors.push(
        `storage_type must be "permanent" or "temporary" (got "${this._storageType}")`,
      );
    }
    if (
      this._context !== null &&
      ![
        "user_upload",
        "chat_attachment",
        "chat_image",
        "thread_attachment",
      ].includes(this._context)
    ) {
      errors.push(
        "context must be user_upload | chat_attachment | thread_attachment",
      );
    }
    if (this._chatMessageId && this._threadMessageId) {
      errors.push("chat_message_id and thread_message_id cannot both be set");
    }
    if (this._context === "chat_image" && !this._conversationId?.trim()) {
      errors.push("conversation_id is required for chat_image context");
    }
    if (this._storageType === "temporary" && !this._expiresAt) {
      errors.push("expires_at is required for temporary files");
    }

    if (errors.length > 0) throw MajikFileError.validationFailed(errors);
  }

  /**
   * Stricter validation used only during create() — includes R2 prefix checks.
   */
  private _validateCreate(): void {
    this.validate();

    const errors: string[] = [];
    const permanentPrefix = `${R2_PREFIX.PERMANENT}/${this._userId}/`;
    const temporaryPrefix = `${R2_PREFIX.TEMPORARY}/`;

    const chatImagePrefix = `${R2_PREFIX.CHAT_IMAGE}/`;

    if (this._context === "chat_image") {
      if (!this._r2Key.startsWith(chatImagePrefix)) {
        errors.push(
          `r2_key for chat_image files must start with "${chatImagePrefix}"`,
        );
      }
    } else if (
      this._storageType === "permanent" &&
      !this._r2Key.startsWith(permanentPrefix)
    ) {
      errors.push(
        `r2_key for permanent files must start with "${permanentPrefix}"`,
      );
    } else if (
      this._storageType === "temporary" &&
      !this._r2Key.startsWith(temporaryPrefix)
    ) {
      errors.push(
        `r2_key for temporary files must start with "${temporaryPrefix}"`,
      );
    }

    if (errors.length > 0) throw MajikFileError.validationFailed(errors);
  }

  // ── OWNERSHIP ─────────────────────────────────────────────────────────────

  /** Returns true if the given userId matches the file's owner. */
  userIsOwner(userId: string): boolean {
    if (!userId?.trim()) return false;
    return this._userId === userId;
  }

  // ── BINARY MANAGEMENT ─────────────────────────────────────────────────────

  /**
   * Attach (or replace) the encrypted .mjkb binary on this instance.
   * Also updates the isGroup flag by peeking at the payload type.
   */
  attachBinary(binary: Uint8Array | ArrayBuffer): void {
    this._binary = normaliseToUint8Array(binary);
  }

  /**
   * Clear the in-memory binary to free memory after an upload completes.
   */
  clearBinary(): void {
    this._binary = null;
  }

  // ── SHARING ───────────────────────────────────────────────────────────────

  /** Returns true if this file has an active share token. */
  get hasShareToken(): boolean {
    return this._shareToken !== null && this._shareToken.length > 0;
  }

  /**
   * Toggle the shareable state of this file.
   *
   * - If currently NOT shared → sets isShared = true, assigns token (auto-generated if omitted).
   * - If currently shared     → sets isShared = false, clears token.
   *
   * Updates last_update automatically. Call toJSON() to persist the change.
   *
   * @param token  Optional explicit token. Ignored when toggling OFF.
   * @returns      The active share token, or null if sharing was disabled.
   */
  toggleSharing(token?: string): string | null {
    if (this._isShared) {
      this._isShared = false;
      this._shareToken = null;
      this._lastUpdate = new Date().toISOString();
      return null;
    } else {
      if (token !== undefined && !token.trim()) {
        throw MajikFileError.invalidInput(
          "toggleSharing: token must be a non-empty string when provided",
        );
      }
      this._isShared = true;
      this._shareToken = token?.trim() ?? generateUUID();
      this._lastUpdate = new Date().toISOString();
      return this._shareToken;
    }
  }

  // ── EXPIRY ────────────────────────────────────────────────────────────────

  /** Returns true if this file has passed its expiry date. */
  get isExpired(): boolean {
    return isExpired(this._expiresAt);
  }

  /** Returns true if this file uses temporary storage. */
  get isTemporary(): boolean {
    return this._storageType === "temporary";
  }

  // ── MIME / FORMAT HELPERS ─────────────────────────────────────────────────

  /** Returns true if the MIME type can be rendered inline in a browser. */
  get isInlineViewable(): boolean {
    return isMimeTypeInlineViewable(this._mimeType);
  }

  /** Safe download filename derived from the hash + original extension. */
  get safeFilename(): string {
    return deriveFilename(this._fileHash, this._originalName);
  }

  // ── SIZE CHECK ────────────────────────────────────────────────────────────

  /**
   * Returns true if the original file size exceeds the given limit.
   * @param limitMB  Limit in megabytes (must be positive and finite).
   * @throws MajikFileError on invalid input.
   */
  exceedsSize(limitMB: number): boolean {
    if (typeof limitMB !== "number" || limitMB <= 0 || !isFinite(limitMB)) {
      throw MajikFileError.invalidInput(
        `exceedsSize: limitMB must be a positive finite number (got ${limitMB})`,
      );
    }
    return this._sizeOriginal > limitMB * 1024 * 1024;
  }

  // ── ACCESS CHECK ──────────────────────────────────────────────────────────

  /**
   * Lightweight fingerprint check — returns true if the given public key
   * hashes (SHA-256 base64) to the supplied ownerFingerprint.
   *
   * This does NOT attempt decryption. For cryptographic proof use decrypt().
   *
   * @param publicKey         ML-KEM-768 public key (1184 bytes).
   * @param ownerFingerprint  Base64 SHA-256 fingerprint of the authorised key.
   */
  static hasPublicKeyAccess(
    publicKey: Uint8Array,
    ownerFingerprint: string,
  ): boolean {
    if (
      !(publicKey instanceof Uint8Array) ||
      publicKey.length !== ML_KEM_PK_LEN
    ) {
      throw MajikFileError.invalidInput(
        `hasPublicKeyAccess: publicKey must be a ${ML_KEM_PK_LEN}-byte Uint8Array (got ${
          (publicKey as any)?.length ?? typeof publicKey
        })`,
      );
    }
    if (!ownerFingerprint?.trim()) {
      throw MajikFileError.invalidInput(
        "hasPublicKeyAccess: ownerFingerprint is required",
      );
    }
    return sha256Base64(publicKey) === ownerFingerprint;
  }

  // ── STATS ─────────────────────────────────────────────────────────────────

  /** Return a human-readable stats snapshot for display in a file manager UI. */
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
      storageType: this._storageType,
      isGroup: this._isGroup,
      context: this._context,
      isShared: this._isShared,
      isExpired: this.isExpired,
      expiresAt: this._expiresAt,
      timestamp: this._timestamp,
      r2Key: this._r2Key,
    };
  }

  // ── DUPLICATE DETECTION ───────────────────────────────────────────────────

  /**
   * Returns true if this file has the same plaintext content as another
   * MajikFile (comparison by SHA-256 file_hash of original bytes).
   */
  isDuplicateOf(other: MajikFile): boolean {
    return this._fileHash === other._fileHash;
  }

  /**
   * Synchronous check — returns true if raw bytes would produce a duplicate.
   * Use this to short-circuit the encrypt + upload flow.
   */
  static wouldBeDuplicate(rawBytes: Uint8Array, existingHash: string): boolean {
    return sha256Hex(rawBytes) === existingHash;
  }

  // ── STATIC HELPERS ────────────────────────────────────────────────────────

  /**
   * Quick magic-byte check. Does NOT fully parse — use before attempting decryption.
   */
  static isMjkbCandidate(data: Uint8Array | ArrayBuffer): boolean {
    const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
    if (bytes.length < 5) return false;
    return (
      bytes[0] === 0x4d && // M
      bytes[1] === 0x4a && // J
      bytes[2] === 0x4b && // K
      bytes[3] === 0x42 // B
    );
  }

  /**
   * Build a default ISO-8601 expiry date for temporary files.
   * @param days Days from now. Defaults to 15 (R2 lifecycle policy).
   */
  static buildExpiryDate(days: TempFileDuration = 15): string {
    return buildExpiryDate(days);
  }

  /** Format bytes as a human-readable string (e.g. "4.2 MB"). */
  static formatBytes(bytes: number): string {
    return formatBytes(bytes);
  }

  /**
   * Infer a MIME type from a filename extension.
   * Exposed here for convenience — delegates to core/utils.
   */
  static inferMimeType(filename: string): string | null {
    return inferMimeTypeFromFilename(filename);
  }

  // ── toString ──────────────────────────────────────────────────────────────

  toString(): string {
    return (
      `MajikFile { ` +
      `id: ${this._id}, ` +
      `hash: ${this._fileHash.slice(0, 8)}…, ` +
      `size: ${formatBytes(this._sizeOriginal)}, ` +
      `type: ${this._isGroup ? "group" : "single"}, ` +
      `storage: ${this._storageType}` +
      ` }`
    );
  }
}
