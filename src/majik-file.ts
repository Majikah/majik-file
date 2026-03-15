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
  MJKB_VERSION,
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
  MajikMessagePublicKey,
  FileSignature,
} from "./core/types";
import { isMjkbGroupPayload, isMjkbSinglePayload } from "./core/types";
import {
  MajikSignature,
  type MajikSignerPublicKeys,
  type VerificationResult,
} from "@majikah/majik-signature";
import { MajikKey } from "@majikah/majik-key";

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
  private _chatMessageId: string | null;
  private _threadMessageId: string | null;
  private _threadId: string | null;
  private _conversationId: string | null;
  private _participants: MajikMessagePublicKey[];
  private _expiresAt: string | null;
  private readonly _timestamp: string | null;
  private _lastUpdate: string | null; // mutable — updated on mutations
  private readonly _isGroup: boolean; // derived from payload type at create/parse time

  private _signature: string | null;

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
    this._threadId = json.thread_id;
    this._conversationId = json.conversation_id;
    this._participants = json.participants;
    this._expiresAt = json.expires_at;
    this._timestamp = json.timestamp;
    this._lastUpdate = json.last_update;
    this._binary = binary;
    this._isGroup = isGroup;
    this._signature = json.signature;
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
  get threadId(): string | null {
    return this._threadId;
  }
  get participants(): MajikMessagePublicKey[] {
    return this._participants;
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

  // ── SIGNATURE ─────────────────────────────────────────────────────────────

  /**
   * Serialized base64 signature string (MajikSignature.serialize() output).
   * Stored in Supabase as a plain text column. Null when unsigned.
   */
  get signatureRaw(): string | null {
    return this._signature;
  }

  /**
   * Deserialize and return the attached MajikSignature instance.
   * Returns null if no signature is attached or the stored value is malformed.
   * Deserializes on every access — avoid calling in tight loops.
   */
  get signature(): MajikSignature | null {
    if (!this._signature?.trim()) return null;
    try {
      return MajikSignature.deserialize(this._signature);
    } catch {
      return null;
    }
  }

  /**
   * Returns true if a structurally valid signature is attached.
   * Does NOT cryptographically verify — call verify() for that.
   */
  get isSigned(): boolean {
    return this._signature?.trim() ? true : false;
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
      threadId = null,
      conversationId = null,
      userId,
      compressionLevel,
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
        ? await MajikCompressor.compress(processedBytes, compressionLevel)
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

      // Owner is always the first key entry
      const allRecipients: MajikFileRecipient[] = [
        {
          fingerprint: identity.fingerprint,
          mlKemPublicKey: identity.mlKemPublicKey,
          publicKey: identity.publicKey,
        },
        ...cleanedRecipients,
      ];

      const participantPubKeys = allRecipients.map(
        (recipient) => recipient.publicKey,
      );

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
        thread_id: threadId,
        conversation_id: conversationId,
        expires_at: buildExpiryDate(expiresAt),
        timestamp: now,
        last_update: now,
        participants: participantPubKeys,
        signature: null,
      };

      const instance = new MajikFile(json, mjkbBytes, isGroupFile);
      instance._validateCreate();
      return instance;
    } catch (err) {
      if (err instanceof MajikFileError) throw err;
      throw MajikFileError.encryptionFailed(err);
    }
  }

  // ── CREATE AND SIGN ───────────────────────────────────────────────────────

  /**
   * Encrypt a raw binary file, sign the resulting .mjkb binary, and return
   * the MajikFile instance with the signature already attached.
   *
   * This is a convenience wrapper around create() + sign() for the common
   * case where the file owner wants to sign immediately after encryption.
   *
   * The signature covers the encrypted .mjkb binary bytes — not the
   * plaintext — so verification can be performed by any party holding the
   * signer's public keys without requiring decryption. See sign() for the
   * full rationale.
   *
   * Typical usage:
   *   const file = await MajikFile.createAndSign(options, key);
   *   await r2.put(file.r2Key, file.toMJKB());
   *   await supabase.from("majik_files").insert(file.toJSON());
   *   // toJSON() includes the serialized signature — one round-trip to Supabase.
   *
   * @param options  Same CreateOptions accepted by create().
   * @param key      Unlocked MajikKey with signing keys (Ed25519 + ML-DSA-87).
   * @param signOptions  Optional content type label and timestamp override.
   * @returns        MajikFile instance with _signature populated and _binary loaded.
   * @throws MajikFileError on any encryption or validation failure.
   * @throws MajikSignatureKeyError if the key is locked or missing signing keys.
   */
  static async createAndSign(
    options: CreateOptions,
    key: MajikKey,
    signOptions?: { contentType?: string; timestamp?: string },
  ): Promise<MajikFile> {
    const file = await MajikFile.create(options);
    // _binary is guaranteed non-null here — create() always populates it
    // and the instance was just constructed, so clearBinary() hasn't run.
    await file.sign(key, signOptions);
    return file;
  }

  // ── QUICK-CREATE WRAPPERS ─────────────────────────────────────────────────

  /**
   * Create a chat image file.
   * Validates that the file is an image and does not exceed 25 MB (original bytes).
   */
  static async createChatImage(options: {
    data: Uint8Array | ArrayBuffer;
    userId: string;
    identity: MajikFileIdentity;
    conversationId: string;
    mimeType: string;
    originalName?: string;
    recipients?: MajikFileRecipient[];
    chatMessageId?: string;
  }): Promise<MajikFile> {
    const raw =
      options.data instanceof Uint8Array
        ? options.data
        : new Uint8Array(options.data);

    if (!options.mimeType?.startsWith("image/")) {
      throw MajikFileError.invalidInput(
        `createChatImage: mimeType must be an image/* type (got "${options.mimeType}")`,
      );
    }
    const CHAT_IMAGE_MAX = 25 * 1024 * 1024; // 25 MB
    if (raw.byteLength > CHAT_IMAGE_MAX) {
      throw MajikFileError.sizeExceeded(raw.byteLength, CHAT_IMAGE_MAX);
    }

    return MajikFile.create({
      data: raw,
      userId: options.userId,
      identity: options.identity,
      context: "chat_image",
      conversationId: options.conversationId,
      mimeType: options.mimeType,
      originalName: options.originalName,
      recipients: options.recipients ?? [],
      chatMessageId: options.chatMessageId,
      isTemporary: false,
    });
  }

  /**
   * Create a chat attachment file.
   */
  static async createChatAttachment(options: {
    data: Uint8Array | ArrayBuffer;
    userId: string;
    identity: MajikFileIdentity;
    chatMessageId: string;
    originalName?: string;
    mimeType?: string;
    recipients?: MajikFileRecipient[];
  }): Promise<MajikFile> {
    return MajikFile.create({
      data: options.data,
      userId: options.userId,
      identity: options.identity,
      context: "chat_attachment",
      chatMessageId: options.chatMessageId,
      originalName: options.originalName,
      mimeType: options.mimeType,
      recipients: options.recipients ?? [],
      isTemporary: false,
    });
  }

  /**
   * Create a thread attachment file.
   */
  static async createThreadAttachment(options: {
    data: Uint8Array | ArrayBuffer;
    userId: string;
    identity: MajikFileIdentity;
    threadId: string;
    threadMessageId?: string;
    originalName?: string;
    mimeType?: string;
    recipients?: MajikFileRecipient[];
  }): Promise<MajikFile> {
    return MajikFile.create({
      data: options.data,
      userId: options.userId,
      identity: options.identity,
      context: "thread_attachment",
      threadId: options.threadId,
      threadMessageId: options.threadMessageId,
      originalName: options.originalName,
      mimeType: options.mimeType,
      recipients: options.recipients ?? [],
      isTemporary: false,
    });
  }

  /**
   * Create a permanent user upload.
   */
  static async createUserUpload(options: {
    data: Uint8Array | ArrayBuffer;
    userId: string;
    identity: MajikFileIdentity;
    originalName?: string;
    mimeType?: string;
    isShared?: boolean;
    recipients?: MajikFileRecipient[];
  }): Promise<MajikFile> {
    return MajikFile.create({
      data: options.data,
      userId: options.userId,
      identity: options.identity,
      context: "user_upload",
      originalName: options.originalName,
      mimeType: options.mimeType,
      isShared: options.isShared ?? false,
      recipients: options.recipients ?? [],
      isTemporary: false,
    });
  }

  /**
   * Create a temporary user upload with a typed TTL.
   * @param duration  Days until expiry. Defaults to 15.
   */
  static async createTemporaryUpload(options: {
    data: Uint8Array | ArrayBuffer;
    userId: string;
    identity: MajikFileIdentity;
    originalName?: string;
    mimeType?: string;
    duration?: TempFileDuration;
    recipients?: MajikFileRecipient[];
  }): Promise<MajikFile> {
    const duration = options.duration ?? 15;
    return MajikFile.create({
      data: options.data,
      userId: options.userId,
      identity: options.identity,
      context: "user_upload",
      originalName: options.originalName,
      mimeType: options.mimeType,
      recipients: options.recipients ?? [],
      isTemporary: true,
      expiresAt: duration,
    });
  }

  // ── PARTICIPANT ACCESS CHECKS ─────────────────────────────────────────────

  /**
   * Returns true if the given public key string is in the participants list
   * for this file. O(n) scan — participants lists are small in practice.
   *
   * Note: participants contains the *recipients'* public keys. The owner's
   * key is NOT included (the owner encrypts to themselves via identity, not
   * via the recipients array). To check owner access use `userIsOwner()`.
   */
  hasParticipantAccess(publicKey: MajikMessagePublicKey): boolean {
    if (!publicKey?.trim()) return false;
    return this._participants.includes(publicKey);
  }

  /**
   * Bind this file to a thread mail after initial creation.
   * Can only be called once — throws if either ID is already set.
   * Call toJSON() and persist to Supabase after binding.
   */
  bindToThreadMail(threadId: string, threadMessageId: string): void {
    if (this._context !== "thread_attachment") {
      throw MajikFileError.invalidInput(
        "bindToThreadMail: only thread_attachment files can be bound to a mail",
      );
    }
    if (this._threadId || this._threadMessageId) {
      throw MajikFileError.invalidInput(
        "bindToThreadMail: this file is already bound to a thread mail — " +
          "IDs are immutable once set",
      );
    }
    if (!threadId?.trim()) {
      throw MajikFileError.invalidInput(
        "bindToThreadMail: threadId is required",
      );
    }
    if (!threadMessageId?.trim()) {
      throw MajikFileError.invalidInput(
        "bindToThreadMail: threadMessageId is required",
      );
    }
    this._threadId = threadId;
    this._threadMessageId = threadMessageId;
    this._lastUpdate = new Date().toISOString();
  }

  /**
   * Bind this file to a chat conversation after initial creation.
   * Can only be called once — throws if either ID is already set.
   * Call toJSON() and persist to Supabase after binding.
   */
  bindToChatConversation(conversationID: string, chatMessageID: string): void {
    if (this._context !== "chat_attachment") {
      throw MajikFileError.invalidInput(
        "bindToChatConversation: only chat_attachment files can be bound to a mail",
      );
    }
    if (this._chatMessageId || this._conversationId) {
      throw MajikFileError.invalidInput(
        "bindToChatConversation: this file is already bound to a chat conversation — " +
          "IDs are immutable once set",
      );
    }
    if (!conversationID?.trim()) {
      throw MajikFileError.invalidInput(
        "bindToChatConversation: conversationID is required",
      );
    }
    if (!chatMessageID?.trim()) {
      throw MajikFileError.invalidInput(
        "bindToChatConversation: chatMessageID is required",
      );
    }
    this._conversationId = conversationID;
    this._chatMessageId = chatMessageID;
    this._lastUpdate = new Date().toISOString();
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
   * original filename, MIME type, and any attached signature that was
   * embedded in the Supabase record at encryption time.
   *
   * Signature handling:
   *   - If a signature string is provided via `signatureRaw`, it is
   *     deserialized and returned as `signature` for the caller to verify.
   *   - If no signature is present, `signature` is null — the rest of the
   *     return shape is unchanged so existing call sites need no updates.
   *   - This method does NOT verify the signature. To verify, pass the
   *     returned signature to file.verify() or MajikSignature.verify().
   *
   * This is the preferred method for the File Vault UI because it avoids a
   * second parse of the binary — everything comes from the single decodeMjkb
   * call that decryption already performs.
   *
   * @returns `{ bytes, originalName, mimeType, signature }` where
   *          `originalName`, `mimeType`, and `signature` may be null.
   */
  static async decryptWithMetadata(
    source: Blob | Uint8Array | ArrayBuffer,
    identity: Pick<MajikFileIdentity, "fingerprint" | "mlKemSecretKey">,
    signatureRaw?: string | null,
  ): Promise<{
    bytes: Uint8Array;
    originalName: string | null;
    mimeType: string | null;
    signature: MajikSignature | null;
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

      const originalName = payload.n;
      const mimeType = payload.m;

      // ── Signature ─────────────────────────────────────────────────────────
      // Deserialize if a raw signature string was provided. Malformed values
      // are silently swallowed — the caller receives null and can decide
      // whether to treat that as an error based on their own policy.
      let signature: MajikSignature | null = null;
      if (signatureRaw?.trim()) {
        try {
          signature = MajikSignature.deserialize(signatureRaw);
        } catch {
          signature = null;
        }
      }

      return { bytes, originalName, mimeType, signature };
    } catch (err) {
      if (err instanceof MajikFileError) throw err;
      throw MajikFileError.decryptionFailed("File decryption failed", err);
    }
  }

  // Fix 1 — instance wrapper for decryptWithMetadata
  // Add alongside decryptBinary() in the DECRYPT section

  /**
   * Instance wrapper around MajikFile.decryptWithMetadata() that automatically
   * passes the attached signature for deserialization.
   * Convenience method — avoids manually threading signatureRaw at call sites.
   *
   * @throws MajikFileError if _binary is not loaded or decryption fails.
   */
  async decryptWithMetadata(
    identity: Pick<MajikFileIdentity, "fingerprint" | "mlKemSecretKey">,
  ): Promise<{
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
      thread_id: this._threadId,
      participants: this._participants,
      conversation_id: this._conversationId,
      expires_at: this._expiresAt,
      timestamp: this._timestamp,
      last_update: this._lastUpdate,
      signature: this._signature ?? null,
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
      isSigned: this.isSigned,
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
      `storage: ${this._storageType}, ` +
      `signed: ${this.isSigned}` +
      ` }`
    );
  }

  /**
   * Fully validate a .mjkb binary beyond the quick magic-byte check.
   *
   * Checks performed (in order):
   *  1. Minimum byte length for a complete fixed header (21 bytes)
   *  2. Magic bytes "MJKB" at offset 0
   *  3. Version byte matches MJKB_VERSION (0x01)
   *  4. Payload JSON length field is positive and not larger than remaining data
   *  5. Payload JSON is valid UTF-8 and parses without error
   *  6. Parsed payload is either a MjkbSinglePayload or MjkbGroupPayload shape
   *  7. Ciphertext section is non-empty (at least 1 byte after the payload)
   *
   * Unlike isMjkbCandidate(), this method parses the full header. It does NOT
   * attempt decryption — use decrypt() for cryptographic verification.
   *
   * @param data  Raw bytes to inspect. Accepts Uint8Array or ArrayBuffer.
   * @returns     true if the binary is structurally valid; false otherwise.
   */
  static isValidMJKB(data: Uint8Array | ArrayBuffer): boolean {
    try {
      const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);

      // 1. Minimum size: 4 magic + 1 version + 12 IV + 4 payload-len = 21 bytes,
      //    plus at least 1 byte of payload JSON and 1 byte of ciphertext.
      if (bytes.length < 23) return false;

      // 2. Magic bytes
      if (
        bytes[0] !== 0x4d || // M
        bytes[1] !== 0x4a || // J
        bytes[2] !== 0x4b || // K
        bytes[3] !== 0x42 // B
      )
        return false;

      // 3. Version
      if (bytes[4] !== MJKB_VERSION) return false;

      // Skip IV (bytes 5–16) — we don't validate randomness, only structure.
      const payloadLenOffset = 17; // 4 magic + 1 version + 12 IV

      // 4. Payload JSON length (big-endian uint32)
      const payloadLen =
        (bytes[payloadLenOffset] << 24) |
        (bytes[payloadLenOffset + 1] << 16) |
        (bytes[payloadLenOffset + 2] << 8) |
        bytes[payloadLenOffset + 3];

      if (payloadLen <= 0) return false;

      const payloadStart = payloadLenOffset + 4; // 21
      const ciphertextStart = payloadStart + payloadLen;

      // Ensure the declared payload fits and leaves at least 1 byte for ciphertext
      if (ciphertextStart >= bytes.length) return false;

      // 5. Payload JSON must parse
      let payload: unknown;
      try {
        payload = JSON.parse(
          new TextDecoder().decode(bytes.slice(payloadStart, ciphertextStart)),
        );
      } catch {
        return false;
      }

      if (!payload || typeof payload !== "object") return false;

      // 6. Must be a recognisable single or group payload shape
      const isSingle =
        "mlKemCipherText" in (payload as object) &&
        !("keys" in (payload as object));
      const isGroup =
        "keys" in (payload as object) &&
        Array.isArray((payload as { keys: unknown }).keys) &&
        (payload as { keys: unknown[] }).keys.length > 0;

      if (!isSingle && !isGroup) return false;

      // 7. Ciphertext section must be non-empty
      if (bytes.length <= ciphertextStart) return false;

      return true;
    } catch {
      // Any unexpected error → not a valid .mjkb
      return false;
    }
  }

  /**
   * Return the raw plaintext byte size of a Uint8Array or ArrayBuffer.
   *
   * This is a cheap O(1) helper — it reads `.byteLength` without copying.
   * Use it to inspect file size before calling create() or to feed into
   * `MajikCompressor.adaptiveLevel()` for manual level selection.
   *
   * @param data  Raw bytes — typically the plaintext before encryption.
   * @returns     Byte length as a plain number.
   *
   * @example
   * const size = MajikFile.getRawFileSize(rawBytes);
   * const level = MajikCompressor.adaptiveLevel(rawBytes, CompressionPreset.ULTRA);
   */
  static getRawFileSize(data: Uint8Array | ArrayBuffer): number {
    return data instanceof Uint8Array ? data.byteLength : data.byteLength;
  }

  /**
   * Attach a pre-computed MajikSignature to this file.
   * Replaces any existing signature — idempotent re-signing is safe.
   * Call toJSON() and persist to Supabase after attaching.
   *
   * Use this when you have already called MajikSignature.sign() yourself
   * and want to store the result. For a one-shot sign + attach, use sign().
   *
   * @param signature  MajikSignature instance or its serialized base64 string.
   * @throws MajikFileError if the value is an empty string.
   */
  attachSignature(signature: MajikSignature | string): void {
    if (typeof signature === "string") {
      if (!signature.trim()) {
        throw MajikFileError.invalidInput(
          "attachSignature: signature string must be non-empty",
        );
      }
      // Validate the string is actually deserializable before storing
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

  /**
   * Remove the attached signature from this file.
   * No-op if no signature is attached.
   * Call toJSON() and persist to Supabase after removing.
   */
  removeSignature(): void {
    if (this._signature === null) return;
    this._signature = null;
    this._lastUpdate = new Date().toISOString();
  }

  /**
   * Sign the loaded .mjkb binary and attach the resulting signature.
   *
   * The signature covers the encrypted binary bytes — exactly what is
   * stored in R2. This means verification does not require decryption:
   * any party with the signer's public keys can verify storage integrity
   * without access to the ML-KEM secret key.
   *
   * Signing the encrypted binary (not the plaintext) is intentional:
   *   - The binary is the canonical artifact — it's what gets stored, fetched,
   *     and transferred. Signing it proves the ciphertext hasn't been tampered
   *     with since the owner created it.
   *   - Verification requires no decryption, making it safe to run in
   *     public/server contexts that only have the signer's public keys.
   *   - If you need to prove plaintext authenticity, use verifyBinary()
   *     which decrypts first and then checks the hash.
   *
   * Replaces any existing signature — re-signing after mutations is safe
   * as long as the binary has not changed (binaries are write-once).
   *
   * @param key      Unlocked MajikKey with signing keys (Ed25519 + ML-DSA-87).
   * @param options  Optional content type label and timestamp override.
   * @returns        The attached MajikSignature instance.
   * @throws MajikFileError if the binary is not loaded.
   * @throws MajikSignatureKeyError if the key is locked or missing signing keys.
   */
  async sign(
    key: MajikKey,
    options?: { contentType?: string; timestamp?: string },
  ): Promise<MajikSignature> {
    if (!this._binary) {
      throw MajikFileError.missingBinary();
    }
    const sig = await MajikSignature.sign(this._binary, key, {
      contentType: options?.contentType ?? this._mimeType ?? undefined,
      timestamp: options?.timestamp,
    });
    this.attachSignature(sig);
    return sig;
  }

  /**
   * Verify the attached signature against the loaded .mjkb binary.
   *
   * Requires the binary to be loaded in memory (_binary !== null).
   * Returns null instead of throwing when the binary is absent or no
   * signature is attached — callers can treat null as "cannot verify."
   *
   * To distinguish "unsigned" from "binary not loaded", check isSigned
   * before calling:
   *
   *   if (!file.isSigned) // definitively unsigned
   *   const result = file.verify(key);
   *   if (result === null) // binary not loaded — fetch from R2 first
   *   if (!result.valid)   // signature present but verification failed
   *
   * For full plaintext verification (decrypt then verify), use verifyBinary().
   *
   * @param keyOrPublicKeys  MajikKey instance (locked or unlocked) or raw public keys.
   * @returns VerificationResult, or null if unsigned or binary not loaded.
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
   * Full binary verification — decrypts the loaded .mjkb binary and verifies
   * the signature against the recovered plaintext bytes.
   *
   * Use this when you want cryptographic proof that:
   *   1. The ciphertext decrypts correctly (ML-KEM + AES-GCM authentication passes)
   *   2. The decrypted plaintext matches what the signer originally signed
   *
   * This is the strongest verification path but requires both the identity
   * (to decrypt) and the signer's public keys (to verify).
   *
   * @param identity         ML-KEM identity for decryption.
   * @param keyOrPublicKeys  Signer's public keys for signature verification.
   * @returns VerificationResult with valid: true/false.
   * @throws MajikFileError if binary is not loaded or no signature is attached.
   */
  async verifyBinary(
    identity: Pick<MajikFileIdentity, "fingerprint" | "mlKemSecretKey">,
    keyOrPublicKeys: MajikKey | MajikSignerPublicKeys,
  ): Promise<VerificationResult> {
    if (!this._binary) {
      throw MajikFileError.missingBinary();
    }
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

    // Decrypt to recover plaintext bytes, then verify signature against them
    const plaintext = await MajikFile.decrypt(this._binary, identity);

    if (MajikFile._isMajikKey(keyOrPublicKeys)) {
      return MajikSignature.verifyWithKey(plaintext, sig, keyOrPublicKeys);
    }
    return MajikSignature.verify(plaintext, sig, keyOrPublicKeys);
  }

  /**
   * Extract envelope metadata from the attached signature without full
   * cryptographic verification. Useful for displaying signer info in a UI
   * (e.g. "Signed by business@thezelijah.world on 2025-01-01") before deciding
   * whether to run the more expensive verify() call.
   *
   * Returns null if no signature is attached or the stored value is malformed.
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

  // ── Private signature helpers ─────────────────────────────────────────────

  /**
   * Duck-type check to distinguish MajikKey from MajikSignerPublicKeys.
   * Mirrors the same helper in MajikSignature — kept private here to avoid
   * exposing key-type discrimination on the public API.
   */
  private static _isMajikKey(
    v: MajikKey | MajikSignerPublicKeys,
  ): v is MajikKey {
    // MajikKey carries `fingerprint`; MajikSignerPublicKeys uses `signerId`.
    // This distinction is what makes the duck-type safe — if MajikSignerPublicKeys
    // ever gains a `fingerprint` field this check must be updated.
    return typeof (v as MajikKey).fingerprint === "string";
  }
}
