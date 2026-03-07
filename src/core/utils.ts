/**
 * utils.ts
 *
 * Utility functions for MajikFile:
 *  - Base64 encode / decode
 *  - SHA-256 hashing (synchronous via @stablelib/sha256)
 *  - UUID generation
 *  - .mjkb binary encode / decode  ← updated format supporting single & group
 *  - R2 key construction
 *  - MIME type helpers
 *  - Human-readable file size formatting
 *  - Expiry helpers
 */

import { hash } from "@stablelib/sha256";
import { MajikFileError } from "./error";
import {
  MJKB_MAGIC,
  MJKB_VERSION,
  R2_PREFIX,
  INLINE_VIEWABLE_MIME_TYPES,
  EXTENSION_TO_MIME,
  MAX_RECIPIENTS,
  INCOMPRESSIBLE_MIME_TYPES,
  WEBP_CONVERTIBLE_IMAGE_TYPES,
} from "./crypto/constants";
import type {
  DecodedMjkb,
  MajikFileRecipient,
  MjkbPayload,
  TempFileDuration,
} from "./types";

// ─── Base64 ───────────────────────────────────────────────────────────────────

export function arrayToBase64(data: Uint8Array): string {
  let binary = "";
  const chunkSize = 0x8000;
  for (let i = 0; i < data.length; i += chunkSize) {
    binary += String.fromCharCode(...data.subarray(i, i + chunkSize));
  }
  return btoa(binary);
}

export function arrayBufferToBase64(buffer: ArrayBuffer): string {
  return arrayToBase64(new Uint8Array(buffer));
}

export function base64ToUint8Array(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export function base64ToArrayBuffer(base64: string): ArrayBuffer {
  return base64ToUint8Array(base64).buffer as ArrayBuffer;
}

// ─── SHA-256 ──────────────────────────────────────────────────────────────────

/**
 * Synchronous SHA-256 digest → lowercase hex string (64 chars).
 * Always computed over the ORIGINAL raw bytes (before compression/encryption)
 * so it can be used reliably for duplicate detection.
 */
export function sha256Hex(data: Uint8Array): string {
  const digest = hash(data);
  return Array.from(digest)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Synchronous SHA-256 digest → base64 string.
 * Used for ML-KEM public key fingerprints.
 */
export function sha256Base64(data: Uint8Array): string {
  return arrayToBase64(hash(data));
}

// ─── UUID ─────────────────────────────────────────────────────────────────────

export function generateUUID(): string {
  return crypto.randomUUID();
}

// ─── Human-readable Size ──────────────────────────────────────────────────────

export function formatBytes(bytes: number): string {
  if (bytes < 0) return "0 B";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 ** 3) return `${(bytes / 1024 ** 2).toFixed(1)} MB`;
  return `${(bytes / 1024 ** 3).toFixed(1)} GB`;
}

// ─── R2 Key Construction ──────────────────────────────────────────────────────

/**
 * Build an R2 object key for a permanent (user-owned) file.
 *   files/user/<userId>/<fileHash>.mjkb
 */
export function buildPermanentR2Key(userId: string, fileHash: string): string {
  return `${R2_PREFIX.PERMANENT}/${userId}/${fileHash}.mjkb`;
}

/**
 * Build an R2 object key for a temporary / public file.
 * Objects under this prefix are auto-deleted by the bucket lifecycle policy.
 *   files/public/15/<userId>_<fileHash>.mjkb
 */
export function buildTemporaryR2Key(
  userId: string,
  fileHash: string,
  duration: TempFileDuration = 15,
): string {
  return `${R2_PREFIX.TEMPORARY}/${duration}/${userId}_${fileHash}.mjkb`;
}

/**
 * Build an R2 object key for an encrypted WebP chat image.
 *
 * Scoped per conversation so all images belonging to a conversation can be
 * listed or batch-deleted via a single R2 prefix scan.
 *
 *   images/chats/<conversationId>/<userId>_<fileHash>.mjkb
 *
 * @param conversationId  The chat conversation / channel ID (UUID or slug).
 * @param userId          The uploading user's auth sub (UUID).
 * @param fileHash        SHA-256 hex digest of the ORIGINAL image bytes
 *                        (pre-WebP-conversion, pre-compression) — same value
 *                        stored in majik_files.file_hash for dedup queries.
 */
export function buildChatImageR2Key(
  conversationId: string,
  userId: string,
  fileHash: string,
): string {
  return `${R2_PREFIX.CHAT_IMAGE}/${conversationId}/${userId}_${fileHash}.mjkb`;
}

// ─── MIME Type Helpers ────────────────────────────────────────────────────────

/**
 * Returns true if the MIME type can be rendered inline in a browser.
 */
export function isMimeTypeInlineViewable(mimeType: string | null): boolean {
  if (!mimeType) return false;
  return INLINE_VIEWABLE_MIME_TYPES.has(
    mimeType.toLowerCase().split(";")[0].trim(),
  );
}

/**
 * Infer a MIME type from a filename extension.
 * Returns null if the extension is unknown.
 *
 * @example
 * inferMimeTypeFromFilename("photo.jpg")  // "image/jpeg"
 * inferMimeTypeFromFilename("archive.rar") // "application/x-rar-compressed"
 * inferMimeTypeFromFilename("unknown.xyz") // null
 */
export function inferMimeTypeFromFilename(filename: string): string | null {
  if (!filename) return null;
  const dot = filename.lastIndexOf(".");
  if (dot === -1) return null;
  const ext = filename.slice(dot + 1).toLowerCase();
  return EXTENSION_TO_MIME[ext] ?? null;
}

/**
 * Derive a safe download filename from the file hash + original extension.
 * Falls back to "<hash>.mjkb" if originalName is null or has no extension.
 */
export function deriveFilename(
  fileHash: string,
  originalName: string | null,
): string {
  if (!originalName) return `${fileHash}.mjkb`;
  const dot = originalName.lastIndexOf(".");
  const ext = dot !== -1 ? originalName.slice(dot).toLowerCase() : "";
  const safeExt = /^\.[a-z0-9]{1,10}$/.test(ext) ? ext : "";
  return `${fileHash}${safeExt || ".mjkb"}`;
}

// ─── Normalise Input to Uint8Array ────────────────────────────────────────────

export function normaliseToUint8Array(
  data: Uint8Array | ArrayBuffer,
): Uint8Array {
  if (data instanceof Uint8Array) return data;
  return new Uint8Array(data);
}

export async function normaliseToUint8ArrayAsync(
  data: Uint8Array | ArrayBuffer | Blob,
): Promise<Uint8Array> {
  if (data instanceof Blob) return new Uint8Array(await data.arrayBuffer());
  return normaliseToUint8Array(data);
}

// ─── .mjkb Binary Codec ───────────────────────────────────────────────────────
//
//  The format supports both single-recipient and group-recipient files by
//  embedding a variable-length JSON payload section (instead of a fixed
//  ML-KEM ciphertext field) after the IV.
//
//  ┌───────────────────────────────────────────────────────────────────────────┐
//  │  4 bytes  │ Magic: ASCII "MJKB"  (0x4D 0x4A 0x4B 0x42)                  │
//  │  1 byte   │ Version              (currently 0x01)                         │
//  │ 12 bytes  │ AES-GCM IV                                                    │
//  │  4 bytes  │ Payload JSON length  (big-endian uint32)                      │
//  │  N bytes  │ Payload JSON         (UTF-8; MjkbSinglePayload | MjkbGroupPayload) │
//  │  M bytes  │ AES-GCM ciphertext   (Zstd-compressed plaintext + 16-byte tag)│
//  └───────────────────────────────────────────────────────────────────────────┘
//
//  Single payload JSON:
//    { "mlKemCipherText": "<base64 1088 bytes>" }
//
//  Group payload JSON:
//    { "keys": [{ "fingerprint": "...", "mlKemCipherText": "...", "encryptedAesKey": "..." }, ...] }
//
//  Fixed header size (before payload JSON):  4 + 1 + 12 + 4 = 21 bytes

const MJKB_FIXED_HEADER = 4 + 1 + 12 + 4; // 21 bytes

/**
 * Encode a .mjkb binary from its constituent parts.
 *
 * @param iv          12-byte AES-GCM IV.
 * @param payload     Serialised MjkbSinglePayload or MjkbGroupPayload.
 * @param ciphertext  AES-GCM ciphertext (Zstd-compressed plaintext + 16-byte auth tag).
 */
export function encodeMjkb(
  iv: Uint8Array,
  payload: MjkbPayload,
  ciphertext: Uint8Array,
): Uint8Array {
  const payloadBytes = new TextEncoder().encode(JSON.stringify(payload));
  const payloadLen = payloadBytes.length;

  const total = MJKB_FIXED_HEADER + payloadLen + ciphertext.length;
  const buf = new Uint8Array(total);
  let offset = 0;

  // Magic
  buf.set(MJKB_MAGIC, offset);
  offset += 4;

  // Version
  buf[offset++] = MJKB_VERSION;

  // IV (12 bytes)
  buf.set(iv, offset);
  offset += 12;

  // Payload JSON length (big-endian uint32)
  buf[offset++] = (payloadLen >>> 24) & 0xff;
  buf[offset++] = (payloadLen >>> 16) & 0xff;
  buf[offset++] = (payloadLen >>> 8) & 0xff;
  buf[offset++] = payloadLen & 0xff;

  // Payload JSON
  buf.set(payloadBytes, offset);
  offset += payloadLen;

  // Ciphertext
  buf.set(ciphertext, offset);

  return buf;
}

/**
 * Decode a raw .mjkb buffer into its constituent parts.
 *
 * @throws MajikFileError on magic mismatch, unsupported version, truncation,
 *         or malformed payload JSON.
 */
export function decodeMjkb(raw: Uint8Array): DecodedMjkb {
  // Minimum: fixed header + 1 byte payload JSON + 1 byte ciphertext
  if (raw.length < MJKB_FIXED_HEADER + 2) {
    throw MajikFileError.formatError(
      `.mjkb binary is too short (${raw.length} bytes) — minimum is ${MJKB_FIXED_HEADER + 2} bytes`,
    );
  }

  // Magic check
  for (let i = 0; i < 4; i++) {
    if (raw[i] !== MJKB_MAGIC[i]) {
      throw MajikFileError.formatError(
        "Invalid .mjkb magic bytes — this is not a MajikFile binary",
      );
    }
  }

  let offset = 4;
  const version = raw[offset++];

  if (version !== MJKB_VERSION) {
    throw MajikFileError.unsupportedVersion(version, MJKB_VERSION);
  }

  // IV (12 bytes)
  const iv = raw.slice(offset, offset + 12);
  offset += 12;

  // Payload JSON length (big-endian uint32)
  const payloadLen =
    (raw[offset] << 24) |
    (raw[offset + 1] << 16) |
    (raw[offset + 2] << 8) |
    raw[offset + 3];
  offset += 4;

  if (payloadLen <= 0 || raw.length < offset + payloadLen + 1) {
    throw MajikFileError.formatError(
      `.mjkb binary is truncated — payload JSON declares ${payloadLen} bytes but insufficient data remains`,
    );
  }

  // Payload JSON
  let payload: MjkbPayload;
  try {
    payload = JSON.parse(
      new TextDecoder().decode(raw.slice(offset, offset + payloadLen)),
    ) as MjkbPayload;
  } catch {
    throw MajikFileError.formatError(
      ".mjkb payload JSON is malformed and could not be parsed",
    );
  }
  offset += payloadLen;

  // Ciphertext (remainder)
  const ciphertext = raw.slice(offset);
  if (ciphertext.length === 0) {
    throw MajikFileError.formatError(".mjkb ciphertext section is empty");
  }

  return { version, iv, payload, ciphertext };
}

// ─── Expiry Helpers ───────────────────────────────────────────────────────────

/** Returns true if the given ISO-8601 timestamp is in the past. */
export function isExpired(expiresAt: string | null): boolean {
  if (!expiresAt) return false;
  return new Date(expiresAt).getTime() < Date.now();
}

/**
 * Build a default expiry ISO string for temporary files.
 * @param days Days from now. Defaults to 15 (matching the R2 lifecycle policy).
 */
export function buildExpiryDate(days: TempFileDuration = 15): string {
  const d = new Date();
  d.setDate(d.getDate() + days);
  return d.toISOString();
}

// ─── Module-level helpers ─────────────────────────────────────────────────────

/**
 * Deduplicate a recipient list and strip the owner's own key.
 *
 * Rules:
 *  - The owner's fingerprint is never allowed in `recipients` — it is
 *    always prepended automatically in the group path. If present, it is
 *    silently removed rather than throwing.
 *  - Any fingerprint that appears more than once is deduplicated; the first
 *    occurrence wins.
 *  - Deduplication is by fingerprint string, not by raw public key bytes.
 *
 * Returns the cleaned list. If the result is empty the caller should use
 * the single-recipient path.
 */
export function deduplicateRecipients(
  recipients: MajikFileRecipient[],
  ownerFingerprint: string,
): MajikFileRecipient[] {
  const seen = new Set<string>([ownerFingerprint]);
  const result: MajikFileRecipient[] = [];
  for (const r of recipients) {
    if (seen.has(r.fingerprint)) continue; // owner duplicate or repeated entry
    seen.add(r.fingerprint);
    result.push(r);
  }
  return result;
}

/**
 * Assert that the recipient count (after deduplication) does not exceed
 * MAX_RECIPIENTS (100). Throws a MajikFileError if the limit is exceeded.
 *
 * Does NOT include the owner in the count — `recipients` here is the
 * already-deduplicated list of *additional* recipients beyond the owner.
 *
 * @throws MajikFileError("INVALID_INPUT") if count > MAX_RECIPIENTS.
 */
export function assertRecipientLimit(recipients: MajikFileRecipient[]): void {
  if (recipients.length > MAX_RECIPIENTS) {
    throw MajikFileError.invalidInput(
      `Too many recipients: ${recipients.length} (maximum is ${MAX_RECIPIENTS} excluding the owner). ` +
        `Consider splitting into multiple files or threads.`,
    );
  }
}

/**
 * Decide whether raw bytes should be Zstd-compressed before encryption.
 *
 * Returns false for MIME types that are already compressed at the codec level
 * (JPEG, WebP, AVIF, all video, lossy audio, archives, zipped Office formats).
 * Returns true for everything else — text, code, raw images (PNG, BMP),
 * lossless audio (WAV, FLAC, AIFF), PDFs, JSON, XML, etc.
 *
 * @param mimeType  The resolved MIME type of the file, or null if unknown.
 *                  When null, compression is applied (safer default).
 */
export function shouldCompress(mimeType: string | null): boolean {
  if (!mimeType) return true;
  const normalised = mimeType.toLowerCase().split(";")[0].trim();
  return !INCOMPRESSIBLE_MIME_TYPES.has(normalised);
}

/**
 * Convert an image Uint8Array to WebP format using the browser's Canvas API.
 *
 * Used exclusively in the `chat_attachment` context to normalise all
 * non-WebP images (PNG, JPEG, GIF, BMP, etc.) to WebP before encryption.
 * This reduces payload size for PNG and BMP in particular, and ensures a
 * consistent delivery format to chat clients.
 *
 * SVG files are returned unchanged — they are vector and cannot be meaningfully
 * rasterised without knowing the intended display dimensions.
 *
 * HEIC/HEIF/JXL files are returned unchanged — browsers do not support
 * encoding these via Canvas.
 *
 * @param imageBytes  Raw bytes of the source image.
 * @param mimeType    Resolved MIME type of the source image.
 * @param quality     WebP encoding quality 0–1. Defaults to 0.88 (a good
 *                    balance between visual quality and file size).
 * @returns           WebP bytes, or the original bytes if conversion is not
 *                    applicable for this MIME type.
 */
export async function convertImageToWebP(
  imageBytes: Uint8Array,
  mimeType: string,
  quality = 0.88,
): Promise<{ bytes: Uint8Array; mimeType: string }> {
  const normalised = mimeType.toLowerCase().split(";")[0].trim();

  // Already WebP, or not a type we can convert via Canvas
  if (!WEBP_CONVERTIBLE_IMAGE_TYPES.has(normalised)) {
    return { bytes: imageBytes, mimeType };
  }

  // Canvas API is only available in browser environments
  if (
    typeof document === "undefined" ||
    typeof HTMLCanvasElement === "undefined"
  ) {
    // Server-side / non-browser environment — return as-is
    return { bytes: imageBytes, mimeType };
  }

  return new Promise((resolve) => {
    const blob = new Blob([imageBytes as BlobPart], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const img = new Image();

    img.onload = () => {
      URL.revokeObjectURL(url);
      try {
        const canvas = document.createElement("canvas");
        canvas.width = img.naturalWidth;
        canvas.height = img.naturalHeight;
        const ctx = canvas.getContext("2d");
        if (!ctx) {
          // Canvas context unavailable — fall back to original
          resolve({ bytes: imageBytes, mimeType });
          return;
        }
        ctx.drawImage(img, 0, 0);
        canvas.toBlob(
          (webpBlob) => {
            if (!webpBlob) {
              // Browser declined to encode WebP — fall back to original
              resolve({ bytes: imageBytes, mimeType });
              return;
            }
            webpBlob
              .arrayBuffer()
              .then((buf) => {
                resolve({ bytes: new Uint8Array(buf), mimeType: "image/webp" });
              })
              .catch(() => resolve({ bytes: imageBytes, mimeType }));
          },
          "image/webp",
          quality,
        );
      } catch {
        resolve({ bytes: imageBytes, mimeType });
      }
    };

    img.onerror = () => {
      URL.revokeObjectURL(url);
      // Not a renderable image — keep original
      resolve({ bytes: imageBytes, mimeType });
    };

    img.src = url;
  });
}
