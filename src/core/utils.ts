/**
 * core/utils/base-utils.ts
 *
 * Generic helpers used by the base MajikFile. Nothing here knows about
 * FileContext, R2, or any other platform concept — that all lives in
 * core/message/message-utils.ts.
 *
 * NOTE on `shouldCompressMime`: the original SDK decided compression via
 * `shouldCompressForContext(context, mime)`. Re-reading its own JSDoc
 * ("skipped for already-compressed images JPEG/WebP/AVIF and video/audio/
 * archives"), the actual policy was mime-driven — context wasn't doing
 * real work in that decision. This version keeps the mime-only policy and
 * drops the context dependency entirely, which is also what unblocks the
 * base layer from needing FileContext at all.
 */

import { hash } from "@stablelib/sha256";
import { MajikFileError } from "./error";

// ─── Hashing ──────────────────────────────────────────────────────────────────


export function sha256Hex(data: Uint8Array): string {
  const digest = hash(data);
  return Array.from(digest)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function sha256Base64(data: Uint8Array): string {
  return arrayToBase64(hash(data));
}

// ─── UUID ─────────────────────────────────────────────────────────────────────

export function generateUUID(): string {
  return crypto.randomUUID();
}

// ─── Byte <-> Base64 ────────────────────────────────────────────────────────
//
// Portable across browser, Tauri webview, and Cloudflare Workers (all
// expose atob/btoa globally) — deliberately avoids Node's Buffer, which
// isn't guaranteed present in a Workers runtime. Chunked to avoid blowing
// the call stack via String.fromCharCode(...bytes) on large files.

const B64_CHUNK_SIZE = 0x8000;

export function arrayToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i += B64_CHUNK_SIZE) {
    binary += String.fromCharCode(...bytes.subarray(i, i + B64_CHUNK_SIZE));
  }
  return btoa(binary);
}

export function base64ToArray(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

// ─── Byte normalisation ─────────────────────────────────────────────────────

export function normaliseToUint8Array(data: Uint8Array | ArrayBuffer): Uint8Array {
  return data instanceof Uint8Array ? data : new Uint8Array(data);
}

export async function normaliseToUint8ArrayAsync(
  source: Blob | Uint8Array | ArrayBuffer,
): Promise<Uint8Array> {
  if (source instanceof Uint8Array) return source;
  if (source instanceof ArrayBuffer) return new Uint8Array(source);
  if (typeof Blob !== "undefined" && source instanceof Blob) {
    return new Uint8Array(await source.arrayBuffer());
  }
  throw MajikFileError.invalidInput(
    "Unsupported source type — expected Blob, Uint8Array, or ArrayBuffer",
  );
}

// ─── Human-readable size ────────────────────────────────────────────────────

const SIZE_UNITS = ["B", "KB", "MB", "GB", "TB"] as const;

export function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const exp = Math.min(
    Math.floor(Math.log(bytes) / Math.log(1024)),
    SIZE_UNITS.length - 1,
  );
  const value = bytes / Math.pow(1024, exp);
  return `${value.toFixed(exp === 0 ? 0 : 2)} ${SIZE_UNITS[exp]}`;
}

// ─── MIME helpers ─────────────────────────────────────────────────────────────

const INLINE_VIEWABLE_PREFIXES = ["image/", "video/", "audio/", "text/"];
const INLINE_VIEWABLE_EXACT = new Set(["application/pdf", "application/json"]);

export function isMimeTypeInlineViewable(mime: string | null): boolean {
  if (!mime) return false;
  if (INLINE_VIEWABLE_EXACT.has(mime)) return true;
  return INLINE_VIEWABLE_PREFIXES.some((prefix) => mime.startsWith(prefix));
}

const EXT_TO_MIME: Record<string, string> = {
  png: "image/png",
  jpg: "image/jpeg",
  jpeg: "image/jpeg",
  webp: "image/webp",
  gif: "image/gif",
  avif: "image/avif",
  heic: "image/heic",
  pdf: "application/pdf",
  txt: "text/plain",
  json: "application/json",
  mp4: "video/mp4",
  mov: "video/quicktime",
  webm: "video/webm",
  mp3: "audio/mpeg",
  wav: "audio/wav",
  zip: "application/zip",
};

export function inferMimeTypeFromFilename(filename: string): string | null {
  const dot = filename.lastIndexOf(".");
  if (dot === -1) return null;
  const ext = filename.slice(dot + 1).toLowerCase();
  return EXT_TO_MIME[ext] ?? null;
}

export function deriveFilename(
  fileHash: string,
  originalName: string | null,
): string {
  const dot = originalName?.lastIndexOf(".") ?? -1;
  const ext = originalName && dot > -1 ? originalName.slice(dot) : "";
  return `${fileHash.slice(0, 16)}${ext}`;
}

/**
 * Mime-driven compression policy — skip zstd for formats that are already
 * compressed (defeats the purpose and wastes CPU). Used both to set the
 * `z` flag at encrypt time and, for legacy v1 binaries at decrypt time,
 * as the fallback when the binary predates the explicit flag.
 */
const INCOMPRESSIBLE_MIME_PREFIXES = ["video/", "audio/"];
const INCOMPRESSIBLE_MIME_EXACT = new Set([
  "image/jpeg",
  "image/webp",
  "image/avif",
  "image/gif",
  "image/heic",
  "image/heif",
  "application/zip",
  "application/x-7z-compressed",
  "application/x-rar-compressed",
  "application/gzip",
  "application/x-gzip",
  "application/x-zstd",
]);

export function shouldCompressMime(mime: string | null): boolean {
  if (!mime) return true; // unknown format — default to compressing
  if (INCOMPRESSIBLE_MIME_EXACT.has(mime)) return false;
  return !INCOMPRESSIBLE_MIME_PREFIXES.some((prefix) => mime.startsWith(prefix));
}

// ─── Image conversion ─────────────────────────────────────────────────────────

/**
 * Convert raw image bytes to WebP (quality 0.88). Generic image utility —
 * the *decision* of when to call this (e.g. only for certain FileContexts)
 * belongs to the caller, not this function. Falls back to returning the
 * original bytes/mime unchanged if conversion isn't supported/fails in the
 * current runtime (e.g. no OffscreenCanvas available).
 */
export async function convertImageToWebP(
  raw: Uint8Array,
  mimeType: string,
): Promise<{ bytes: Uint8Array; mimeType: string }> {
  if (typeof OffscreenCanvas === "undefined" || typeof createImageBitmap === "undefined") {
    return { bytes: raw, mimeType };
  }
  try {
    const blob = new Blob([raw as BlobPart], { type: mimeType });
    const bitmap = await createImageBitmap(blob);
    const canvas = new OffscreenCanvas(bitmap.width, bitmap.height);
    const ctx = canvas.getContext("2d");
    if (!ctx) return { bytes: raw, mimeType };
    ctx.drawImage(bitmap, 0, 0);
    const webpBlob = await canvas.convertToBlob({ type: "image/webp", quality: 0.88 });
    const bytes = new Uint8Array(await webpBlob.arrayBuffer());
    return { bytes, mimeType: "image/webp" };
  } catch {
    // Conversion failed — fall back to the original bytes rather than throw.
    // Image conversion is an optimisation, not a correctness requirement.
    return { bytes: raw, mimeType };
  }
}

// ─── Recipients ───────────────────────────────────────────────────────────────

/**
 * Strip the owner's own fingerprint and any duplicates from a recipient
 * list. Order-preserving, first-occurrence-wins.
 */
export function deduplicateRecipients<T extends { fingerprint: string }>(
  recipients: T[],
  ownerFingerprint: string,
): T[] {
  const seen = new Set<string>([ownerFingerprint]);
  const result: T[] = [];
  for (const r of recipients) {
    if (seen.has(r.fingerprint)) continue;
    seen.add(r.fingerprint);
    result.push(r);
  }
  return result;
}