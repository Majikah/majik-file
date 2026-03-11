/**
 * majik-compressor.ts
 *
 * Zstd (WASM) compression provider for MajikFile.
 * Uses @bokuweb/zstd-wasm exclusively — no gzip fallback.
 *
 * The WASM module is initialised lazily on first use and cached for the
 * lifetime of the module. Subsequent calls are synchronous after the first
 * await.
 */

import {
  init,
  compress as zstdCompress,
  decompress as zstdDecompress,
} from "@bokuweb/zstd-wasm";
import { MajikFileError } from "../error";
import { ZSTD_MAX_LEVEL } from "../crypto/constants";

// ─── Compression Level Type ───────────────────────────────────────────────────

/**
 * Explicit integer compression level for Zstd, 1–22.
 *
 * Recommended values:
 *  - 1   → Fastest possible; still meaningfully compresses text/code.
 *  - 3   → Good speed/ratio balance for real-time paths.
 *  - 6   → Inflection point — noticeably better ratio, modest speed cost.
 *  - 9   → Strong compression; gains plateau significantly after this.
 *  - 15  → High-effort; use only for smaller, latency-insensitive uploads.
 *  - 19  → Near-maximum ratio without WASM memory pressure.
 *  - 22  → Archival-grade; not safe for files > 10 MB in WASM environments.
 *
 * For production use, prefer a CompressionPreset over a raw integer unless
 * you have a specific tuning requirement.
 */
export type CompressionLevel =
  | 1
  | 2
  | 3
  | 4
  | 5
  | 6
  | 7
  | 8
  | 9
  | 10
  | 11
  | 12
  | 13
  | 14
  | 15
  | 16
  | 17
  | 18
  | 19
  | 20
  | 21
  | 22;

// ─── Compression Preset ───────────────────────────────────────────────────────

/**
 * Named compression presets. Maps human-readable intent to a concrete Zstd
 * level that is safe and well-tuned for that use case.
 *
 * Preset → level mapping:
 *  FASTEST  → 2   Near-instant; still ~2× smaller than raw for text.
 *                 Level 1 is technically valid and ~5–10% faster than 2,
 *                 but the ratio drop is noticeable. 2 is the better floor.
 *  FAST     → 3   Zstd's own "default fast" tuning point.
 *  BALANCED → 6   Best ratio-per-millisecond across the whole range.
 *  GOOD     → 9   Recommended for most user uploads — strong ratio, reasonable time.
 *  BETTER   → 15  High-effort pass; good for documents and code archives.
 *  BEST     → 19  Maximum safe level for files up to ~10 MB in WASM.
 *  ULTRA    → 22  Archival only. Will OOM on files > ~10 MB in WASM heap.
 *                 Use adaptiveLevel() or the auto-clamp in compress() instead.
 */
export const CompressionPreset = {
  FASTEST: 2 as CompressionLevel,
  FAST: 3 as CompressionLevel,
  BALANCED: 6 as CompressionLevel,
  GOOD: 9 as CompressionLevel,
  BETTER: 15 as CompressionLevel,
  BEST: 19 as CompressionLevel,
  ULTRA: 22 as CompressionLevel,
} as const;

export type CompressionPresetKey = keyof typeof CompressionPreset;

// ─── Adaptive Level Thresholds ────────────────────────────────────────────────

/**
 * Maximum safe Zstd level for a given input byte size, ordered from largest
 * to smallest. The first threshold whose `minBytes` the input exceeds wins.
 *
 * Rationale:
 *  Zstd's ultra modes (≥ 20) allocate scratch memory proportional to input
 *  size. In a WASM heap of ~2 GB, a 500 MB file at level 22 will reliably OOM.
 *  The thresholds below keep peak memory well inside the WASM safe zone while
 *  still applying strong compression on smaller inputs where it matters most.
 *
 *  > 500 MB  → cap 6   (safe, fast; ratio gains from higher levels are marginal
 *                        for already-large payloads like video or raw audio)
 *  > 100 MB  → cap 12  (solid ratio, ~2–4 s on modern hardware)
 *  >  50 MB  → cap 16  (strong ratio, memory stays bounded)
 *  >  10 MB  → cap 19  (near-maximum ratio; still WASM-safe)
 *  ≤  10 MB  → no cap  (all levels safe; apply requested level as-is)
 */
const ADAPTIVE_THRESHOLDS: { minBytes: number; maxLevel: CompressionLevel }[] =
  [
    { minBytes: 500 * 1024 * 1024, maxLevel: 6 },
    { minBytes: 100 * 1024 * 1024, maxLevel: 12 },
    { minBytes: 50 * 1024 * 1024, maxLevel: 16 },
    { minBytes: 10 * 1024 * 1024, maxLevel: 19 },
  ];

// ─── MajikCompressor ──────────────────────────────────────────────────────────

export class MajikCompressor {
  private static initialized = false;

  /**
   * Ensure the Zstd WASM module is initialised.
   * Safe to call concurrently — the second caller will await the same promise.
   */
  private static async ensureInit() {
    if (!this.initialized) {
      await init();
      this.initialized = true;
    }
  }

  // ── Level helpers ─────────────────────────────────────────────────────────

  /**
   * Clamp any integer to the valid Zstd level range [1, 22].
   * Accepts both raw integers and CompressionPreset values — they are
   * identical at runtime (both are numbers).
   *
   * @example
   * MajikCompressor.clampLevel(0)   // 1
   * MajikCompressor.clampLevel(25)  // 22
   * MajikCompressor.clampLevel(CompressionPreset.BALANCED) // 6
   */
  static clampLevel(level: number): CompressionLevel {
    return Math.max(1, Math.min(22, Math.round(level))) as CompressionLevel;
  }

  /**
   * Return the raw byte size of a Uint8Array.
   *
   * Exposed as a named helper so callers can log or display the original file
   * size before compression without reading a separate metadata field.
   *
   * @param data  Any Uint8Array — typically the raw plaintext bytes.
   * @returns     Byte length as a plain number.
   */
  static rawByteSize(data: Uint8Array): number {
    return data.byteLength;
  }

  /**
   * Derive a safe Zstd compression level for the given input size.
   *
   * This is the recommended way to pick a level when you want maximum
   * compression without risking WASM out-of-memory errors on large files.
   *
   * The requested `desiredLevel` is honoured unless it would exceed the
   * memory-safe ceiling for the input size, in which case it is silently
   * clamped downward.  The level is never raised — if you pass a low desired
   * level the function respects it.
   *
   * @param data          The raw input bytes (used only for `.byteLength`).
   * @param desiredLevel  The level you would ideally like to use.
   *                      Defaults to ZSTD_MAX_LEVEL (22).
   * @returns             A safe level in [1, 22].
   *
   * @example
   * const level = MajikCompressor.adaptiveLevel(rawBytes); // auto-safe
   * const level = MajikCompressor.adaptiveLevel(rawBytes, CompressionPreset.BEST);
   */
  static adaptiveLevel(
    data: Uint8Array,
    desiredLevel: CompressionLevel | number = ZSTD_MAX_LEVEL,
  ): CompressionLevel {
    const inputSize = MajikCompressor.rawByteSize(data);
    const clamped = MajikCompressor.clampLevel(desiredLevel);

    for (const { minBytes, maxLevel } of ADAPTIVE_THRESHOLDS) {
      if (inputSize > minBytes) {
        // Cap the requested level, but never raise it
        return Math.min(clamped, maxLevel) as CompressionLevel;
      }
    }

    // ≤ 10 MB — all levels are safe
    return clamped;
  }

  // ── Compress / Decompress ─────────────────────────────────────────────────

  /**
   * Compress raw bytes using Zstd at the specified level.
   *
   * Accepts either a `CompressionLevel` integer (1–22) or a `CompressionPreset`
   * value. The level is always safety-clamped via `adaptiveLevel()` before
   * being passed to the WASM codec, so passing `CompressionPreset.ULTRA` on a
   * 1 GB file will silently use level 6 rather than crashing.
   *
   * @param data   Raw bytes to compress.
   * @param level  Compression level or preset. Defaults to ZSTD_MAX_LEVEL (22).
   *               The effective level may be lower if the input is large —
   *               inspect the return of `adaptiveLevel()` first if you need
   *               to know the actual level used.
   * @returns      Compressed bytes.
   * @throws       MajikFileError on invalid input or codec failure.
   */
  static async compress(
    data: Uint8Array,
    level: CompressionLevel | number = ZSTD_MAX_LEVEL,
  ): Promise<Uint8Array> {
    if (!(data instanceof Uint8Array) || data.length === 0) {
      throw MajikFileError.invalidInput(
        "MajikCompressor.compress: data must be a non-empty Uint8Array",
      );
    }

    // clampLevel catches NaN / out-of-range; adaptiveLevel handles OOM risk
    const safeLevel = MajikCompressor.adaptiveLevel(data, level);

    try {
      await this.ensureInit();
      return zstdCompress(data, safeLevel);
    } catch (err) {
      throw MajikFileError.compressionFailed(err);
    }
  }

  /**
   * Decompress Zstd-compressed bytes.
   *
   * @param data  Zstd-compressed bytes.
   * @returns     Decompressed bytes.
   * @throws      MajikFileError on failure or corrupt data.
   */
  static async decompress(data: Uint8Array): Promise<Uint8Array> {
    if (!(data instanceof Uint8Array) || data.length === 0) {
      throw MajikFileError.invalidInput(
        "MajikCompressor.decompress: data must be a non-empty Uint8Array",
      );
    }
    try {
      await this.ensureInit();
      return zstdDecompress(data);
    } catch (err) {
      throw MajikFileError.decompressionFailed(err);
    }
  }

  // ── Stats ─────────────────────────────────────────────────────────────────

  /**
   * Returns the compression ratio as a percentage size reduction.
   * e.g. 100 bytes → 30 bytes = 70.0% reduction.
   *
   * @param originalSize   Size before compression (bytes).
   * @param compressedSize Size after compression (bytes).
   * @returns              Reduction percentage (0–100), rounded to one decimal.
   */
  static compressionRatioPct(
    originalSize: number,
    compressedSize: number,
  ): number {
    if (originalSize <= 0) return 0;
    const reduction = ((originalSize - compressedSize) / originalSize) * 100;
    return Math.max(0, Math.round(reduction * 10) / 10);
  }
}
