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

// ─── MajikCompressor ──────────────────────────────────────────────────────────

export class MajikCompressor {
  private static initialized = false;

  /**
   * Ensure the Zstd WASM module is initialised.
   * Safe to call concurrently — the second caller will await the same promise.
   */
  private static async ensureInit() {
    if (!this.initialized) {
      await init(); // only init Zstd for binary mode
      this.initialized = true;
    }
  }

  /**
   * Compress raw bytes using Zstd at the specified level.
   *
   * @param data   Raw bytes to compress.
   * @param level  Compression level 1–22. Defaults to ZSTD_MAX_LEVEL (22).
   * @returns      Compressed bytes.
   * @throws       MajikFileError on failure.
   */
  static async compress(
    data: Uint8Array,
    level: number = ZSTD_MAX_LEVEL,
  ): Promise<Uint8Array> {
    if (!(data instanceof Uint8Array) || data.length === 0) {
      throw MajikFileError.invalidInput(
        "MajikCompressor.compress: data must be a non-empty Uint8Array",
      );
    }
    if (!Number.isInteger(level) || level < 1 || level > 22) {
      throw MajikFileError.invalidInput(
        `MajikCompressor.compress: level must be an integer between 1 and 22 (got ${level})`,
      );
    }
    try {
      await this.ensureInit();
      return zstdCompress(data, level);
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
