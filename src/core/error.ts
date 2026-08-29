// ─── MajikFile Error ──────────────────────────────────────────────────────────

export type MajikFileErrorCode =
  | "INVALID_INPUT"
  | "VALIDATION_ERROR"
  | "ENCRYPTION_FAILED"
  | "DECRYPTION_FAILED"
  | "COMPRESSION_FAILED"
  | "DECOMPRESSION_FAILED"
  | "FORMAT_ERROR"
  | "SIZE_EXCEEDED"
  | "MISSING_BINARY"
  | "UNSUPPORTED_VERSION"
  | "UNSUPPORTED_SCHEMA_VERSION"
  | "UNSUPPORTED_COMPRESSION_ALG"
  | "LEGACY_MIGRATION_FAILED"
  | "STORAGE_KEY_MISMATCH";

export class MajikFileError extends Error {
  readonly code: MajikFileErrorCode;

  constructor(
    code: MajikFileErrorCode,
    message: string,
    public readonly cause?: unknown,
  ) {
    super(message);
    this.name = "MajikFileError";
    this.code = code;
  }

  static invalidInput(message: string, cause?: unknown): MajikFileError {
    return new MajikFileError("INVALID_INPUT", message, cause);
  }

  static validationFailed(errors: string[]): MajikFileError {
    return new MajikFileError(
      "VALIDATION_ERROR",
      `MajikFile validation failed:\n  • ${errors.join("\n  • ")}`,
    );
  }

  static encryptionFailed(cause?: unknown): MajikFileError {
    return new MajikFileError(
      "ENCRYPTION_FAILED",
      "File encryption failed",
      cause,
    );
  }

  static decryptionFailed(
    message = "File decryption failed",
    cause?: unknown,
  ): MajikFileError {
    return new MajikFileError("DECRYPTION_FAILED", message, cause);
  }

  static compressionFailed(cause?: unknown): MajikFileError {
    return new MajikFileError(
      "COMPRESSION_FAILED",
      "File compression failed",
      cause,
    );
  }

  static decompressionFailed(cause?: unknown): MajikFileError {
    return new MajikFileError(
      "DECOMPRESSION_FAILED",
      "File decompression failed",
      cause,
    );
  }

  static formatError(message: string): MajikFileError {
    return new MajikFileError("FORMAT_ERROR", message);
  }

  static sizeExceeded(actual: number, limit: number): MajikFileError {
    return new MajikFileError(
      "SIZE_EXCEEDED",
      `File size ${actual} bytes exceeds the ${limit}-byte limit (${Math.round(limit / 1024 / 1024)} MB). ` +
        `Set bypassSizeLimit: true to override.`,
    );
  }

  static missingBinary(): MajikFileError {
    return new MajikFileError(
      "MISSING_BINARY",
      "No encrypted binary available. " +
        "Either create() the file or supply the binary to fromJSON() / attachBinary().",
    );
  }

  static unsupportedVersion(
    version: number,
    supported: number,
  ): MajikFileError {
    return new MajikFileError(
      "UNSUPPORTED_VERSION",
      `Unsupported .mjkb binary version: ${version}. ` +
        `Only v${supported} (plus documented legacy versions) is supported.`,
    );
  }

  /**
   * JSON/record schema version is unsupported — distinct from
   * unsupportedVersion(), which is about the .mjkb *binary* layout.
   */
  static unsupportedSchemaVersion(
    version: number,
    supportedMax: number,
  ): MajikFileError {
    return new MajikFileError(
      "UNSUPPORTED_SCHEMA_VERSION",
      `Unsupported MajikFile record schema version: ${version}. ` +
        `This SDK supports up to schema v${supportedMax}. ` +
        `Upgrade the SDK, or this may be a legacy record — try fromLegacyJSON().`,
    );
  }

  /**
   * A .mjkb payload's `ca` names a compression algorithm that isn't the
   * built-in zstd codec and wasn't found in the `compressors` array passed
   * to the decrypt call. Distinct from decompressionFailed(), which is for
   * a *recognised* codec's decompress() call itself throwing — this is
   * "I don't even know what codec to try."
   */
  static unsupportedCompressionAlg(alg: string): MajikFileError {
    return new MajikFileError(
      "UNSUPPORTED_COMPRESSION_ALG",
      `Unsupported compression algorithm: "${alg}". ` +
        `No matching CompressionCodec was found in the "compressors" option ` +
        `passed to this decrypt call.`,
    );
  }

  /** Thrown when an automatic or explicit legacy → current migration fails. */
  static legacyMigrationFailed(cause?: unknown): MajikFileError {
    return new MajikFileError(
      "LEGACY_MIGRATION_FAILED",
      "Failed to migrate a legacy MajikFile record to the current schema",
      cause,
    );
  }

  /**
   * Generic "the storage key doesn't match this record's declared storage
   * class" error. Deliberately platform-neutral (not R2-specific) so any
   * MajikFile subclass targeting a different storage backend can reuse it.
   */
  static storageKeyMismatch(message: string): MajikFileError {
    return new MajikFileError("STORAGE_KEY_MISMATCH", message);
  }
}

// Freeze static and instance methods
Object.freeze(MajikFileError);
Object.freeze(MajikFileError.prototype);
