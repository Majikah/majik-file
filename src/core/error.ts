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
  | "UNSUPPORTED_VERSION";

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
      `Unsupported .mjkb version: ${version}. Only v${supported} is supported.`,
    );
  }
}
