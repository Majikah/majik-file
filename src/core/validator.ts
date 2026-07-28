/**
 * majik-file-validator.ts
 *
 * Centralised validation rules for the base MajikFile.
 *
 * Every rule is implemented exactly once as a `checkX(...)` function that
 * returns an error message string, or `null` when the input is valid.
 * Two consumption modes build on top of that single source of truth so
 * the rule itself never has to be written twice:
 *
 *   - `checkX(...)`  → returns the message for the caller to collect into
 *                       an `errors: string[]` array. Used by `validate()`,
 *                       which gathers every problem before throwing once.
 *   - `assertX(...)` → throws immediately via MajikFileError. Used by
 *                       `create()` / mutators that should fail fast on the
 *                       first bad input, matching the original SDK's
 *                       assertValidMlKemPublicKey()-style call sites.
 *
 * MajikMessageFileValidator (sibling file) follows the exact same pattern
 * for platform-specific rules (context, storage type, R2 key shape, etc).
 */

import { MajikFileError } from "./error";
import {
  ML_KEM_PK_LEN,
  ML_KEM_SK_LEN,
  FILE_SCHEMA_VERSION,
} from "./crypto/constants";

export class MajikFileValidator {
  // ── Aggregation helper ──────────────────────────────────────────────────

  /** Throws a single VALIDATION_ERROR if `errors` is non-empty. No-op otherwise. */
  static assertAll(errors: string[]): void {
    if (errors.length > 0) throw MajikFileError.validationFailed(errors);
  }

  // ── id / userId / hash / iv ─────────────────────────────────────────────

  static checkId(id: string | null | undefined): string | null {
    return id?.trim() ? null : "id is required";
  }
  static assertId(id: string | null | undefined): void {
    const err = this.checkId(id);
    if (err) throw MajikFileError.invalidInput(err);
  }

  static checkUserId(userId: string | null | undefined): string | null {
    return userId?.trim() ? null : "userId is required";
  }
  static assertUserId(userId: string | null | undefined): void {
    const err = this.checkUserId(userId);
    if (err) throw MajikFileError.invalidInput(err);
  }

  static checkFileHash(hash: string | null | undefined): string | null {
    return hash?.trim() ? null : "file_hash is required";
  }

  static checkEncryptionIv(iv: string | null | undefined): string | null {
    return iv?.trim() ? null : "encryption_iv is required";
  }

  // ── sizes ──────────────────────────────────────────────────────────────

  static checkNonNegativeSize(size: number, fieldName: string): string | null {
    return typeof size === "number" && size >= 0
      ? null
      : `${fieldName} must be a non-negative number`;
  }

  /** Non-throwing check — for use inside validate()'s error-collection pass. */
  static checkSizeWithinLimit(
    byteLength: number,
    limit: number,
    bypass: boolean,
  ): string | null {
    if (bypass) return null;
    return byteLength > limit
      ? `size ${byteLength} bytes exceeds the ${limit}-byte limit`
      : null;
  }

  /** Throwing variant — used at create() time, mirrors original sizeExceeded() semantics. */
  static assertSizeWithinLimit(
    byteLength: number,
    limit: number,
    bypass: boolean,
  ): void {
    if (bypass) return;
    if (byteLength > limit)
      throw MajikFileError.sizeExceeded(byteLength, limit);
  }

  static assertNonEmptyData(byteLength: number): void {
    if (byteLength === 0) {
      throw MajikFileError.invalidInput("data must not be empty");
    }
  }

  // ── ML-KEM key shapes ────────────────────────────────────────────────────

  static checkMlKemPublicKey(
    pk: Uint8Array | null | undefined,
    fieldName: string,
  ): string | null {
    if (!(pk instanceof Uint8Array) || pk.length !== ML_KEM_PK_LEN) {
      return `${fieldName} must be a ${ML_KEM_PK_LEN}-byte Uint8Array (got ${
        (pk as { length?: number } | null | undefined)?.length ?? typeof pk
      })`;
    }
    return null;
  }
  static assertMlKemPublicKey(
    pk: Uint8Array | null | undefined,
    fieldName: string,
  ): void {
    const err = this.checkMlKemPublicKey(pk, fieldName);
    if (err) throw MajikFileError.invalidInput(err);
  }

  static checkMlKemSecretKey(
    sk: Uint8Array | null | undefined,
    fieldName: string,
  ): string | null {
    if (!(sk instanceof Uint8Array) || sk.length !== ML_KEM_SK_LEN) {
      return `${fieldName} must be ${ML_KEM_SK_LEN} bytes (got ${sk?.length ?? "undefined"})`;
    }
    return null;
  }
  static assertMlKemSecretKey(
    sk: Uint8Array | null | undefined,
    fieldName: string,
  ): void {
    const err = this.checkMlKemSecretKey(sk, fieldName);
    if (err) throw MajikFileError.invalidInput(err);
  }

  // ── recipients ────────────────────────────────────────────────────────

  static checkRecipientLimit(count: number, max: number): string | null {
    return count > max
      ? `recipient count ${count} exceeds the maximum of ${max}`
      : null;
  }
  static assertRecipientLimit(count: number, max: number): void {
    const err = this.checkRecipientLimit(count, max);
    if (err) throw MajikFileError.invalidInput(err);
  }

  // ── schema version ───────────────────────────────────────────────────────

  /**
   * `undefined` is deliberately treated as valid here — an absent
   * schema_version means "legacy record," which is a migration concern
   * handled by fromJSON()/fromLegacyJSON(), not a validation failure.
   */
  static checkSchemaVersion(
    version: number | undefined,
    supportedMax: number = FILE_SCHEMA_VERSION,
  ): string | null {
    if (version === undefined) return null;
    return version > supportedMax
      ? `schema_version ${version} is newer than this SDK supports (max ${supportedMax})`
      : null;
  }
  static assertSchemaVersion(
    version: number | undefined,
    supportedMax: number = FILE_SCHEMA_VERSION,
  ): void {
    if (version !== undefined && version > supportedMax) {
      throw MajikFileError.unsupportedSchemaVersion(version, supportedMax);
    }
  }

  // ── shared primitive, reused by MajikMessageFileValidator ────────────────

  static checkMutuallyExclusive(
    a: unknown,
    b: unknown,
    labelA: string,
    labelB: string,
  ): string | null {
    return a && b ? `${labelA} and ${labelB} cannot both be set` : null;
  }
}
