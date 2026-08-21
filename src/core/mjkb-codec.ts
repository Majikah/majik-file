/**
 * core/utils/mjkb-codec.ts
 *
 * Encode/decode for the .mjkb binary format, plus AES key recovery from a
 * decoded payload. Deliberately separate from base-utils.ts — this is the
 * one module that understands the binary's byte layout, kept isolated so
 * a future format change touches exactly one file.
 *
 * Version-aware: decodeMjkb() reads whatever version is on the wire (v1
 * legacy or v2 current) and hands back the raw payload shape unmodified —
 * it does NOT decide compression policy. That decision (reading the v2 `z`
 * flag, or falling back to shouldCompressMime() for v1) belongs to
 * MajikFile._decryptCore(), keeping this module a pure structural codec.
 */

import {
  IV_LENGTH,
  MJKB_VERSION,
  MJKB_SUPPORTED_VERSIONS,
} from "./crypto/constants";
import { MajikFileError } from "./error";
import { mlKemDecapsulate } from "./crypto/crypto-provider";
import { withZeroize } from "./crypto/zeroize";
import { arrayToBase64, base64ToArray } from "./utils";

import type {
  AnyMjkbPayload,
  MjkbPayload,
  DecodedMjkb,
  MajikFileGroupKey,
  MjkbPayloadV2,
} from "./types";

export const MJKB_MAGIC = [0x4d, 0x4a, 0x4b, 0x42]; // "MJKB"

export function isMjkbGroupPayload<T extends AnyMjkbPayload>(
  p: T,
): p is Extract<T, { keys: MajikFileGroupKey[] }> {
  return "keys" in p && Array.isArray((p as { keys: unknown }).keys);
}

export function isMjkbSinglePayload<T extends AnyMjkbPayload>(
  p: T,
): p is Exclude<T, { keys: MajikFileGroupKey[] }> {
  return "mlKemCipherText" in p && !("keys" in p);
}

/** True if this payload is the v2 shape (has the explicit compression flag). */
export function hasCompressionFlag(p: AnyMjkbPayload): p is MjkbPayloadV2 {
  return "z" in p;
}

// ─── Encode ───────────────────────────────────────────────────────────────────

/**
 * Encode a .mjkb binary. Always writes the current MJKB_VERSION — encoding
 * an old (v1) payload shape is not supported; v1 only ever appears when
 * *reading* pre-existing binaries.
 */
export function encodeMjkb(
  iv: Uint8Array,
  payload: MjkbPayload,
  ciphertext: Uint8Array,
): Uint8Array {
  if (iv.length !== IV_LENGTH) {
    throw MajikFileError.invalidInput(
      `encodeMjkb: iv must be ${IV_LENGTH} bytes (got ${iv.length})`,
    );
  }

  const payloadJson = new TextEncoder().encode(JSON.stringify(payload));
  const headerLen = MJKB_MAGIC.length + 1 + IV_LENGTH + 4;
  const out = new Uint8Array(
    headerLen + payloadJson.length + ciphertext.length,
  );

  out.set(MJKB_MAGIC, 0);
  out[MJKB_MAGIC.length] = MJKB_VERSION;
  out.set(iv, MJKB_MAGIC.length + 1);

  const lenOffset = MJKB_MAGIC.length + 1 + IV_LENGTH;
  out[lenOffset] = (payloadJson.length >>> 24) & 0xff;
  out[lenOffset + 1] = (payloadJson.length >>> 16) & 0xff;
  out[lenOffset + 2] = (payloadJson.length >>> 8) & 0xff;
  out[lenOffset + 3] = payloadJson.length & 0xff;

  out.set(payloadJson, headerLen);
  out.set(ciphertext, headerLen + payloadJson.length);
  return out;
}

// ─── Decode ───────────────────────────────────────────────────────────────────

export function decodeMjkb(raw: Uint8Array): DecodedMjkb {
  const headerLen = MJKB_MAGIC.length + 1 + IV_LENGTH + 4; // 21 for a 12-byte IV
  if (raw.length < headerLen + 2) {
    // +2 == at least 1 byte of payload JSON + 1 byte of ciphertext
    throw MajikFileError.formatError(
      "Malformed .mjkb: too short to contain a valid header",
    );
  }

  for (let i = 0; i < MJKB_MAGIC.length; i++) {
    if (raw[i] !== MJKB_MAGIC[i]) {
      throw MajikFileError.formatError(
        'Malformed .mjkb: missing "MJKB" magic bytes',
      );
    }
  }

  const version = raw[MJKB_MAGIC.length];
  if (!(MJKB_SUPPORTED_VERSIONS as readonly number[]).includes(version)) {
    throw MajikFileError.unsupportedVersion(version, MJKB_VERSION);
  }

  const iv = raw.slice(
    MJKB_MAGIC.length + 1,
    MJKB_MAGIC.length + 1 + IV_LENGTH,
  );

  const lenOffset = MJKB_MAGIC.length + 1 + IV_LENGTH;
  const payloadLen =
    (raw[lenOffset] << 24) |
    (raw[lenOffset + 1] << 16) |
    (raw[lenOffset + 2] << 8) |
    raw[lenOffset + 3];

  if (payloadLen <= 0) {
    throw MajikFileError.formatError("Malformed .mjkb: invalid payload length");
  }

  const payloadStart = lenOffset + 4;
  const ciphertextStart = payloadStart + payloadLen;
  if (ciphertextStart > raw.length) {
    throw MajikFileError.formatError(
      "Malformed .mjkb: declared payload length exceeds buffer",
    );
  }

  let payload: AnyMjkbPayload;
  try {
    payload = JSON.parse(
      new TextDecoder().decode(raw.slice(payloadStart, ciphertextStart)),
    );
  } catch {
    throw MajikFileError.formatError(
      "Malformed .mjkb: payload JSON failed to parse",
    );
  }

  const ciphertext = raw.slice(ciphertextStart);
  if (ciphertext.length === 0) {
    throw MajikFileError.formatError(
      "Malformed .mjkb: empty ciphertext section",
    );
  }

  return { version, iv, ciphertext, payload };
}

// ─── AES key recovery ───────────────────────────────────────────────────────

/**
 * Recover the AES-256-GCM key from a decoded payload for the given
 * identity — single-recipient (sharedSecret used directly) or group
 * (XOR-unwrap using this recipient's key entry).
 *
 * Zeroization: in the group path, the intermediate `sharedSecret` is
 * wiped immediately after the XOR-unwrap via withZeroize() — it's pure
 * scratch material once the AES key is derived. In the single path, the
 * returned value *is* the shared secret directly (no intermediate to
 * wipe here) — the caller (MajikFile._decryptCore) owns zeroizing it
 * once AES-GCM has consumed it.
 *
 * @throws MajikFileError if the payload shape is unrecognised, or (group
 *         mode) if no key entry matches the given fingerprint.
 */
export function resolveAesKeyFromPayload(
  payload: AnyMjkbPayload,
  identity: { fingerprint: string; mlKemSecretKey: Uint8Array },
): Uint8Array {
  if (isMjkbSinglePayload(payload)) {
    const cipherText = base64ToArray(payload.mlKemCipherText);
    return mlKemDecapsulate(cipherText, identity.mlKemSecretKey);
  }

  if (isMjkbGroupPayload(payload)) {
    const entry = payload.keys.find(
      (k) => k.fingerprint === identity.fingerprint,
    );
    if (!entry) {
      throw MajikFileError.decryptionFailed(
        `No key entry found for fingerprint "${identity.fingerprint}" — this identity is not a participant of this file`,
      );
    }

    const cipherText = base64ToArray(entry.mlKemCipherText);
    const encryptedAesKey = base64ToArray(entry.encryptedAesKey);
    const sharedSecret = mlKemDecapsulate(cipherText, identity.mlKemSecretKey);

    return withZeroize([sharedSecret], () => {
      const aesKey = new Uint8Array(encryptedAesKey.length);
      for (let i = 0; i < aesKey.length; i++) {
        aesKey[i] = encryptedAesKey[i] ^ sharedSecret[i];
      }
      return aesKey;
    });
  }

  throw MajikFileError.formatError(
    "Malformed .mjkb payload: neither single- nor group-recipient shape recognised",
  );
}

// Re-exported for callers that only need base64 helpers alongside the codec.
export { arrayToBase64, base64ToArray };
