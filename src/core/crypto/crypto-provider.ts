/**
 * crypto-provider.ts
 *
 * Encryption engine for MajikFile.
 * Provides AES-256-GCM and ML-KEM-768 (FIPS-203) primitives.
 *
 * All operations are synchronous except where noted.
 * Random bytes are sourced from crypto.getRandomValues().
 */

import { AES } from "@stablelib/aes";
import { GCM } from "@stablelib/gcm";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import {
  IV_LENGTH,
  AES_KEY_LEN,
  ML_KEM_PK_LEN,
  ML_KEM_SK_LEN,
  ML_KEM_CT_LEN,
} from "./constants";
import { MajikFileError } from "../error";

export { IV_LENGTH, AES_KEY_LEN };

// ─── Random ───────────────────────────────────────────────────────────────────

/**
 * Generate cryptographically random bytes using the Web Crypto API.
 * @param len Number of bytes to generate.
 */
export function generateRandomBytes(len: number): Uint8Array {
  if (len <= 0 || !Number.isInteger(len)) {
    throw MajikFileError.invalidInput(
      `generateRandomBytes: len must be a positive integer (got ${len})`,
    );
  }
  const buf = new Uint8Array(len);
  crypto.getRandomValues(buf);
  return buf;
}

// ─── AES-256-GCM ─────────────────────────────────────────────────────────────

/**
 * Encrypt plaintext bytes with AES-256-GCM.
 *
 * @param keyBytes  32-byte AES key.
 * @param iv        12-byte IV / nonce.
 * @param plaintext Arbitrary-length plaintext.
 * @returns         Ciphertext with 16-byte GCM authentication tag appended.
 */
export function aesGcmEncrypt(
  keyBytes: Uint8Array,
  iv: Uint8Array,
  plaintext: Uint8Array,
): Uint8Array {
  if (keyBytes.length !== AES_KEY_LEN) {
    throw MajikFileError.invalidInput(
      `aesGcmEncrypt: key must be ${AES_KEY_LEN} bytes (got ${keyBytes.length})`,
    );
  }
  if (iv.length !== IV_LENGTH) {
    throw MajikFileError.invalidInput(
      `aesGcmEncrypt: iv must be ${IV_LENGTH} bytes (got ${iv.length})`,
    );
  }
  const aes = new AES(keyBytes);
  const gcm = new GCM(aes);
  return gcm.seal(iv, plaintext);
}

/**
 * Decrypt AES-256-GCM ciphertext.
 *
 * @param keyBytes   32-byte AES key.
 * @param iv         12-byte IV / nonce.
 * @param ciphertext Ciphertext with 16-byte GCM authentication tag.
 * @returns          Decrypted plaintext, or null if authentication fails.
 */
export function aesGcmDecrypt(
  keyBytes: Uint8Array,
  iv: Uint8Array,
  ciphertext: Uint8Array,
): Uint8Array | null {
  if (keyBytes.length !== AES_KEY_LEN) {
    throw MajikFileError.invalidInput(
      `aesGcmDecrypt: key must be ${AES_KEY_LEN} bytes (got ${keyBytes.length})`,
    );
  }
  if (iv.length !== IV_LENGTH) {
    throw MajikFileError.invalidInput(
      `aesGcmDecrypt: iv must be ${IV_LENGTH} bytes (got ${iv.length})`,
    );
  }
  const aes = new AES(keyBytes);
  const gcm = new GCM(aes);
  return gcm.open(iv, ciphertext);
}

// ─── ML-KEM-768 ───────────────────────────────────────────────────────────────

/**
 * ML-KEM-768 key encapsulation.
 *
 * The sender calls this with the recipient's public key.
 * Returns a 32-byte shared secret (used as the AES-256-GCM key)
 * and a 1088-byte ciphertext that is stored in the .mjkb binary.
 *
 * Only the holder of the corresponding secret key can recover the
 * shared secret via mlKemDecapsulate().
 *
 * @param recipientPublicKey  ML-KEM-768 public key (1184 bytes).
 * @returns { sharedSecret: 32 bytes, cipherText: 1088 bytes }
 */
export function mlKemEncapsulate(recipientPublicKey: Uint8Array): {
  sharedSecret: Uint8Array;
  cipherText: Uint8Array;
} {
  if (recipientPublicKey.length !== ML_KEM_PK_LEN) {
    throw MajikFileError.invalidInput(
      `mlKemEncapsulate: public key must be ${ML_KEM_PK_LEN} bytes (got ${recipientPublicKey.length})`,
    );
  }
  return ml_kem768.encapsulate(recipientPublicKey);
}

/**
 * ML-KEM-768 key decapsulation.
 *
 * IMPORTANT: ML-KEM decapsulation NEVER throws on a wrong key — it returns
 * a different (useless) shared secret. The AES-GCM authentication tag will
 * catch this, causing aesGcmDecrypt() to return null.
 *
 * @param cipherText         ML-KEM-768 ciphertext from encapsulation (1088 bytes).
 * @param recipientSecretKey ML-KEM-768 secret key (2400 bytes).
 * @returns 32-byte shared secret.
 */
export function mlKemDecapsulate(
  cipherText: Uint8Array,
  recipientSecretKey: Uint8Array,
): Uint8Array {
  if (cipherText.length !== ML_KEM_CT_LEN) {
    throw MajikFileError.invalidInput(
      `mlKemDecapsulate: cipherText must be ${ML_KEM_CT_LEN} bytes (got ${cipherText.length})`,
    );
  }
  if (recipientSecretKey.length !== ML_KEM_SK_LEN) {
    throw MajikFileError.invalidInput(
      `mlKemDecapsulate: secret key must be ${ML_KEM_SK_LEN} bytes (got ${recipientSecretKey.length})`,
    );
  }
  return ml_kem768.decapsulate(cipherText, recipientSecretKey);
}

/**
 * Generate a random ML-KEM-768 keypair.
 * Intended for testing only.
 * Production identities must use deriveMlKemKeypairFromSeed() from a BIP-39 mnemonic.
 */
export function generateMlKemKeypair(): {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
} {
  return ml_kem768.keygen();
}
