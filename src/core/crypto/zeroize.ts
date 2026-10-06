/**
 * zeroize.ts
 *
 * Best-effort secure memory wiping for sensitive byte buffers: ML-KEM
 * shared secrets, derived AES keys, XOR scratch buffers, and the
 * decrypted-plaintext cache MajikFile keeps at runtime.
 *
 * IMPORTANT — honest limitations: JavaScript gives no hard guarantee that
 * a Uint8Array isn't copied elsewhere by the engine (JIT, GC compaction,
 * a structured-clone across a worker boundary, etc.) before you get a
 * chance to wipe it. This is defense-in-depth, not a cryptographic
 * guarantee — it closes the realistic window where plaintext/key material
 * sits reachable in memory indefinitely after MajikFile is done with it.
 *
 * Ownership rule (see MajikFile._encryptCore / _decryptCore in majik-file.ts):
 * only zeroize buffers *allocated by MajikFile itself* — derived shared
 * secrets, derived/random AES keys, scratch XOR buffers, the `_decrypted`
 * cache. NEVER zeroize a caller-supplied secret key (e.g.
 * MajikKey.mlKemSecretKey) — that buffer is owned and lifecycle-managed by
 * the caller, and MajikFile has no business mutating it.
 */

/**
 * Overwrite a buffer's contents in place with zeros.
 * Safe to call on undefined/null/empty buffers (no-op).
 */
export function secureFill(buf: Uint8Array | null | undefined): void {
  if (!buf || buf.length === 0) return;
  buf.fill(0);
}

/**
 * Zeroize multiple buffers in one call. Skips any nullish entries.
 */
export function secureFillMany(
  ...bufs: Array<Uint8Array | null | undefined>
): void {
  for (const buf of bufs) secureFill(buf);
}

/**
 * Run `fn`, then guarantee the listed buffers are zeroized afterward —
 * whether `fn` succeeds or throws. Wrap any block that allocates a derived
 * secret with this so cleanup can never be skipped by an early return or
 * an unexpected throw (e.g. AES-GCM auth failure mid-decrypt).
 *
 * @example
 * const { sharedSecret, cipherText } = mlKemEncapsulate(pk);
 * const ciphertext = withZeroize([sharedSecret], () =>
 *   aesGcmEncrypt(sharedSecret, iv, compressed),
 * );
 */
export function withZeroize<T>(
  bufs: Array<Uint8Array | null | undefined>,
  fn: () => T,
): T {
  try {
    return fn();
  } finally {
    secureFillMany(...bufs);
  }
}
