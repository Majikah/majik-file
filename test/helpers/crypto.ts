// test/helpers/crypto.ts
import { MajikKey } from "@majikah/majik-key";

/**
 * Generates a fresh, fully-upgraded, and UNLOCKED MajikKey for testing.
 * Uses a 128-bit mnemonic for faster test execution.
 */
export async function getTestKey(): Promise<MajikKey> {
  // Return a pre-seeded or quickly generated key for testing

  const testPassphrase = "test_passphrase";

  const generatedMnemonic = await MajikKey.generateMnemonic();
  console.log("Creating Test Keys");

  const key = await MajikKey.create(
    generatedMnemonic,
    testPassphrase,
    "Test Account",
  );
  console.log("[majik-key] Issuer Key Created", key.fingerprint);

  return key;
}
