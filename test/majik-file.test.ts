// majik-file.test.ts
//
// Refactored unit tests for the platform-agnostic MajikFile class.
// Exercises post-quantum cryptography (ML-KEM-768), AES-256-GCM, and
// @majikah/majik-signature implementations directly without mocking crypto logic.

import {
  describe,
  it,
  expect,
  beforeAll,
  beforeEach,
  afterEach,
  vi,
} from "vitest";
import { MajikFile } from "../src/majik-file";
import { MajikFileError } from "../src/core/error";

import {
  isMjkbGroupPayload,
  isMjkbSinglePayload,
} from "../src/core/mjkb-codec";
import type {
  MajikFileIdentity,
  MajikFileRecipient,
  MajikFileJSON,
} from "../src/core/types";
import {
  ML_KEM_PK_LEN,
  ML_KEM_SK_LEN,
  MAX_FILE_SIZE_BYTES,
  MJKB_VERSION,
  FILE_SCHEMA_VERSION,
} from "../src/core/crypto/constants";
import type { MajikKey } from "@majikah/majik-key";
import { type MajikSignerPublicKeys } from "@majikah/majik-signature";
import { getTestKey } from "./helpers/crypto";
import { decodeMjkb } from "../src/core/mjkb-codec";

const CRYPTO_TIMEOUT = 60_000;

// ── TEST HELPERS ─────────────────────────────────────────────────────────────

interface TestFileUser {
  identity: MajikFileIdentity;
  recipient: MajikFileRecipient;
}

/** Generates real ML-KEM-768 identities and recipients matching base types */
async function createTestFileUser(): Promise<TestFileUser> {
  const keys = await getTestKey();
  const publicKey = keys.publicKeyBase64;
  const fingerprint = keys.fingerprint;

  return {
    identity: {
      publicKey,
      fingerprint,
      mlKemPublicKey: keys.mlKemPublicKey,
      mlKemSecretKey: keys.mlKemSecretKey!,
    },
    recipient: {
      fingerprint,
      publicKey,
      mlKemPublicKey: keys.mlKemPublicKey,
    },
  };
}

const DUMMY_DATA = new TextEncoder().encode(
  "Hello, post-quantum cloud storage! This binary content is encrypted.",
);
const USER_ID = "auth-user-alice-uuid-12345";

// ── TEST SUITE ───────────────────────────────────────────────────────────────

describe("MajikFile Class Unit Tests", () => {
  let alice: TestFileUser;
  let bob: TestFileUser;
  let charlie: TestFileUser;
  let signerKeyA: MajikKey;
  let signerKeyB: MajikKey;

  beforeAll(async () => {
    [alice, bob, charlie, signerKeyA, signerKeyB] = await Promise.all([
      createTestFileUser(),
      createTestFileUser(),
      createTestFileUser(),
      getTestKey(),
      getTestKey(),
    ]);
  }, CRYPTO_TIMEOUT * 5);

  function signerKey(which: "A" | "B" = "A"): MajikKey {
    return which === "A" ? signerKeyA : signerKeyB;
  }

  function signerPublicKeys(which: "A" | "B" = "A"): MajikSignerPublicKeys {
    const key = signerKey(which);
    return {
      edPublicKey: (key as any).edPublicKey,
      mlDsaPublicKey: (key as any).mlDsaPublicKey,
      signerId: key.fingerprint,
    } as MajikSignerPublicKeys;
  }

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // ── 1. CREATE() INPUT VALIDATION ──────────────────────────────────────────
  describe("create() — input validation", () => {
    it("should reject when identity is missing", async () => {
      await expect(
        MajikFile.create({
          data: DUMMY_DATA,
          userId: USER_ID,
        } as any),
      ).rejects.toThrow(/identity is required/i);
    });

    it("should reject when userId is missing or blank", async () => {
      await expect(
        MajikFile.create({
          data: DUMMY_DATA,
          userId: "   ",
          identity: alice.identity,
        }),
      ).rejects.toThrow(/userId is required/i);
    });

    it("should reject when identity.fingerprint is missing", async () => {
      await expect(
        MajikFile.create({
          data: DUMMY_DATA,
          userId: USER_ID,
          identity: { ...alice.identity, fingerprint: "" },
        }),
      ).rejects.toThrow(/identity\.fingerprint is required/i);
    });

    it("should reject identity with invalid mlKemPublicKey length", async () => {
      await expect(
        MajikFile.create({
          data: DUMMY_DATA,
          userId: USER_ID,
          identity: { ...alice.identity, mlKemPublicKey: new Uint8Array(10) },
        }),
      ).rejects.toThrow(/mlKemPublicKey must be a 1184-byte/i);
    });

    it("should reject empty/zero-byte file data", async () => {
      await expect(
        MajikFile.create({
          data: new Uint8Array(0),
          userId: USER_ID,
          identity: alice.identity,
        }),
      ).rejects.toThrow(/data must not be empty/i);
    });

    it("should reject creation if file size exceeds size limit", async () => {
      const oversizedData = new Uint8Array(MAX_FILE_SIZE_BYTES + 1);
      await expect(
        MajikFile.create({
          data: oversizedData,
          userId: USER_ID,
          identity: alice.identity,
          bypassSizeLimit: false,
        }),
      ).rejects.toThrow(/exceeds the.*limit/i);
    });

    it(
      "should allow oversized payloads when bypassSizeLimit is true",
      async () => {
        const oversizedData = new Uint8Array(MAX_FILE_SIZE_BYTES + 1);
        try {
          await MajikFile.create({
            data: oversizedData,
            userId: USER_ID,
            identity: alice.identity,
            bypassSizeLimit: true,
          });
        } catch (err: any) {
          expect(err.message).not.toMatch(/exceeds maximum allowed size/i);
        }
      },
      CRYPTO_TIMEOUT,
    );

    it("should reject a recipient with a missing fingerprint", async () => {
      await expect(
        MajikFile.create({
          data: DUMMY_DATA,
          userId: USER_ID,
          identity: alice.identity,
          recipients: [
            {
              fingerprint: "",
              publicKey: "x",
              mlKemPublicKey: new Uint8Array(ML_KEM_PK_LEN),
            },
          ],
        }),
      ).rejects.toThrow(/recipients\[0\]\.fingerprint is required/i);
    });

    it("should reject recipients with invalid ML-KEM public key lengths", async () => {
      const invalidRecipient: MajikFileRecipient = {
        fingerprint: "bad-fp",
        publicKey: "bad-pub",
        mlKemPublicKey: new Uint8Array(32),
      };

      await expect(
        MajikFile.create({
          data: DUMMY_DATA,
          userId: USER_ID,
          identity: alice.identity,
          recipients: [invalidRecipient],
        }),
      ).rejects.toThrow(/mlKemPublicKey must be a 1184-byte/i);
    });
  });

  // ── 2. SINGLE RECIPIENT (SELF-ENCRYPTION) ───────────────────────────────
  describe("Single recipient (self-encryption)", () => {
    let singleFile: MajikFile;

    it(
      "should correctly encrypt a file for a single owner recipient",
      async () => {
        singleFile = await MajikFile.create({
          data: DUMMY_DATA,
          userId: USER_ID,
          identity: alice.identity,
          originalName: "secure-report.pdf",
          mimeType: "application/pdf",
        });

        expect(singleFile).toBeInstanceOf(MajikFile);
        expect(singleFile.kind).toBe("file");
        expect(singleFile.isSingle).toBe(true);
        expect(singleFile.isGroup).toBe(false);
        expect(singleFile.hasBinary).toBe(true);

        const bytes = singleFile.toBinaryBytes();
        expect(bytes[4]).toBe(MJKB_VERSION);

        const { payload } = decodeMjkb(bytes);
        expect(isMjkbSinglePayload(payload)).toBe(true);
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "should decrypt via the static decrypt() using raw bytes",
      async () => {
        const decrypted = await MajikFile.decrypt(
          singleFile.toBinaryBytes(),
          alice.identity,
        );
        expect(new TextDecoder().decode(decrypted)).toBe(
          "Hello, post-quantum cloud storage! This binary content is encrypted.",
        );
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "should decrypt via the static decrypt() using a Blob (toMJKB())",
      async () => {
        const blob = singleFile.toMJKB();
        expect(blob).toBeInstanceOf(Blob);
        const decrypted = await MajikFile.decrypt(blob, alice.identity);
        expect(new TextDecoder().decode(decrypted)).toBe(
          "Hello, post-quantum cloud storage! This binary content is encrypted.",
        );
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "should decrypt via instance decryptBinary() method",
      async () => {
        const decrypted = await singleFile.decryptBinary(alice.identity);
        expect(new TextDecoder().decode(decrypted)).toBe(
          "Hello, post-quantum cloud storage! This binary content is encrypted.",
        );
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "should decryptWithMetadata() and return null signature when unsigned",
      async () => {
        const result = await singleFile.decryptWithMetadata(alice.identity);
        expect(new TextDecoder().decode(result.bytes)).toBe(
          "Hello, post-quantum cloud storage! This binary content is encrypted.",
        );
        expect(result.originalName).toBe("secure-report.pdf");
        expect(result.mimeType).toBe("application/pdf");
        expect(result.signature).toBeNull();
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "should fail to decrypt with an unauthorized identity",
      async () => {
        await expect(singleFile.decryptBinary(bob.identity)).rejects.toThrow(
          MajikFileError,
        );
      },
      CRYPTO_TIMEOUT,
    );

    it("should reject decrypt() with a malformed mlKemSecretKey length", async () => {
      await expect(
        MajikFile.decrypt(singleFile.toBinaryBytes(), {
          fingerprint: alice.identity.fingerprint,
          mlKemSecretKey: new Uint8Array(5),
        }),
      ).rejects.toThrow(new RegExp(`must be ${ML_KEM_SK_LEN} bytes`, "i"));
    });

    it("decryptBinary() should throw missingBinary if binary was cleared", async () => {
      const cleared = await MajikFile.create({
        data: DUMMY_DATA,
        userId: USER_ID,
        identity: alice.identity,
      });
      cleared.clearBinary();
      expect(cleared.hasBinary).toBe(false);
      await expect(cleared.decryptBinary(alice.identity)).rejects.toThrow(
        MajikFileError,
      );
    });
  });

  // ── 3. MULTI-RECIPIENT / GROUP ENCRYPTION ────────────────────────────────
  describe("Multi-recipient (shared group file encryption)", () => {
    let groupFile: MajikFile;

    it(
      "should encrypt once and distribute key entries to every recipient",
      async () => {
        groupFile = await MajikFile.create({
          data: DUMMY_DATA,
          userId: USER_ID,
          identity: alice.identity,
          recipients: [bob.recipient],
          originalName: "shared-photo.png",
          mimeType: "image/png",
        });

        expect(groupFile.isSingle).toBe(false);
        expect(groupFile.isGroup).toBe(true);

        const { payload } = decodeMjkb(groupFile.toBinaryBytes());
        expect(isMjkbGroupPayload(payload)).toBe(true);

        if (isMjkbGroupPayload(payload)) {
          expect(payload.keys).toHaveLength(2); // owner + bob
        }

        expect(groupFile.participants).toEqual([
          alice.identity.publicKey,
          bob.recipient.publicKey,
        ]);
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "should decrypt successfully for the owner (Alice)",
      async () => {
        const decrypted = await groupFile.decryptBinary(alice.identity);
        expect(new TextDecoder().decode(decrypted)).toBe(
          "Hello, post-quantum cloud storage! This binary content is encrypted.",
        );
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "should decrypt successfully for the designated member (Bob)",
      async () => {
        const decrypted = await groupFile.decryptBinary(bob.identity);
        expect(new TextDecoder().decode(decrypted)).toBe(
          "Hello, post-quantum cloud storage! This binary content is encrypted.",
        );
      },
      CRYPTO_TIMEOUT,
    );

    it("should throw if an unlisted recipient attempts decryption", async () => {
      await expect(groupFile.decryptBinary(charlie.identity)).rejects.toThrow(
        /No key entry found for fingerprint/i,
      );
    });

    it(
      "should treat owner's key in recipients as a no-op",
      async () => {
        const selfListed = await MajikFile.create({
          data: DUMMY_DATA,
          userId: USER_ID,
          identity: alice.identity,
          recipients: [
            {
              fingerprint: alice.identity.fingerprint,
              publicKey: alice.identity.publicKey,
              mlKemPublicKey: alice.identity.mlKemPublicKey,
            },
          ],
        });
        expect(selfListed.isSingle).toBe(true);
        expect(selfListed.isGroup).toBe(false);
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "should deduplicate recipients listed more than once",
      async () => {
        const dupeListed = await MajikFile.create({
          data: DUMMY_DATA,
          userId: USER_ID,
          identity: alice.identity,
          recipients: [bob.recipient, bob.recipient],
        });

        expect(dupeListed.isGroup).toBe(true);
        expect(dupeListed.participants).toHaveLength(2);

        const decrypted = await dupeListed.decryptBinary(bob.identity);
        expect(new TextDecoder().decode(decrypted)).toBe(
          "Hello, post-quantum cloud storage! This binary content is encrypted.",
        );
      },
      CRYPTO_TIMEOUT,
    );
  });

  // ── 4. CREATE AND SIGN ───────────────────────────────────────────────────
  describe("createAndSign()", () => {
    it(
      "should encrypt and attach a signature in one call",
      async () => {
        const file = await MajikFile.createAndSign(
          {
            data: DUMMY_DATA,
            userId: USER_ID,
            identity: alice.identity,
          },
          signerKey(),
        );
        expect(file.isSigned).toBe(true);
        expect(file.hasBinary).toBe(true);
      },
      CRYPTO_TIMEOUT,
    );
  });

  // ── 5. BINARY FORMAT & STRUCTURAL CHECKS ────────────────────────────────
  describe("Binary format (.mjkb) structural checks", () => {
    let file: MajikFile;

    beforeAll(async () => {
      file = await MajikFile.create({
        data: DUMMY_DATA,
        userId: USER_ID,
        identity: alice.identity,
        originalName: "backup-archive.zip",
        mimeType: "application/zip",
      });
    }, CRYPTO_TIMEOUT);

    it("toMJKB() and toBinaryBytes() should produce equivalent bytes", async () => {
      const bytes = file.toBinaryBytes();
      const blob = file.toMJKB();
      const fromBlob = new Uint8Array(await blob.arrayBuffer());
      expect(fromBlob).toEqual(bytes);
    });

    it("toBinaryBytes()/toMJKB() should throw missingBinary if cleared", async () => {
      const f2 = await MajikFile.create({
        data: DUMMY_DATA,
        userId: USER_ID,
        identity: alice.identity,
      });
      f2.clearBinary();
      expect(() => f2.toBinaryBytes()).toThrow(MajikFileError);
      expect(() => f2.toMJKB()).toThrow(MajikFileError);
    });

    it("isMjkbCandidate() should validate magic bytes correctly", () => {
      expect(MajikFile.isMjkbCandidate(file.toBinaryBytes())).toBe(true);
      expect(MajikFile.isMjkbCandidate(new Uint8Array([1, 2, 3]))).toBe(false);
      expect(
        MajikFile.isMjkbCandidate(new Uint8Array([0x4d, 0x4a, 0x4b, 0x00, 0])),
      ).toBe(false);
    });

    it("isValidMJKB() should pass for real binaries and fail for corrupt ones", () => {
      expect(MajikFile.isValidMJKB(file.toBinaryBytes())).toBe(true);
      expect(MajikFile.isValidMJKB(new Uint8Array([1, 2, 3]))).toBe(false);

      const tampered = file.toBinaryBytes().slice();
      tampered[0] = 0x00; // corrupt magic
      expect(MajikFile.isValidMJKB(tampered)).toBe(false);

      const truncated = file.toBinaryBytes().slice(0, 10);
      expect(MajikFile.isValidMJKB(truncated)).toBe(false);
    });

    it("static decrypt() should throw on invalid magic bytes", async () => {
      const corrupt = new Uint8Array([
        99, 99, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17,
        18, 19, 20, 21, 22, 23, 24,
      ]);
      await expect(
        MajikFile.decrypt(corrupt, {
          fingerprint: alice.identity.fingerprint,
          mlKemSecretKey: alice.identity.mlKemSecretKey,
        }),
      ).rejects.toThrow(/missing "MJKB" magic bytes/i);
    });

    it("static decrypt() should throw on an unsupported version byte", async () => {
      const bytes = file.toBinaryBytes().slice();
      bytes[4] = 0xff; // unsupported version
      await expect(
        MajikFile.decrypt(bytes, {
          fingerprint: alice.identity.fingerprint,
          mlKemSecretKey: alice.identity.mlKemSecretKey,
        }),
      ).rejects.toThrow(MajikFileError);
    });

    it("static decrypt() should throw on a truncated payload section", async () => {
      const bytes = file.toBinaryBytes().slice(0, 25);
      await expect(
        MajikFile.decrypt(bytes, {
          fingerprint: alice.identity.fingerprint,
          mlKemSecretKey: alice.identity.mlKemSecretKey,
        }),
      ).rejects.toThrow(MajikFileError);
    });
  });

  // ── 6. SERIALIZATION (toJSON / fromJSON / toDangerousJSON) ───────────────
  describe("Serialization: toJSON(), toDangerousJSON(), fromJSON()", () => {
    let originalFile: MajikFile;

    beforeAll(async () => {
      originalFile = await MajikFile.create({
        data: DUMMY_DATA,
        userId: USER_ID,
        identity: alice.identity,
        originalName: "backup-archive.zip",
        mimeType: "application/zip",
      });
    }, CRYPTO_TIMEOUT);

    it("toJSON() should produce the expected plain object record shape", () => {
      const jsonOutput = originalFile.toJSON();

      expect(jsonOutput.id).toBeDefined();
      expect(jsonOutput.schema_version).toBe(FILE_SCHEMA_VERSION);
      expect(jsonOutput.kind).toBe("file");
      expect(jsonOutput.user_id).toBe(USER_ID);
      expect(jsonOutput.original_name).toBe("backup-archive.zip");
      expect(jsonOutput.mime_type).toBe("application/zip");
      expect(jsonOutput.size_original).toBe(DUMMY_DATA.byteLength);
      expect(jsonOutput.encryption_iv).toBeDefined();
      expect(jsonOutput.kem_alg).toBeDefined();
      expect(jsonOutput.cipher_alg).toBeDefined();
      expect(jsonOutput.signature).toBeNull();
    });

    it(
      "toDangerousJSON() should include base64 decrypted plaintext when hydrated",
      async () => {
        await originalFile.decryptHydrate(alice.identity);
        const dangerous = originalFile.toDangerousJSON();

        expect(dangerous.decrypted_base64).not.toBeNull();
        expect(typeof dangerous.decrypted_base64).toBe("string");

        originalFile.secureLock();
      },
      CRYPTO_TIMEOUT,
    );

    it("fromJSON() without a binary should restore a metadata-only instance", () => {
      const json = originalFile.toJSON();
      const restored = MajikFile.fromJSON(json);
      expect(restored).toBeInstanceOf(MajikFile);
      expect(restored.hasBinary).toBe(false);
      expect(restored.isGroup).toBe(false);
      expect(restored.toJSON().id).toBe(json.id);
    });

    it(
      "fromJSON() with binary should re-derive group vs single state",
      async () => {
        const singleJson = originalFile.toJSON();
        const singleRestored = MajikFile.fromJSON(
          singleJson,
          originalFile.toBinaryBytes(),
        );
        expect(singleRestored.isSingle).toBe(true);
        expect(singleRestored.hasBinary).toBe(true);

        const groupOriginal = await MajikFile.create({
          data: DUMMY_DATA,
          userId: USER_ID,
          identity: alice.identity,
          recipients: [bob.recipient],
        });
        const groupRestored = MajikFile.fromJSON(
          groupOriginal.toJSON(),
          groupOriginal.toBinaryBytes(),
        );
        expect(groupRestored.isGroup).toBe(true);

        const decrypted = await groupRestored.decryptBinary(bob.identity);
        expect(new TextDecoder().decode(decrypted)).toBe(
          "Hello, post-quantum cloud storage! This binary content is encrypted.",
        );
      },
      CRYPTO_TIMEOUT,
    );

    it("fromJSONWithBlob() should accept a Blob binary", async () => {
      const blob = originalFile.toMJKB();
      const restored = await MajikFile.fromJSONWithBlob(
        originalFile.toJSON(),
        blob,
      );
      expect(restored.hasBinary).toBe(true);
      const decrypted = await restored.decryptBinary(alice.identity);
      expect(new TextDecoder().decode(decrypted)).toBe(
        "Hello, post-quantum cloud storage! This binary content is encrypted.",
      );
    });

    it("fromJSON() should throw validation failure for an invalid record", () => {
      const badJson: MajikFileJSON = {
        ...originalFile.toJSON(),
        user_id: "",
      };
      expect(() => MajikFile.fromJSON(badJson)).toThrow(MajikFileError);
      expect(() => MajikFile.fromJSON(badJson)).toThrow(/userId is required/i);
    });

    it("fromJSON() should reject a non-object argument", () => {
      expect(() => MajikFile.fromJSON(null as any)).toThrow(
        /json must be a non-null object/i,
      );
    });
  });

  // ── 7. BATCH OPERATIONS & CACHING / LOCKING ──────────────────────────────
  describe("Batch operations, hydration, and zeroizing secure lock", () => {
    let file1: MajikFile;
    let file2: MajikFile;

    beforeEach(async () => {
      [file1, file2] = await Promise.all([
        MajikFile.create({
          data: DUMMY_DATA,
          userId: USER_ID,
          identity: alice.identity,
        }),
        MajikFile.create({
          data: DUMMY_DATA,
          userId: USER_ID,
          identity: alice.identity,
        }),
      ]);
    });

    it(
      "decryptHydrate() caches plaintext and secureLock() zeroizes it",
      async () => {
        expect(file1.hasDecryptedFile).toBe(false);
        expect(file1.decryptedFile).toBeUndefined();

        await file1.decryptHydrate(alice.identity);
        expect(file1.hasDecryptedFile).toBe(true);
        expect(file1.decryptedFile).toBeDefined();

        file1.secureLock();
        expect(file1.hasDecryptedFile).toBe(false);
        expect(file1.decryptedFile).toBeUndefined();
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "batchDecrypt() hydrates multiple files concurrently",
      async () => {
        // FIX: The files were encrypted with alice.identity, so we must decrypt
        // with Alice's identity, not the random signerKey("A").
        const key = alice.identity;

        const result = await MajikFile.batchDecrypt([file1, file2], key);

        expect(result.success).toBe(true);
        expect(result.decrypted).toHaveLength(2);
        expect(result.errors).toHaveLength(0);
        expect(file1.hasDecryptedFile).toBe(true);
        expect(file2.hasDecryptedFile).toBe(true);
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "batchLock() locks hydrated files and reports accurate stats",
      async () => {
        await file1.decryptHydrate(alice.identity);

        const lockResult = MajikFile.batchLock([file1, file2]);
        expect(lockResult.locked).toBe(1);
        expect(lockResult.skipped).toBe(1);
        expect(file1.hasDecryptedFile).toBe(false);
        expect(file2.hasDecryptedFile).toBe(false);
      },
      CRYPTO_TIMEOUT,
    );
  });

  // ── 8. MJKS SIGNED TRAILER ───────────────────────────────────────────────
  describe("Signed MJKB trailer (toSignedMJKB / verifySignedMJKB)", () => {
    let file: MajikFile;

    beforeAll(async () => {
      file = await MajikFile.create({
        data: DUMMY_DATA,
        userId: USER_ID,
        identity: alice.identity,
      });
    }, CRYPTO_TIMEOUT);

    it("toSignedMJKB() should throw if no signature is attached", () => {
      expect(() => file.toSignedMJKB()).toThrow(/no signature attached/i);
    });

    it(
      "toSignedMJKB() should append a recoverable MJKS trailer",
      async () => {
        const sig = await file.sign(signerKey());
        const signedBlob = file.toSignedMJKB();
        const signedBytes = new Uint8Array(await signedBlob.arrayBuffer());

        expect(MajikFile.hasMjksTrailer(signedBytes)).toBe(true);
        expect(MajikFile.hasMjksTrailer(file.toBinaryBytes())).toBe(false);

        const extractedSig = MajikFile.extractMjksSignature(signedBytes);
        expect(extractedSig).not.toBeNull();
        expect(extractedSig!.signerId).toBe(sig.signerId);

        const stripped = MajikFile.stripMjksTrailer(signedBytes);
        expect(stripped).toEqual(file.toBinaryBytes());
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "static decrypt() should transparently strip the MJKS trailer",
      async () => {
        const signedBlob = file.toSignedMJKB();
        const decrypted = await MajikFile.decrypt(signedBlob, alice.identity);
        expect(new TextDecoder().decode(decrypted)).toBe(
          "Hello, post-quantum cloud storage! This binary content is encrypted.",
        );
      },
      CRYPTO_TIMEOUT,
    );

    it("verifySignedMJKB() should verify a signed binary via MajikKey", async () => {
      const signedBlob = file.toSignedMJKB();
      const result = await MajikFile.verifySignedMJKB(signedBlob, signerKey());
      expect(result.valid).toBe(true);
    });

    it("verifySignedMJKB() should throw if there is no MJKS trailer", async () => {
      await expect(
        MajikFile.verifySignedMJKB(file.toBinaryBytes(), signerPublicKeys()),
      ).rejects.toThrow(/no MJKS trailer found/i);
    });

    it("extractMjksSignature() should return null when there is no trailer", () => {
      expect(MajikFile.extractMjksSignature(file.toBinaryBytes())).toBeNull();
    });

    it("stripMjksTrailer() should be a safe no-op on an unsigned binary", () => {
      const bytes = file.toBinaryBytes();
      expect(MajikFile.stripMjksTrailer(bytes)).toEqual(bytes);
    });
  });

  // ── 9. DIGITAL SIGNATURES ────────────────────────────────────────────────
  describe("Digital signatures", () => {
    let file: MajikFile;

    beforeEach(async () => {
      file = await MajikFile.create({
        data: DUMMY_DATA,
        userId: USER_ID,
        identity: alice.identity,
        mimeType: "text/plain",
      });
    });

    it("should be unsigned by default", () => {
      expect(file.isSigned).toBe(false);
      expect(file.signatureRaw).toBeNull();
      expect(file.signature).toBeNull();
      expect(file.getSignatureInfo()).toBeNull();
      expect(file.verify(signerKey())).toBeNull();
    });

    it(
      "sign() should attach signature and populate signature metadata",
      async () => {
        const key = signerKey("A");
        const sig = await file.sign(key, { contentType: "text/plain" });

        expect(file.isSigned).toBe(true);
        expect(typeof file.signatureRaw).toBe("string");
        expect(typeof sig.signerId).toBe("string");
        expect(sig.signerId.length).toBeGreaterThan(0);
      },
      CRYPTO_TIMEOUT,
    );

    it("sign() should throw missingBinary if binary was cleared", async () => {
      file.clearBinary();
      await expect(file.sign(signerKey())).rejects.toThrow(MajikFileError);
    });

    it(
      "attachSignature() should attach string and round-trip via getSignatureInfo()",
      async () => {
        const sig = await file.sign(signerKey("A"));
        const raw = file.signatureRaw!;

        const fresh = await MajikFile.create({
          data: DUMMY_DATA,
          userId: USER_ID,
          identity: alice.identity,
        });
        fresh.attachSignature(raw);
        expect(fresh.isSigned).toBe(true);

        const info = fresh.getSignatureInfo();
        expect(info?.signerId).toBe(sig.signerId);
      },
      CRYPTO_TIMEOUT,
    );

    it("attachSignature() should reject an empty string", () => {
      expect(() => file.attachSignature("")).toThrow(
        /signature string must be non-empty/i,
      );
    });

    it("attachSignature() should reject invalid serialized string", () => {
      expect(() => file.attachSignature("not-valid-base64-json")).toThrow(
        /not a valid serialized MajikSignature/i,
      );
    });

    it(
      "removeSignature() should clear signature and update lastUpdate",
      async () => {
        await file.sign(signerKey());
        expect(file.isSigned).toBe(true);
        file.removeSignature();
        expect(file.isSigned).toBe(false);
        expect(file.signatureRaw).toBeNull();
        expect(() => file.removeSignature()).not.toThrow();
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "verify() should return null when binary is cleared",
      async () => {
        await file.sign(signerKey());
        file.clearBinary();
        expect(file.verify(signerKey())).toBeNull();
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "verify() should verify via MajikKey",
      async () => {
        await file.sign(signerKey("A"));
        const result = file.verify(signerKey("A"));
        expect(result?.valid).toBe(true);
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "verify() should verify via public keys object",
      async () => {
        await file.sign(signerKey("A"));
        const result = file.verify(signerPublicKeys("A"));
        expect(result?.valid).toBe(true);
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "verifyBinary() should decrypt and verify attached signature",
      async () => {
        await file.sign(signerKey("A"));
        const result = await file.verifyBinary(alice.identity, signerKey("A"));
        expect(result.valid).toBe(true);
      },
      CRYPTO_TIMEOUT,
    );

    it("verifyBinary() should throw if file has no signature", async () => {
      await expect(
        file.verifyBinary(alice.identity, signerKey()),
      ).rejects.toThrow(/no attached signature/i);
    });

    it(
      "verifyBinary() should throw missingBinary if binary is cleared",
      async () => {
        await file.sign(signerKey());
        file.clearBinary();
        await expect(
          file.verifyBinary(alice.identity, signerKey()),
        ).rejects.toThrow(MajikFileError);
      },
      CRYPTO_TIMEOUT,
    );
  });

  // ── 10. OWNERSHIP & PARTICIPANT ACCESS ───────────────────────────────────
  describe("Ownership and participant access checks", () => {
    let groupFile: MajikFile;

    beforeAll(async () => {
      groupFile = await MajikFile.create({
        data: DUMMY_DATA,
        userId: USER_ID,
        identity: alice.identity,
        recipients: [bob.recipient],
      });
    }, CRYPTO_TIMEOUT);

    it("userIsOwner() should correctly verify owner ID", () => {
      expect(groupFile.userIsOwner(USER_ID)).toBe(true);
      expect(groupFile.userIsOwner("someone-else")).toBe(false);
      expect(groupFile.userIsOwner("")).toBe(false);
    });

    it("hasParticipantAccess() should reflect participants array", () => {
      expect(groupFile.hasParticipantAccess(alice.identity.publicKey)).toBe(
        true,
      );
      expect(groupFile.hasParticipantAccess(bob.recipient.publicKey)).toBe(
        true,
      );
      expect(groupFile.hasParticipantAccess(charlie.identity.publicKey)).toBe(
        false,
      );
      expect(groupFile.hasParticipantAccess("")).toBe(false);
    });

    it("canDecrypt() should verify recipient capability by key/fingerprint", () => {
      expect(groupFile.canDecrypt(alice.identity)).toBe(true);
      expect(groupFile.canDecrypt(bob.identity)).toBe(true);
      expect(groupFile.canDecrypt(charlie.identity)).toBe(false);
    });
  });

  // ── 11. DUPLICATE DETECTION ──────────────────────────────────────────────
  describe("Duplicate detection", () => {
    it(
      "isDuplicateOf() should compare by original content hash",
      async () => {
        const fileA = await MajikFile.create({
          data: DUMMY_DATA,
          userId: USER_ID,
          identity: alice.identity,
        });
        const fileB = await MajikFile.create({
          data: DUMMY_DATA,
          userId: USER_ID,
          identity: alice.identity,
        });
        const fileC = await MajikFile.create({
          data: new TextEncoder().encode("different content"),
          userId: USER_ID,
          identity: alice.identity,
        });

        expect(fileA.isDuplicateOf(fileB)).toBe(true);
        expect(fileA.isDuplicateOf(fileC)).toBe(false);
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "wouldBeDuplicate() should check raw bytes against existing hash",
      async () => {
        const file = await MajikFile.create({
          data: DUMMY_DATA,
          userId: USER_ID,
          identity: alice.identity,
        });
        expect(MajikFile.wouldBeDuplicate(DUMMY_DATA, file.fileHash)).toBe(
          true,
        );
        expect(
          MajikFile.wouldBeDuplicate(
            new TextEncoder().encode("different"),
            file.fileHash,
          ),
        ).toBe(false);
      },
      CRYPTO_TIMEOUT,
    );
  });

  // ── 12. STATS & UTILITY HELPERS ──────────────────────────────────────────
  describe("Stats and static utility helpers", () => {
    let file: MajikFile;

    beforeAll(async () => {
      file = await MajikFile.create({
        data: DUMMY_DATA,
        userId: USER_ID,
        identity: alice.identity,
        originalName: "log.txt",
        mimeType: "text/plain",
      });
    }, CRYPTO_TIMEOUT);

    it("getStats() should return correct base metrics", () => {
      const stats = file.getStats();
      expect(stats.id).toBe(file.id);
      expect(stats.originalName).toBe("log.txt");
      expect(stats.mimeType).toBe("text/plain");
      expect(typeof stats.sizeOriginalHuman).toBe("string");
      expect(typeof stats.sizeStoredHuman).toBe("string");
      expect(typeof stats.compressionRatioPct).toBe("number");
      expect(stats.fileHash).toBe(file.fileHash);
      expect(stats.isGroup).toBe(false);
      expect(stats.isSigned).toBe(false);
    });

    it("size getters (KB/MB/GB/TB) should compute correctly", () => {
      expect(file.sizeKB).toBeCloseTo(file.sizeOriginal / 1024, 3);
      expect(file.sizeMB).toBeCloseTo(file.sizeOriginal / 1024 ** 2, 3);
      expect(file.sizeGB).toBeCloseTo(file.sizeOriginal / 1024 ** 3, 3);
      expect(file.sizeTB).toBeCloseTo(file.sizeOriginal / 1024 ** 4, 3);
    });

    it("exceedsSize() should validate limits", () => {
      expect(() => file.exceedsSize(0)).toThrow(/positive finite number/i);
      expect(file.exceedsSize(100)).toBe(false);
    });

    it("isInlineViewable and safeFilename getters should derive properly", () => {
      expect(file.isInlineViewable).toBe(true);
      expect(file.safeFilename).toMatch(/^[a-f0-9]+\.txt$/i);
    });

    it("static utility methods inferMimeType and formatBytes should work", () => {
      expect(MajikFile.inferMimeType("document.pdf")).toBe("application/pdf");
      expect(MajikFile.formatBytes(1024)).toBe("1.00 KB");
    });
  });
});
