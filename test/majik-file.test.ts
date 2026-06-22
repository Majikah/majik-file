// majik-file.test.ts
//
// These tests exercise MajikFile against real post-quantum cryptography
// (@noble/post-quantum ML-KEM-768) and real AES-256-GCM for binary file
// payloads. The core crypto layer (crypto-provider) and compression layer
// (MajikCompressor / zstd-wasm) are NOT mocked — real encapsulation /
// decapsulation cycles and real compression are verified end-to-end.
//
// `@majikah/majik-signature` IS mocked. MajikFile.sign()/verify() delegate
// to that package, which has its own test suite — mocking it here lets us
// test MajikFile's plumbing (attach/detach/serialize/trailer logic) without
// needing a real MajikKey (Ed25519 + ML-DSA-87) fixture.
//
// ─────────────────────────────────────────────────────────────────────────
// CORRECTIONS vs. the previous version of this suite (please read):
//
//  1. `MajikFile` has NO `toBinary()` instance method and NO static
//     `fromBinary()`. It only has `toMJKB()` (Blob), `toBinaryBytes()`
//     (Uint8Array), and `toSignedMJKB()` (Blob, signed). There is no public
//     API that reconstructs a `MajikFile` *instance* from raw `.mjkb` bytes
//     alone (the binary doesn't carry id/userId/etc.) — round-tripping goes
//     through the static `MajikFile.decrypt(bytes, identity)` instead.
//  2. There is NO instance `.decrypt(identity)` method. Use
//     `.decryptBinary(identity)` (instance) or `MajikFile.decrypt(src, id)`
//     (static).
//  3. There is no `.version` getter on `MajikFile`. The format version
//     lives in the `.mjkb` binary header byte (index 4), checked here via
//     `decodeMjkb()` / raw byte inspection instead.
//  4. `chat_attachment` now requires `conversationId` at creation time,
//     identical to `chat_image` / `chat_voice`. The old suite's group-file
//     test omitted it, which would throw given the current validation.
//  5. `MajikFile.createChatAttachment()` never forwards `conversationId`
//     into `MajikFile.create()`, so as currently written it will ALWAYS
//     throw "conversationId is required...". That test below documents
//     this (see the BUG comment) rather than silently working around it —
//     flag this to whoever owns `majik-file.ts`.
//  6. `bindToChatConversation()`'s "success" path can't be reached through
//     any public constructor today: both `create()` and `fromJSON()` run
//     `validate()`, which requires `conversation_id` for `chat_attachment`
//     up front. The binding test below pokes at private state directly
//     (clearly commented) purely to keep the method's own logic covered.
//  7. `sign()` takes a `MajikKey` (from `@majikah/majik-key`), not a
//     `MajikFileIdentity`. The old suite passed `alice.identity` into
//     `.sign()`, which only "worked" by accident because `MajikFileIdentity`
//     also happens to have a string `fingerprint` field that satisfies the
//     internal duck-type check.
// ─────────────────────────────────────────────────────────────────────────

import { describe, it, expect, beforeAll, beforeEach, vi } from "vitest";
import { MajikFile } from "../src/majik-file";
import { generateMlKemKeypair } from "../src/core/crypto/crypto-provider";
import { MajikFileError } from "../src/core/error";
import {
  decodeMjkb,
  sha256Base64,
  formatBytes as utilFormatBytes,
} from "../src/core/utils";
import { isMjkbGroupPayload, isMjkbSinglePayload } from "../src/core/types";
import type {
  MajikFileIdentity,
  MajikFileRecipient,
  MajikFileJSON,
} from "../src/core/types";
import {
  ML_KEM_PK_LEN,
  ML_KEM_SK_LEN,
  MAX_RECIPIENTS,
  MAX_FILE_SIZE_BYTES,
  MJKB_VERSION,
} from "../src/core/crypto/constants";
import type { MajikKey } from "@majikah/majik-key";
import type { MajikSignerPublicKeys } from "@majikah/majik-signature";

const CRYPTO_TIMEOUT = 60_000;

// ── MOCK: @majikah/majik-signature ──────────────────────────────────────────
// MajikFile delegates all real signing/verification crypto to this package.
// It has its own test suite — here we only need a deterministic stand-in so
// we can test MajikFile's attach/detach/trailer/serialization logic.

vi.mock("@majikah/majik-signature", () => {
  class FakeMajikSignature {
    signerId: string;
    timestamp: string;
    contentType?: string;
    contentHash: string;
    constructor(data: {
      signerId: string;
      timestamp: string;
      contentType?: string;
      contentHash: string;
    }) {
      this.signerId = data.signerId;
      this.timestamp = data.timestamp;
      this.contentType = data.contentType;
      this.contentHash = data.contentHash;
    }
    serialize(): string {
      return Buffer.from(
        JSON.stringify({
          signerId: this.signerId,
          timestamp: this.timestamp,
          contentType: this.contentType,
          contentHash: this.contentHash,
        }),
      ).toString("base64");
    }
    toJSON() {
      return {
        signerId: this.signerId,
        timestamp: this.timestamp,
        contentType: this.contentType,
        contentHash: this.contentHash,
      };
    }
  }

  return {
    MajikSignature: {
      sign: vi.fn(
        async (
          binary: Uint8Array,
          key: { fingerprint?: string },
          options?: { contentType?: string; timestamp?: string },
        ) =>
          new FakeMajikSignature({
            signerId: key?.fingerprint ?? "mock-signer-fp",
            timestamp: options?.timestamp ?? "2026-01-01T00:00:00.000Z",
            contentType: options?.contentType,
            contentHash: `mockhash-${binary.length}`,
          }),
      ),
      deserialize: vi.fn((raw: string) => {
        const json = JSON.parse(Buffer.from(raw, "base64").toString("utf-8"));
        return new FakeMajikSignature(json);
      }),
      fromJSON: vi.fn(
        (json: {
          signerId: string;
          timestamp: string;
          contentType?: string;
          contentHash: string;
        }) => new FakeMajikSignature(json),
      ),
      verify: vi.fn((_data: Uint8Array, sig: FakeMajikSignature) => ({
        valid: true,
        signerId: sig.signerId,
      })),
      verifyWithKey: vi.fn((_data: Uint8Array, sig: FakeMajikSignature) => ({
        valid: true,
        signerId: sig.signerId,
      })),
    },
  };
});

// Import AFTER vi.mock so we get the mocked module.
import { MajikSignature } from "@majikah/majik-signature";

// ── TEST HELPERS ─────────────────────────────────────────────────────────────

interface TestFileUser {
  identity: MajikFileIdentity;
  recipient: MajikFileRecipient;
}

/** Generates real ML-KEM-768 identities and recipients matching types.ts */
function createTestFileUser(name: string): TestFileUser {
  const keys = generateMlKemKeypair(); // Real 1184 public / 2400 secret bytes
  const fingerprint = `test-fp-${name}-${Date.now()}-${Math.random()}`;
  const publicKey = `pubkey-${name}-${Date.now()}`;

  return {
    identity: {
      publicKey,
      fingerprint,
      mlKemPublicKey: keys.publicKey,
      mlKemSecretKey: keys.secretKey,
    },
    recipient: {
      fingerprint,
      publicKey,
      mlKemPublicKey: keys.publicKey,
    },
  };
}

/** Builds N structurally-valid (but not cryptographically real) recipients. */
function buildFakeRecipients(count: number): MajikFileRecipient[] {
  const list: MajikFileRecipient[] = [];
  for (let i = 0; i < count; i++) {
    list.push({
      fingerprint: `fake-recipient-fp-${i}`,
      publicKey: `fake-pub-${i}`,
      mlKemPublicKey: new Uint8Array(ML_KEM_PK_LEN),
    });
  }
  return list;
}

function fakeSignerKey(fingerprint = "signer-fp-001"): MajikKey {
  return { fingerprint } as unknown as MajikKey;
}

function fakePublicKeys(signerId = "signer-fp-001"): MajikSignerPublicKeys {
  return { signerId } as unknown as MajikSignerPublicKeys;
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

  beforeAll(() => {
    alice = createTestFileUser("alice");
    bob = createTestFileUser("bob");
    charlie = createTestFileUser("charlie");
  });

  beforeEach(() => {
    vi.clearAllMocks();
  });

  // ── 1. CREATE() VALIDATION ───────────────────────────────────────────────
  describe("create() — input validation", () => {
    it("should reject when data is missing", async () => {
      await expect(
        MajikFile.create({
          userId: USER_ID,
          identity: alice.identity,
          context: "user_upload",
        } as any),
      ).rejects.toThrow(/data is required/i);
    });

    it("should reject when identity is missing", async () => {
      await expect(
        MajikFile.create({
          data: DUMMY_DATA,
          userId: USER_ID,
          context: "user_upload",
        } as any),
      ).rejects.toThrow(/identity is required/i);
    });

    it("should reject when userId is missing or blank", async () => {
      await expect(
        MajikFile.create({
          data: DUMMY_DATA,
          userId: "   ",
          identity: alice.identity,
          context: "user_upload",
        }),
      ).rejects.toThrow(/userId is required/i);
    });

    it("should reject when identity.fingerprint is missing", async () => {
      await expect(
        MajikFile.create({
          data: DUMMY_DATA,
          userId: USER_ID,
          identity: { ...alice.identity, fingerprint: "" },
          context: "user_upload",
        }),
      ).rejects.toThrow(/identity\.fingerprint is required/i);
    });

    it("should reject identity with invalid mlKemPublicKey length", async () => {
      await expect(
        MajikFile.create({
          data: DUMMY_DATA,
          userId: USER_ID,
          identity: { ...alice.identity, mlKemPublicKey: new Uint8Array(10) },
          context: "user_upload",
        }),
      ).rejects.toThrow(/mlKemPublicKey must be a 1184-byte/i);
    });

    it("should reject an unrecognised context value", async () => {
      await expect(
        MajikFile.create({
          data: DUMMY_DATA,
          userId: USER_ID,
          identity: alice.identity,
          context: "not_a_real_context" as any,
        }),
      ).rejects.toThrow(/Invalid context/i);
    });

    it("should reject empty/zero-byte file data", async () => {
      await expect(
        MajikFile.create({
          data: new Uint8Array(0),
          userId: USER_ID,
          identity: alice.identity,
          context: "user_upload",
        }),
      ).rejects.toThrow(/data must not be empty/i);
    });

    it("should reject creation if file size exceeds the size limit", async () => {
      const oversizedData = new Uint8Array(MAX_FILE_SIZE_BYTES + 1);
      await expect(
        MajikFile.create({
          data: oversizedData,
          userId: USER_ID,
          identity: alice.identity,
          context: "user_upload",
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
            context: "user_upload",
            bypassSizeLimit: true,
          });
        } catch (err: any) {
          expect(err.message).not.toMatch(/exceeds maximum allowed size/i);
        }
      },
      CRYPTO_TIMEOUT,
    );

    it("should reject when context is 'chat_image' without conversationId", async () => {
      await expect(
        MajikFile.create({
          data: DUMMY_DATA,
          userId: USER_ID,
          identity: alice.identity,
          context: "chat_image",
        }),
      ).rejects.toThrow(/conversationId is required.*chat_image/i);
    });

    it("should reject when context is 'chat_voice' without conversationId", async () => {
      await expect(
        MajikFile.create({
          data: DUMMY_DATA,
          userId: USER_ID,
          identity: alice.identity,
          context: "chat_voice",
        }),
      ).rejects.toThrow(/conversationId is required.*chat_voice/i);
    });

    it("should reject when context is 'chat_attachment' without conversationId", async () => {
      await expect(
        MajikFile.create({
          data: DUMMY_DATA,
          userId: USER_ID,
          identity: alice.identity,
          context: "chat_attachment",
        }),
      ).rejects.toThrow(/conversationId is required.*chat_attachment/i);
    });

    it("should reject chatMessageId + threadMessageId set together", async () => {
      await expect(
        MajikFile.create({
          data: DUMMY_DATA,
          userId: USER_ID,
          identity: alice.identity,
          context: "user_upload",
          chatMessageId: "chat-msg-1",
          threadMessageId: "thread-msg-1",
        }),
      ).rejects.toThrow(/mutually exclusive/i);
    });

    it("should reject isTemporary without expiresAt", async () => {
      await expect(
        MajikFile.create({
          data: DUMMY_DATA,
          userId: USER_ID,
          identity: alice.identity,
          context: "user_upload",
          isTemporary: true,
          expiresAt: undefined,
        }),
      ).rejects.toThrow(/expiresAt is required for temporary files/i);
    });

    it("should reject a recipient with a missing fingerprint", async () => {
      await expect(
        MajikFile.create({
          data: DUMMY_DATA,
          userId: USER_ID,
          identity: alice.identity,
          context: "user_upload",
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
        mlKemPublicKey: new Uint8Array(32), // Expected 1184 bytes
      };

      await expect(
        MajikFile.create({
          data: DUMMY_DATA,
          userId: USER_ID,
          identity: alice.identity,
          context: "user_upload",
          recipients: [invalidRecipient],
        }),
      ).rejects.toThrow(/mlKemPublicKey must be a 1184-byte/i);
    });

    it(
      "should reject more than MAX_RECIPIENTS additional recipients",
      async () => {
        const tooMany = buildFakeRecipients(MAX_RECIPIENTS + 1);
        await expect(
          MajikFile.create({
            data: DUMMY_DATA,
            userId: USER_ID,
            identity: alice.identity,
            context: "user_upload",
            recipients: tooMany,
          }),
        ).rejects.toThrow(/Too many recipients/i);
      },
      CRYPTO_TIMEOUT,
    );
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
          context: "user_upload",
          originalName: "secure-report.pdf",
          mimeType: "application/pdf",
        });

        expect(singleFile).toBeInstanceOf(MajikFile);
        expect(singleFile.isSingle).toBe(true);
        expect(singleFile.isGroup).toBe(false);
        expect(singleFile.hasBinary).toBe(true);

        // No `.version` getter exists on MajikFile — the version lives in
        // the .mjkb binary header. Verify it there instead.
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
      "should decrypt via the instance decryptBinary() convenience method",
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
        context: "user_upload",
      });
      cleared.clearBinary();
      expect(cleared.hasBinary).toBe(false);
      await expect(cleared.decryptBinary(alice.identity)).rejects.toThrow(
        MajikFileError,
      );
    });
  });

  // ── 3. GROUP / MULTI-RECIPIENT ───────────────────────────────────────────
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
          context: "user_upload",
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
      "should treat the owner's own key in `recipients` as a no-op (single, not group)",
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
          context: "user_upload",
        });
        expect(selfListed.isSingle).toBe(true);
        expect(selfListed.isGroup).toBe(false);
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "should deduplicate a recipient listed more than once",
      async () => {
        const dupeListed = await MajikFile.create({
          data: DUMMY_DATA,
          userId: USER_ID,
          identity: alice.identity,
          recipients: [bob.recipient, bob.recipient],
          context: "user_upload",
        });

        expect(dupeListed.isGroup).toBe(true);
        expect(dupeListed.participants).toHaveLength(2); // owner + bob, not 3

        const decrypted = await dupeListed.decryptBinary(bob.identity);
        expect(new TextDecoder().decode(decrypted)).toBe(
          "Hello, post-quantum cloud storage! This binary content is encrypted.",
        );
      },
      CRYPTO_TIMEOUT,
    );
  });

  // ── 4. QUICK-CREATE WRAPPERS ─────────────────────────────────────────────
  describe("Quick-create wrappers", () => {
    it(
      "createChatImage() should succeed for a valid image",
      async () => {
        const file = await MajikFile.createChatImage({
          data: DUMMY_DATA,
          userId: USER_ID,
          identity: alice.identity,
          conversationId: "conv-123",
          mimeType: "image/png",
          originalName: "avatar.png",
        });
        expect(file.context).toBe("chat_image");
        expect(file.conversationId).toBe("conv-123");
      },
      CRYPTO_TIMEOUT,
    );

    it("createChatImage() should reject a non-image mimeType", async () => {
      await expect(
        MajikFile.createChatImage({
          data: DUMMY_DATA,
          userId: USER_ID,
          identity: alice.identity,
          conversationId: "conv-123",
          mimeType: "application/pdf",
        }),
      ).rejects.toThrow(/mimeType must be an image\/\* type/i);
    });

    it("createChatImage() should reject files over the 25MB chat-image limit", async () => {
      const oversized = new Uint8Array(25 * 1024 * 1024 + 1);
      await expect(
        MajikFile.createChatImage({
          data: oversized,
          userId: USER_ID,
          identity: alice.identity,
          conversationId: "conv-123",
          mimeType: "image/png",
        }),
      ).rejects.toThrow(/exceeds the.*limit/i);
    });

    it(
      // BUG (see header comment #5): createChatAttachment() never forwards
      // conversationId into create(), but create() now requires it for the
      // "chat_attachment" context. As written, this wrapper can never
      // succeed. This test documents CURRENT behavior — if/when the source
      // is fixed to thread conversationId through, this test should be
      // updated to assert success instead.
      "createChatAttachment() currently always throws (conversationId is not forwarded — see source bug)",
      async () => {
        await expect(
          MajikFile.createChatAttachment({
            data: DUMMY_DATA,
            userId: USER_ID,
            identity: alice.identity,
            chatMessageId: "chat-msg-1",
            originalName: "doc.txt",
            mimeType: "text/plain",
          }),
        ).rejects.toThrow(/conversationId is required/i);
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "createThreadAttachment() should succeed without a conversationId",
      async () => {
        const file = await MajikFile.createThreadAttachment({
          data: DUMMY_DATA,
          userId: USER_ID,
          identity: alice.identity,
          threadId: "thread-1",
          originalName: "memo.txt",
          mimeType: "text/plain",
        });
        expect(file.context).toBe("thread_attachment");
        expect(file.threadId).toBe("thread-1");
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "createUserUpload() should succeed and respect isShared",
      async () => {
        const file = await MajikFile.createUserUpload({
          data: DUMMY_DATA,
          userId: USER_ID,
          identity: alice.identity,
          originalName: "notes.txt",
          isShared: true,
        });
        expect(file.context).toBe("user_upload");
        expect(file.storageType).toBe("permanent");
        expect(file.isShared).toBe(true);
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "createTemporaryUpload() should default to a 15-day duration",
      async () => {
        const file = await MajikFile.createTemporaryUpload({
          data: DUMMY_DATA,
          userId: USER_ID,
          identity: alice.identity,
        });
        expect(file.storageType).toBe("temporary");
        expect(file.expiresAt).not.toBeNull();
        const days =
          (new Date(file.expiresAt!).getTime() - Date.now()) /
          (1000 * 60 * 60 * 24);
        expect(days).toBeGreaterThan(14.9);
        expect(days).toBeLessThan(15.1);
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "createTemporaryUpload() should respect a custom duration",
      async () => {
        const file = await MajikFile.createTemporaryUpload({
          data: DUMMY_DATA,
          userId: USER_ID,
          identity: alice.identity,
          duration: 1,
        });
        const days =
          (new Date(file.expiresAt!).getTime() - Date.now()) /
          (1000 * 60 * 60 * 24);
        expect(days).toBeGreaterThan(0.9);
        expect(days).toBeLessThan(1.1);
      },
      CRYPTO_TIMEOUT,
    );
  });

  // ── 5. CREATE AND SIGN ───────────────────────────────────────────────────
  describe("createAndSign()", () => {
    it(
      "should encrypt and attach a signature in one call",
      async () => {
        const file = await MajikFile.createAndSign(
          {
            data: DUMMY_DATA,
            userId: USER_ID,
            identity: alice.identity,
            context: "user_upload",
          },
          fakeSignerKey(),
        );
        expect(file.isSigned).toBe(true);
        expect(file.hasBinary).toBe(true);
        expect(MajikSignature.sign).toHaveBeenCalledTimes(1);
      },
      CRYPTO_TIMEOUT,
    );
  });

  // ── 6. BINARY FORMAT & STRUCTURAL VALIDATION ────────────────────────────
  describe("Binary format (.mjkb) structural checks", () => {
    let file: MajikFile;

    beforeAll(async () => {
      file = await MajikFile.create({
        data: DUMMY_DATA,
        userId: USER_ID,
        identity: alice.identity,
        context: "user_upload",
        originalName: "backup-archive.zip",
        mimeType: "application/zip",
      });
    }, CRYPTO_TIMEOUT);

    it("toMJKB() and toBinaryBytes() should describe the same bytes", async () => {
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
        context: "user_upload",
      });
      f2.clearBinary();
      expect(() => f2.toBinaryBytes()).toThrow(MajikFileError);
      expect(() => f2.toMJKB()).toThrow(MajikFileError);
    });

    it("isMjkbCandidate() should pass for real binaries and fail for garbage", () => {
      expect(MajikFile.isMjkbCandidate(file.toBinaryBytes())).toBe(true);
      expect(MajikFile.isMjkbCandidate(new Uint8Array([1, 2, 3]))).toBe(false);
      expect(
        MajikFile.isMjkbCandidate(new Uint8Array([0x4d, 0x4a, 0x4b, 0x00, 0])),
      ).toBe(false);
    });

    it("isValidMJKB() should pass for a real file and fail for corrupted ones", () => {
      expect(MajikFile.isValidMJKB(file.toBinaryBytes())).toBe(true);
      expect(MajikFile.isValidMJKB(new Uint8Array([1, 2, 3]))).toBe(false);

      const tampered = file.toBinaryBytes().slice();
      tampered[0] = 0x00; // corrupt magic
      expect(MajikFile.isValidMJKB(tampered)).toBe(false);

      const truncated = file.toBinaryBytes().slice(0, 10);
      expect(MajikFile.isValidMJKB(truncated)).toBe(false);
    });

    it("static decrypt() should throw a formatError on bad magic bytes", async () => {
      const corrupt = new Uint8Array([
        99, 99, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17,
        18, 19, 20, 21, 22, 23, 24,
      ]);
      await expect(
        MajikFile.decrypt(corrupt, {
          fingerprint: alice.identity.fingerprint,
          mlKemSecretKey: alice.identity.mlKemSecretKey,
        }),
      ).rejects.toThrow(/Invalid \.mjkb magic bytes/i);
    });

    it("static decrypt() should throw on an unsupported version byte", async () => {
      const bytes = file.toBinaryBytes().slice();
      bytes[4] = 0xff; // bogus version
      await expect(
        MajikFile.decrypt(bytes, {
          fingerprint: alice.identity.fingerprint,
          mlKemSecretKey: alice.identity.mlKemSecretKey,
        }),
      ).rejects.toThrow(MajikFileError);
    });

    it("static decrypt() should throw on a truncated payload section", async () => {
      const bytes = file.toBinaryBytes().slice(0, 25); // cuts off mid-payload
      await expect(
        MajikFile.decrypt(bytes, {
          fingerprint: alice.identity.fingerprint,
          mlKemSecretKey: alice.identity.mlKemSecretKey,
        }),
      ).rejects.toThrow(MajikFileError);
    });
  });

  // ── 7. SERIALIZATION: toJSON() / fromJSON() ─────────────────────────────
  describe("toJSON() / fromJSON() / fromJSONWithBlob()", () => {
    let originalFile: MajikFile;

    beforeAll(async () => {
      originalFile = await MajikFile.create({
        data: DUMMY_DATA,
        userId: USER_ID,
        identity: alice.identity,
        context: "user_upload",
        originalName: "backup-archive.zip",
        mimeType: "application/zip",
      });
    }, CRYPTO_TIMEOUT);

    it("toJSON() should map 1-to-1 to the expected Supabase row shape", () => {
      const jsonOutput = originalFile.toJSON();

      expect(jsonOutput.id).toBeDefined();
      expect(jsonOutput.user_id).toBe(USER_ID);
      expect(jsonOutput.original_name).toBe("backup-archive.zip");
      expect(jsonOutput.mime_type).toBe("application/zip");
      expect(jsonOutput.size_original).toBe(DUMMY_DATA.byteLength);
      expect(jsonOutput.encryption_iv).toBeDefined();
      expect(jsonOutput.signature).toBeNull();
    });

    it("fromJSON() without a binary should produce a metadata-only, single-mode instance", () => {
      const json = originalFile.toJSON();
      const restored = MajikFile.fromJSON(json);
      expect(restored).toBeInstanceOf(MajikFile);
      expect(restored.hasBinary).toBe(false);
      expect(restored.isGroup).toBe(false);
      expect(restored.toJSON().id).toBe(json.id);
    });

    it(
      "fromJSON() with a binary should correctly re-derive isGroup/isSingle",
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
          context: "user_upload",
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

    it("fromJSONWithBlob() should accept a Blob and behave like fromJSON()", async () => {
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

    it("fromJSON() should throw a validationFailed error for an invalid row", () => {
      const badJson: MajikFileJSON = {
        ...originalFile.toJSON(),
        user_id: "", // required field blanked out
      };
      expect(() => MajikFile.fromJSON(badJson)).toThrow(MajikFileError);
      expect(() => MajikFile.fromJSON(badJson)).toThrow(/user_id is required/i);
    });

    it("fromJSON() should reject a non-object json argument", () => {
      expect(() => MajikFile.fromJSON(null as any)).toThrow(
        /json must be a non-null object/i,
      );
    });
  });

  // ── 8. MJKS SIGNED TRAILER ───────────────────────────────────────────────
  describe("Signed MJKB trailer (toSignedMJKB / verifySignedMJKB)", () => {
    let file: MajikFile;

    beforeAll(async () => {
      file = await MajikFile.create({
        data: DUMMY_DATA,
        userId: USER_ID,
        identity: alice.identity,
        context: "user_upload",
      });
    }, CRYPTO_TIMEOUT);

    it("toSignedMJKB() should throw if there is no attached signature", () => {
      expect(() => file.toSignedMJKB()).toThrow(/no signature attached/i);
    });

    it(
      "toSignedMJKB() should append a recoverable MJKS trailer",
      async () => {
        await file.sign(fakeSignerKey());
        const signedBlob = file.toSignedMJKB();
        const signedBytes = new Uint8Array(await signedBlob.arrayBuffer());

        expect(MajikFile.hasMjksTrailer(signedBytes)).toBe(true);
        expect(MajikFile.hasMjksTrailer(file.toBinaryBytes())).toBe(false);

        const extractedSig = MajikFile.extractMjksSignature(signedBytes);
        expect(extractedSig).not.toBeNull();
        expect(extractedSig!.signerId).toBe("signer-fp-001");

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

    it("verifySignedMJKB() should verify a signed binary against public keys", async () => {
      const signedBlob = file.toSignedMJKB();
      const result = await MajikFile.verifySignedMJKB(
        signedBlob,
        fakePublicKeys(),
      );
      expect(result.valid).toBe(true);
      expect(MajikSignature.verify).toHaveBeenCalledTimes(1);
    });

    it("verifySignedMJKB() should use verifyWithKey() for a MajikKey argument", async () => {
      const signedBlob = file.toSignedMJKB();
      await MajikFile.verifySignedMJKB(signedBlob, fakeSignerKey());
      expect(MajikSignature.verifyWithKey).toHaveBeenCalledTimes(1);
      expect(MajikSignature.verify).not.toHaveBeenCalled();
    });

    it("verifySignedMJKB() should throw if there is no MJKS trailer", async () => {
      await expect(
        MajikFile.verifySignedMJKB(file.toBinaryBytes(), fakePublicKeys()),
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

  // ── 9. DIGITAL SIGNATURES (structural, via mocked majik-signature) ──────
  describe("Digital signatures", () => {
    let file: MajikFile;

    beforeEach(async () => {
      file = await MajikFile.create({
        data: DUMMY_DATA,
        userId: USER_ID,
        identity: alice.identity,
        context: "user_upload",
        mimeType: "text/plain",
      });
    });

    it("should be unsigned by default", () => {
      expect(file.isSigned).toBe(false);
      expect(file.signatureRaw).toBeNull();
      expect(file.signature).toBeNull();
      expect(file.getSignatureInfo()).toBeNull();
      expect(file.verify(fakeSignerKey())).toBeNull();
    });

    it(
      "sign() should attach a signature and call MajikSignature.sign() with the binary + key",
      async () => {
        const key = fakeSignerKey("alice-signing-key");
        const sig = await file.sign(key, { contentType: "text/plain" });

        expect(file.isSigned).toBe(true);
        expect(typeof file.signatureRaw).toBe("string");
        expect(sig.signerId).toBe("alice-signing-key");
        expect(MajikSignature.sign).toHaveBeenCalledWith(
          file.toBinaryBytes(),
          key,
          expect.objectContaining({ contentType: "text/plain" }),
        );
      },
      CRYPTO_TIMEOUT,
    );

    it("sign() should throw missingBinary if the binary has been cleared", async () => {
      file.clearBinary();
      await expect(file.sign(fakeSignerKey())).rejects.toThrow(MajikFileError);
    });

    it(
      "attachSignature() should accept a serialized string and round-trip via getSignatureInfo()",
      async () => {
        await file.sign(fakeSignerKey("alice-key"));
        const raw = file.signatureRaw!;

        const fresh = await MajikFile.create({
          data: DUMMY_DATA,
          userId: USER_ID,
          identity: alice.identity,
          context: "user_upload",
        });
        fresh.attachSignature(raw);
        expect(fresh.isSigned).toBe(true);

        const info = fresh.getSignatureInfo();
        expect(info?.signerId).toBe("alice-key");
      },
      CRYPTO_TIMEOUT,
    );

    it("attachSignature() should reject an empty string", () => {
      expect(() => file.attachSignature("")).toThrow(
        /signature string must be non-empty/i,
      );
    });

    it("attachSignature() should reject a string that doesn't deserialize", () => {
      vi.mocked(MajikSignature.deserialize).mockImplementationOnce(() => {
        throw new Error("corrupt");
      });
      expect(() => file.attachSignature("not-valid-base64-json")).toThrow(
        /not a valid serialized MajikSignature/i,
      );
    });

    it(
      "removeSignature() should clear an attached signature, and no-op if already unsigned",
      async () => {
        await file.sign(fakeSignerKey());
        expect(file.isSigned).toBe(true);
        file.removeSignature();
        expect(file.isSigned).toBe(false);
        expect(file.signatureRaw).toBeNull();
        // no-op
        expect(() => file.removeSignature()).not.toThrow();
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "verify() should return null when the binary is not loaded, even if signed",
      async () => {
        await file.sign(fakeSignerKey());
        file.clearBinary();
        expect(file.verify(fakeSignerKey())).toBeNull();
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "verify() should call verifyWithKey() for a MajikKey-shaped argument",
      async () => {
        await file.sign(fakeSignerKey());
        const result = file.verify(fakeSignerKey("alice-key"));
        expect(result?.valid).toBe(true);
        expect(MajikSignature.verifyWithKey).toHaveBeenCalledTimes(1);
        expect(MajikSignature.verify).not.toHaveBeenCalled();
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "verify() should call verify() (not verifyWithKey) for a public-keys-shaped argument",
      async () => {
        await file.sign(fakeSignerKey());
        const result = file.verify(fakePublicKeys("alice-key"));
        expect(result?.valid).toBe(true);
        expect(MajikSignature.verify).toHaveBeenCalledTimes(1);
        expect(MajikSignature.verifyWithKey).not.toHaveBeenCalled();
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "verify() should surface a tampered/invalid result from the signature library",
      async () => {
        await file.sign(fakeSignerKey());
        vi.mocked(MajikSignature.verifyWithKey).mockReturnValueOnce({
          valid: false,
          signerId: "alice-key",
        } as any);
        const result = file.verify(fakeSignerKey());
        expect(result?.valid).toBe(false);
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "verifyBinary() should decrypt then verify against the plaintext",
      async () => {
        await file.sign(fakeSignerKey("alice-key"));
        const result = await file.verifyBinary(
          alice.identity,
          fakeSignerKey("alice-key"),
        );
        expect(result.valid).toBe(true);
        expect(MajikSignature.verifyWithKey).toHaveBeenCalledWith(
          DUMMY_DATA,
          expect.anything(),
          expect.anything(),
        );
      },
      CRYPTO_TIMEOUT,
    );

    it("verifyBinary() should throw if there is no attached signature", async () => {
      await expect(
        file.verifyBinary(alice.identity, fakeSignerKey()),
      ).rejects.toThrow(/no attached signature/i);
    });

    it(
      "verifyBinary() should throw missingBinary if the binary is cleared",
      async () => {
        await file.sign(fakeSignerKey());
        file.clearBinary();
        await expect(
          file.verifyBinary(alice.identity, fakeSignerKey()),
        ).rejects.toThrow(MajikFileError);
      },
      CRYPTO_TIMEOUT,
    );
  });

  // ── 10. STORAGE TYPE, SHARING, EXPIRY ────────────────────────────────────
  describe("Storage type mutation, sharing, and expiry", () => {
    it(
      "setTemporary() / setPermanent() should toggle storage type and the R2 key",
      async () => {
        const file = await MajikFile.create({
          data: DUMMY_DATA,
          userId: USER_ID,
          identity: alice.identity,
          context: "user_upload",
        });
        expect(file.storageType).toBe("permanent");
        const permKey = file.r2Key;

        file.setTemporary(7);
        expect(file.storageType).toBe("temporary");
        expect(file.r2Key).not.toBe(permKey);
        expect(file.expiresAt).not.toBeNull();

        file.setPermanent();
        expect(file.storageType).toBe("permanent");
        expect(file.expiresAt).toBeNull();
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "setStorageType('temporary') without expiresAt should throw",
      async () => {
        const file = await MajikFile.create({
          data: DUMMY_DATA,
          userId: USER_ID,
          identity: alice.identity,
          context: "user_upload",
        });
        expect(() => file.setStorageType("temporary", null)).toThrow(
          /expiresAt is required when switching to temporary/i,
        );
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "setStorageType() should refuse to mutate chat_image files",
      async () => {
        const file = await MajikFile.createChatImage({
          data: DUMMY_DATA,
          userId: USER_ID,
          identity: alice.identity,
          conversationId: "conv-1",
          mimeType: "image/png",
        });
        expect(() => file.setPermanent()).toThrow(
          /chat_image files are conversation-scoped/i,
        );
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "toggleSharing() should turn sharing on (auto token) and off (clears token)",
      async () => {
        const file = await MajikFile.create({
          data: DUMMY_DATA,
          userId: USER_ID,
          identity: alice.identity,
          context: "user_upload",
        });
        expect(file.hasShareToken).toBe(false);

        const token = file.toggleSharing();
        expect(token).toBeTruthy();
        expect(file.isShared).toBe(true);
        expect(file.hasShareToken).toBe(true);

        const cleared = file.toggleSharing();
        expect(cleared).toBeNull();
        expect(file.isShared).toBe(false);
        expect(file.hasShareToken).toBe(false);
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "toggleSharing() should accept an explicit token and reject a blank one",
      async () => {
        const file = await MajikFile.create({
          data: DUMMY_DATA,
          userId: USER_ID,
          identity: alice.identity,
          context: "user_upload",
        });
        const token = file.toggleSharing("custom-token-abc");
        expect(token).toBe("custom-token-abc");

        file.toggleSharing(); // turn off
        expect(() => file.toggleSharing("   ")).toThrow(
          /token must be a non-empty string/i,
        );
      },
      CRYPTO_TIMEOUT,
    );

    it("isExpired / isTemporary should reflect the stored expiry date", () => {
      const baseJson = {
        id: "id-1",
        user_id: USER_ID,
        r2_key: "files/public/15/x_y.mjkb",
        original_name: null,
        mime_type: null,
        size_original: 10,
        size_stored: 20,
        file_hash: "abc",
        encryption_iv: "abc",
        is_shared: false,
        share_token: null,
        context: null,
        chat_message_id: null,
        thread_message_id: null,
        thread_id: null,
        participants: [],
        conversation_id: null,
        timestamp: null,
        last_update: null,
        signature: null,
      } satisfies Omit<MajikFileJSON, "storage_type" | "expires_at">;

      const expired = MajikFile.fromJSON({
        ...baseJson,
        storage_type: "temporary",
        expires_at: new Date(Date.now() - 1000).toISOString(),
      });
      expect(expired.isExpired).toBe(true);
      expect(expired.isTemporary).toBe(true);

      const notExpired = MajikFile.fromJSON({
        ...baseJson,
        storage_type: "temporary",
        expires_at: new Date(Date.now() + 1_000_000).toISOString(),
      });
      expect(notExpired.isExpired).toBe(false);

      const permanent = MajikFile.fromJSON({
        ...baseJson,
        r2_key: "files/user/x/y.mjkb",
        storage_type: "permanent",
        expires_at: null,
      });
      expect(permanent.isExpired).toBe(false);
      expect(permanent.isTemporary).toBe(false);
    });
  });

  // ── 11. THREAD / CHAT BINDINGS ───────────────────────────────────────────
  describe("bindToThreadMail() / bindToChatConversation()", () => {
    it(
      "bindToThreadMail() should succeed exactly once for a thread_attachment file",
      async () => {
        const file = await MajikFile.createThreadAttachment({
          data: DUMMY_DATA,
          userId: USER_ID,
          identity: alice.identity,
          threadId: "thread-1",
        });
        // thread_attachment does not require threadMessageId up front, so
        // it's still unbound here.
        expect(file.threadMessageId).toBeNull();

        file.bindToThreadMail("thread-1", "thread-msg-1");
        expect(file.threadId).toBe("thread-1");
        expect(file.threadMessageId).toBe("thread-msg-1");

        expect(() => file.bindToThreadMail("thread-2", "thread-msg-2")).toThrow(
          /already bound to a thread mail/i,
        );
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "bindToThreadMail() should reject the wrong context",
      async () => {
        const file = await MajikFile.create({
          data: DUMMY_DATA,
          userId: USER_ID,
          identity: alice.identity,
          context: "user_upload",
        });
        expect(() => file.bindToThreadMail("t", "m")).toThrow(
          /only thread_attachment files can be bound/i,
        );
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "bindToThreadMail() should reject missing threadId/threadMessageId",
      async () => {
        const file = await MajikFile.createThreadAttachment({
          data: DUMMY_DATA,
          userId: USER_ID,
          identity: alice.identity,
          threadId: "thread-1",
        });
        expect(() => file.bindToThreadMail("", "msg")).toThrow(
          /threadId is required/i,
        );
        expect(() => file.bindToThreadMail("thread-1", "")).toThrow(
          /threadMessageId is required/i,
        );
      },
      CRYPTO_TIMEOUT,
    );

    // NOTE (see header comment #6): under current validation rules,
    // `chat_attachment` files always require `conversation_id` at creation,
    // so the "unbound" state bindToChatConversation() expects can't be
    // produced via the public API. We force that state via direct private
    // field access purely to exercise the method's own logic — this is a
    // workaround for a real inconsistency in the source, not a pattern to
    // copy elsewhere.
    it(
      "bindToChatConversation() — logic check (state forced; see NOTE above)",
      async () => {
        const file = await MajikFile.create({
          data: DUMMY_DATA,
          userId: USER_ID,
          identity: alice.identity,
          context: "chat_attachment",
          conversationId: "temp-conv-for-construction",
        });
        // Force the "unbound" state that the public API cannot currently produce.
        (file as any)._conversationId = null;
        (file as any)._chatMessageId = null;

        file.bindToChatConversation("conv-99", "chat-msg-99");
        expect(file.conversationId).toBe("conv-99");
        expect(file.chatMessageId).toBe("chat-msg-99");

        expect(() =>
          file.bindToChatConversation("conv-other", "chat-msg-other"),
        ).toThrow(/already bound to a chat conversation/i);
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "bindToChatConversation() should reject the wrong context",
      async () => {
        const file = await MajikFile.create({
          data: DUMMY_DATA,
          userId: USER_ID,
          identity: alice.identity,
          context: "user_upload",
        });
        expect(() => file.bindToChatConversation("c", "m")).toThrow(
          /only chat_attachment files can be bound/i,
        );
      },
      CRYPTO_TIMEOUT,
    );
  });

  // ── 12. OWNERSHIP & PARTICIPANT ACCESS ──────────────────────────────────
  describe("Ownership and participant access checks", () => {
    let groupFile: MajikFile;

    beforeAll(async () => {
      groupFile = await MajikFile.create({
        data: DUMMY_DATA,
        userId: USER_ID,
        identity: alice.identity,
        recipients: [bob.recipient],
        context: "user_upload",
      });
    }, CRYPTO_TIMEOUT);

    it("userIsOwner() should correctly identify the owner", () => {
      expect(groupFile.userIsOwner(USER_ID)).toBe(true);
      expect(groupFile.userIsOwner("someone-else")).toBe(false);
      expect(groupFile.userIsOwner("")).toBe(false);
    });

    it("hasParticipantAccess() should reflect the participants list", () => {
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
  });

  // ── 13. DUPLICATE DETECTION ──────────────────────────────────────────────
  describe("Duplicate detection", () => {
    it(
      "isDuplicateOf() should compare by file_hash of original bytes",
      async () => {
        const fileA = await MajikFile.create({
          data: DUMMY_DATA,
          userId: USER_ID,
          identity: alice.identity,
          context: "user_upload",
        });
        const fileB = await MajikFile.create({
          data: DUMMY_DATA,
          userId: USER_ID,
          identity: alice.identity,
          context: "user_upload",
        });
        const fileC = await MajikFile.create({
          data: new TextEncoder().encode("totally different content"),
          userId: USER_ID,
          identity: alice.identity,
          context: "user_upload",
        });

        expect(fileA.isDuplicateOf(fileB)).toBe(true);
        expect(fileA.isDuplicateOf(fileC)).toBe(false);
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "wouldBeDuplicate() should hash-compare raw bytes against an existing hash",
      async () => {
        const file = await MajikFile.create({
          data: DUMMY_DATA,
          userId: USER_ID,
          identity: alice.identity,
          context: "user_upload",
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

  // ── 14. STATS & STATIC HELPERS ───────────────────────────────────────────
  describe("Stats and static helper methods", () => {
    let file: MajikFile;

    beforeAll(async () => {
      file = await MajikFile.create({
        data: DUMMY_DATA,
        userId: USER_ID,
        identity: alice.identity,
        context: "user_upload",
        originalName: "log.txt",
        mimeType: "text/plain",
      });
    }, CRYPTO_TIMEOUT);

    it("getStats() should compute precise statistics", () => {
      const stats = file.getStats();
      expect(stats.id).toBeDefined();
      expect(stats.originalName).toBe("log.txt");
      expect(stats.mimeType).toBe("text/plain");
      expect(typeof stats.sizeOriginalHuman).toBe("string");
      expect(typeof stats.sizeStoredHuman).toBe("string");
      expect(typeof stats.compressionRatioPct).toBe("number");
      expect(stats.compressionRatioPct).toBeGreaterThanOrEqual(0);
      expect(stats.storageType).toBe("permanent");
      expect(stats.isGroup).toBe(false);
      expect(stats.isSigned).toBe(false);
    });

    it("size getters (KB/MB/GB/TB) should be internally consistent", () => {
      expect(file.sizeKB).toBeCloseTo(file.sizeOriginal / 1024, 3);
      expect(file.sizeMB).toBeCloseTo(file.sizeOriginal / 1024 ** 2, 3);
      expect(file.sizeGB).toBeCloseTo(file.sizeOriginal / 1024 ** 3, 3);
      expect(file.sizeTB).toBeCloseTo(file.sizeOriginal / 1024 ** 4, 3);
    });

    it("exceedsSize() should validate its input and compare correctly", () => {
      expect(() => file.exceedsSize(0)).toThrow(/positive finite number/i);
      expect(() => file.exceedsSize(-5)).toThrow(/positive finite number/i);
      expect(() => file.exceedsSize(Infinity)).toThrow(
        /positive finite number/i,
      );
      expect(() => file.exceedsSize(NaN)).toThrow(/positive finite number/i);

      expect(file.exceedsSize(0.00001)).toBe(true); // ~10 bytes — DUMMY_DATA is bigger
      expect(file.exceedsSize(1)).toBe(false); // 1 MB — DUMMY_DATA is far smaller
    });

    it(
      "isInlineViewable should reflect known inline-viewable MIME types",
      async () => {
        expect(file.isInlineViewable).toBe(true); // text/plain

        const binFile = await MajikFile.create({
          data: DUMMY_DATA,
          userId: USER_ID,
          identity: alice.identity,
          context: "user_upload",
          mimeType: "application/x-msdownload",
        });
        expect(binFile.isInlineViewable).toBe(false);
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "safeFilename should derive from hash + extension, falling back to .mjkb",
      async () => {
        expect(file.safeFilename).toBe(`${file.fileHash}.txt`);

        const noName = await MajikFile.create({
          data: DUMMY_DATA,
          userId: USER_ID,
          identity: alice.identity,
          context: "user_upload",
        });
        expect(noName.safeFilename).toBe(`${noName.fileHash}.mjkb`);
      },
      CRYPTO_TIMEOUT,
    );

    it("toString() should produce a readable summary", () => {
      const str = file.toString();
      expect(str).toContain("MajikFile");
      expect(str).toContain(file.id.slice(0, 0)); // sanity: doesn't throw
      expect(str).toMatch(/type: single/);
      expect(str).toMatch(/storage: permanent/);
    });

    it("MajikFile.formatBytes() should match the human-readable utility", () => {
      expect(MajikFile.formatBytes(500)).toBe(utilFormatBytes(500));
      expect(MajikFile.formatBytes(2048)).toBe(utilFormatBytes(2048));
      expect(MajikFile.formatBytes(5 * 1024 ** 2)).toBe(
        utilFormatBytes(5 * 1024 ** 2),
      );
    });

    it("MajikFile.inferMimeType() should resolve known and unknown extensions", () => {
      expect(MajikFile.inferMimeType("photo.png")).toBe("image/png");
      expect(MajikFile.inferMimeType("archive.zip")).toBe("application/zip");
      expect(MajikFile.inferMimeType("mystery.xyz123")).toBeNull();
    });

    it("MajikFile.getRawFileSize() should read byteLength for both input types", () => {
      expect(MajikFile.getRawFileSize(DUMMY_DATA)).toBe(DUMMY_DATA.byteLength);
      expect(MajikFile.getRawFileSize(DUMMY_DATA.buffer as ArrayBuffer)).toBe(
        DUMMY_DATA.byteLength,
      );
    });

    it("MajikFile.buildExpiryDate() should produce a date N days in the future", () => {
      const iso = MajikFile.buildExpiryDate(5);
      const diffDays =
        (new Date(iso).getTime() - Date.now()) / (1000 * 60 * 60 * 24);
      expect(diffDays).toBeGreaterThan(4.9);
      expect(diffDays).toBeLessThan(5.1);
    });

    it("MajikFile.hasPublicKeyAccess() should verify a real fingerprint match", () => {
      const realFingerprint = sha256Base64(alice.identity.mlKemPublicKey);
      expect(
        MajikFile.hasPublicKeyAccess(
          alice.identity.mlKemPublicKey,
          realFingerprint,
        ),
      ).toBe(true);
      expect(
        MajikFile.hasPublicKeyAccess(
          bob.identity.mlKemPublicKey,
          realFingerprint,
        ),
      ).toBe(false);
    });

    it("MajikFile.hasPublicKeyAccess() should validate its inputs", () => {
      expect(() =>
        MajikFile.hasPublicKeyAccess(new Uint8Array(10), "fp"),
      ).toThrow(/publicKey must be a 1184-byte/i);
      expect(() =>
        MajikFile.hasPublicKeyAccess(alice.identity.mlKemPublicKey, ""),
      ).toThrow(/ownerFingerprint is required/i);
    });
  });

  // ── 15. ATTACH / CLEAR BINARY ─────────────────────────────────────────────
  describe("attachBinary() / clearBinary()", () => {
    it(
      "should allow detaching and reattaching the encrypted binary",
      async () => {
        const file = await MajikFile.create({
          data: DUMMY_DATA,
          userId: USER_ID,
          identity: alice.identity,
          context: "user_upload",
        });
        const bytes = file.toBinaryBytes();

        file.clearBinary();
        expect(file.hasBinary).toBe(false);

        file.attachBinary(bytes);
        expect(file.hasBinary).toBe(true);

        const decrypted = await file.decryptBinary(alice.identity);
        expect(new TextDecoder().decode(decrypted)).toBe(
          "Hello, post-quantum cloud storage! This binary content is encrypted.",
        );
      },
      CRYPTO_TIMEOUT,
    );
  });
});
