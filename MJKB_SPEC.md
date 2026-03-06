# MJKB — Majik Binary Container Format

**File Extension:** `.mjkb`  
**Proposed Media Type:** `application/vnd.majikah.bundle`  
**Category:** Secure binary container format  
**Specification Version:** 1.0  
**Format Version Byte:** `0x01`  
**Status:** Draft / Implementation-aligned

---

## Contents

- [MJKB — Majik Binary Container Format](#mjkb--majik-binary-container-format)
  - [Contents](#contents)
  - [1. Overview](#1-overview)
  - [2. Design Goals](#2-design-goals)
  - [3. Cryptographic Model](#3-cryptographic-model)
    - [3.1 Key Encapsulation — Single Recipient](#31-key-encapsulation--single-recipient)
    - [3.2 Key Encapsulation — Multiple Recipients](#32-key-encapsulation--multiple-recipients)
    - [3.3 Symmetric Encryption](#33-symmetric-encryption)
    - [3.4 Compression](#34-compression)
    - [3.5 Randomness](#35-randomness)
  - [4. Binary Layout](#4-binary-layout)
    - [4.1 Fixed Header](#41-fixed-header)
    - [4.2 Payload JSON — Single Recipient](#42-payload-json--single-recipient)
    - [4.3 Payload JSON — Multiple Recipients](#43-payload-json--multiple-recipients)
    - [4.4 Ciphertext Section](#44-ciphertext-section)
  - [5. Field Definitions](#5-field-definitions)
  - [6. Payload JSON Schema](#6-payload-json-schema)
    - [6.1 Single-Recipient Payload](#61-single-recipient-payload)
    - [6.2 Group Payload](#62-group-payload)
    - [6.3 Payload Discrimination](#63-payload-discrimination)
  - [7. Encryption Pipeline](#7-encryption-pipeline)
  - [8. Decryption and Parsing Algorithm](#8-decryption-and-parsing-algorithm)
  - [9. Cryptographic Parameters](#9-cryptographic-parameters)
  - [10. Security Considerations](#10-security-considerations)
  - [11. File Identification](#11-file-identification)
  - [12. MIME Type](#12-mime-type)
  - [13. Versioning](#13-versioning)
  - [14. Reference Implementation](#14-reference-implementation)
  - [Author](#author)

---

## 1. Overview

**MJKB (Majik Binary Container)** is a self-contained secure binary container format for confidential file transport and storage. A single `.mjkb` file contains everything required to decrypt it: the IV, all key encapsulation material, optional filename and MIME type metadata, and the authenticated ciphertext. No sidecar files are required.

The format supports both single-recipient and multi-recipient encryption using a hybrid construction: **ML-KEM-768 (FIPS 203)** for post-quantum key encapsulation and **AES-256-GCM** for authenticated symmetric encryption.

The format is defined by and implemented in the **MajikFile** TypeScript library, used within the **Majik Message** ecosystem. This specification is implementation-aligned: all field sizes, encodings, and invariants described here are derived directly from the reference implementation and are normative for format version `0x01`.

---

## 2. Design Goals

**Security**
- Post-quantum key encapsulation using ML-KEM-768 (FIPS 203 / CRYSTALS-Kyber)
- Authenticated encryption via AES-256-GCM; ciphertext integrity is always verified before use
- IV is per-file random; key material is never reused across files

**Simplicity**
- Minimal fixed header (21 bytes)
- Single variable-length JSON section carries all key material and metadata
- No nested containers, no optional header fields, no flags byte

**Self-containment**
- All decryption inputs (IV, key encapsulation ciphertext, filename, MIME type) are embedded in the binary
- Decryption requires only the `.mjkb` file and the recipient's secret key

**Compactness**
- Short payload JSON keys (`n`, `m`) minimise per-file overhead
- Optional Zstd compression at level 22 before encryption for compressible content types

**Limitations (not design goals)**
- Not streaming-friendly: the entire file is loaded into memory during both encryption and decryption
- Browser-only in the reference implementation: depends on `crypto.getRandomValues`, `Blob`, `Canvas API`
- No associated data (AD) is supplied to AES-GCM in the current implementation

---

## 3. Cryptographic Model

MJKB uses a **hybrid encryption** construction. The precise key derivation method differs between single-recipient and multi-recipient modes.

### 3.1 Key Encapsulation — Single Recipient

```
ML-KEM-768.Encapsulate(recipientPublicKey)
  → (sharedSecret: 32 bytes, kemCipherText: 1088 bytes)

AES key = sharedSecret   ← used directly; no additional wrapping
```

The ML-KEM shared secret is used **directly** as the AES-256-GCM key. No separate random AES key is generated in single-recipient mode.

### 3.2 Key Encapsulation — Multiple Recipients

```
aesKey ← random 32 bytes (CSPRNG)

For each recipient r:
  ML-KEM-768.Encapsulate(r.publicKey)
    → (sharedSecret_r: 32 bytes, kemCipherText_r: 1088 bytes)
  encryptedAesKey_r = aesKey XOR sharedSecret_r   ← 32-byte one-time-pad

The file is encrypted once with aesKey.
Each recipient stores: (fingerprint_r, kemCipherText_r, encryptedAesKey_r)
```

Each recipient recovers `aesKey` independently:

```
sharedSecret_r = ML-KEM-768.Decapsulate(kemCipherText_r, r.secretKey)
aesKey = encryptedAesKey_r XOR sharedSecret_r
```

The XOR one-time-pad is secure because each `sharedSecret_r` is 32 bytes of output from ML-KEM encapsulation, which is computationally indistinguishable from uniform random. The owner is always prepended as the first recipient entry; the `keys` array always has at least one entry.

**Maximum recipients:** 100 (excluding the owner). Each additional recipient adds approximately 1.6 KB to the payload JSON: 1088 bytes raw KEM ciphertext → 1452 bytes base64, plus 32 bytes raw AES key → 44 bytes base64, plus ~44 bytes base64 fingerprint, plus JSON punctuation.

### 3.3 Symmetric Encryption

Algorithm: **AES-256-GCM**

| Parameter          | Value                                                                 |
| ------------------ | --------------------------------------------------------------------- |
| Key length         | 32 bytes (256 bits)                                                   |
| IV length          | 12 bytes (96 bits), randomly generated per file                       |
| Authentication tag | 16 bytes (128 bits), appended to ciphertext by the GCM implementation |
| Associated data    | None used in version `0x01`                                           |

The 16-byte authentication tag is **not** stored as a separate field. It is appended to the ciphertext bytes by the GCM `seal` operation and verified by the GCM `open` operation. The ciphertext section of the binary contains `len(plaintext) + 16` bytes.

**Decapsulation and wrong-key behaviour:** ML-KEM decapsulation is deterministic and does not throw or signal failure when given a wrong secret key — it returns a different shared secret. Authentication failure is detected by AES-GCM: `open` returns null when the tag does not verify, and the implementation treats this as a decryption failure. No partial plaintext is returned.

### 3.4 Compression

Zstd at compression level 22 is applied to plaintext bytes **before** encryption when the resolved MIME type is not on the incompressible list (JPEG, WebP, AVIF, HEIC, HEIF, JXL, all video, lossy audio, ZIP, gzip, 7z, rar, bzip2, xz, .docx/.xlsx/.pptx/.epub). If the MIME type is unknown or null, compression is applied. Compression is skipped for pre-compressed codec formats where Zstd would yield negligible savings.

This step is part of the reference implementation's encryption pipeline, not a flag stored in the binary. Decoders must always attempt Zstd decompression after AES-GCM decryption. If decompression fails on data that was not compressed, Zstd will return an error — callers should handle this case.

### 3.5 Randomness

All cryptographic randomness is sourced from `crypto.getRandomValues()` (Web Crypto API). This covers:

- The 12-byte AES-GCM IV
- The 32-byte group AES key (multi-recipient mode only)

ML-KEM encapsulation uses its own internal CSPRNG seeded from `crypto.getRandomValues()` via the underlying `@noble/post-quantum` library.

---

## 4. Binary Layout

All multi-byte integer fields are **big-endian**.

### 4.1 Fixed Header

The first 21 bytes of every `.mjkb` file are a fixed-size header:

```
Offset  Length  Field
──────  ──────  ──────────────────────────────────────────────────
0       4       Magic bytes: ASCII "MJKB" (0x4D 0x4A 0x4B 0x42)
4       1       Format version: 0x01
5       12      AES-GCM IV (random, 96 bits)
17      4       Payload JSON byte length (big-endian uint32)
21      N       Payload JSON (UTF-8)
21+N    M       AES-GCM ciphertext (Zstd-compressed plaintext + 16-byte GCM auth tag)
```

There is no flags byte, no KEM ciphertext length field, no metadata length field, and no IV length field. The IV length is always exactly 12 bytes. The authentication tag is not a separate trailing field.

### 4.2 Payload JSON — Single Recipient

The payload JSON contains the ML-KEM-768 ciphertext (base64-encoded) and optional file metadata:

```json
{
  "mlKemCipherText": "<base64-encoded 1088-byte ML-KEM-768 ciphertext>",
  "n": "photo.png",
  "m": "image/png"
}
```

`n` (original filename) and `m` (MIME type) are required fields that may be `null` if not provided at encryption time.

### 4.3 Payload JSON — Multiple Recipients

```json
{
  "keys": [
    {
      "fingerprint": "<base64 SHA-256 of recipient public key>",
      "mlKemCipherText": "<base64-encoded 1088-byte ML-KEM-768 ciphertext>",
      "encryptedAesKey": "<base64-encoded 32-byte XOR-wrapped group AES key>"
    },
    ...
  ],
  "n": "photo.png",
  "m": "image/png"
}
```

The `keys` array always contains at least one entry (the owner). The owner's entry is always first.

### 4.4 Ciphertext Section

The ciphertext section begins at byte offset `21 + N` (where N is the payload JSON length read from bytes 17–20) and extends to the end of the file. Its length in bytes is:

```
M = len(compressed_plaintext) + 16
```

The 16-byte AES-GCM authentication tag is the last 16 bytes of this section, appended by the GCM `seal` operation. Parsers must not assume a fixed ciphertext length.

---

## 5. Field Definitions

| Field          | Offset | Length   | Encoding          | Description                                                                                     |
| -------------- | ------ | -------- | ----------------- | ----------------------------------------------------------------------------------------------- |
| Magic          | 0      | 4 bytes  | Raw bytes         | ASCII "MJKB" — `0x4D 0x4A 0x4B 0x42`                                                            |
| Version        | 4      | 1 byte   | Unsigned integer  | Format version. Current: `0x01`                                                                 |
| IV             | 5      | 12 bytes | Raw bytes         | AES-GCM initialization vector. Randomly generated per file. Must not repeat with the same key.  |
| Payload length | 17     | 4 bytes  | Big-endian uint32 | Byte length of the following payload JSON section                                               |
| Payload JSON   | 21     | N bytes  | UTF-8 JSON        | `MjkbSinglePayload` or `MjkbGroupPayload` — see Section 6                                       |
| Ciphertext     | 21+N   | M bytes  | Raw bytes         | AES-GCM ciphertext. Includes the 16-byte authentication tag appended by the GCM implementation. |

**Total fixed header size:** 21 bytes.

---

## 6. Payload JSON Schema

The payload JSON encodes all key material and file metadata. It is parsed after reading the payload length field. Two schemas are defined, discriminated by the presence or absence of the `keys` field.

### 6.1 Single-Recipient Payload

```typescript
interface MjkbSinglePayload {
  mlKemCipherText: string   // base64, always 1452 chars (1088 raw bytes)
  n: string | null          // original filename, e.g. "photo.png"
  m: string | null          // MIME type, e.g. "image/png"
}
```

### 6.2 Group Payload

```typescript
interface MajikFileGroupKey {
  fingerprint: string       // base64 SHA-256 of recipient ML-KEM public key (~44 chars)
  mlKemCipherText: string   // base64, always 1452 chars (1088 raw bytes)
  encryptedAesKey: string   // base64, always 44 chars (32 raw bytes)
}

interface MjkbGroupPayload {
  keys: MajikFileGroupKey[] // minimum 1 entry (the owner); maximum 101 entries (owner + 100 recipients)
  n: string | null          // original filename
  m: string | null          // MIME type
}
```

### 6.3 Payload Discrimination

Parsers discriminate between payload types as follows:

- If the parsed JSON object contains a `keys` field that is an array → `MjkbGroupPayload`
- If the parsed JSON object contains a `mlKemCipherText` field and no `keys` field → `MjkbSinglePayload`
- Otherwise → format error; container must be rejected

The `n` and `m` fields are present in both schemas and may be `null`. Implementations must handle `null` gracefully. Files encrypted without a filename or MIME type will have `null` for both fields.

---

## 7. Encryption Pipeline

The full encryption pipeline, in order:

```
1. Input: raw plaintext bytes

2. SHA-256 hash of raw bytes
   → file_hash (hex, 64 chars)
   Used for duplicate detection. Computed before any transformation.

3. [Optional] Image → WebP conversion
   Applies only in specific application contexts (chat attachments).
   Not encoded in the binary; transparent to the format.

4. [Conditional] Zstd compress at level 22
   Applied if MIME type is not on the incompressible list.
   If mimeType is null, compression is applied.
   Result: compressed_plaintext

5. Generate IV: 12 random bytes (crypto.getRandomValues)

6a. [Single recipient]
    ML-KEM-768.Encapsulate(ownerPublicKey)
      → sharedSecret (32 bytes)   ← AES key
      → kemCipherText (1088 bytes)
    Build payload: { mlKemCipherText: base64(kemCipherText), n, m }

6b. [Multiple recipients]
    aesKey ← 32 random bytes (crypto.getRandomValues)
    For each recipient (owner first, then additional):
      ML-KEM-768.Encapsulate(recipient.publicKey)
        → sharedSecret_r (32 bytes)
        → kemCipherText_r (1088 bytes)
      encryptedAesKey_r = aesKey XOR sharedSecret_r
    Build payload: { keys: [...], n, m }

7. AES-256-GCM.seal(key=aesKey, iv=IV, plaintext=compressed_plaintext)
   → ciphertext (len(compressed_plaintext) + 16 bytes, tag appended)

8. Encode binary:
   magic(4) | version(1) | iv(12) | payloadLen(4) | payloadJSON(N) | ciphertext(M)
```

---

## 8. Decryption and Parsing Algorithm

Parsers must follow this sequence. Failing at any step must terminate parsing and report an error. No partial output may be returned.

```
1. Read first 4 bytes. Verify magic = 0x4D 0x4A 0x4B 0x42.
   Error if mismatch: FORMAT_ERROR

2. Read byte at offset 4. Verify version = 0x01.
   Error if unsupported: UNSUPPORTED_VERSION

3. Read bytes 5–16 (12 bytes): IV.

4. Read bytes 17–20 (4 bytes, big-endian uint32): payloadLen.
   Verify payloadLen > 0 and file is at least 21 + payloadLen + 1 bytes.
   Error if not: FORMAT_ERROR

5. Read bytes 21 to 21+payloadLen: payload JSON (UTF-8).
   Parse as JSON. Error if malformed: FORMAT_ERROR
   Discriminate payload type per Section 6.3.

6a. [Single payload]
    Decode mlKemCipherText from base64 → 1088 bytes.
    ML-KEM-768.Decapsulate(kemCipherText, identity.secretKey)
      → sharedSecret (32 bytes) = aesKey

6b. [Group payload]
    Locate entry in keys[] where entry.fingerprint == identity.fingerprint.
    Error if not found: DECRYPTION_FAILED (access denied)
    Decode entry.mlKemCipherText from base64 → 1088 bytes.
    ML-KEM-768.Decapsulate(kemCipherText, identity.secretKey)
      → sharedSecret (32 bytes)
    Decode entry.encryptedAesKey from base64 → 32 bytes.
    aesKey = encryptedAesKey XOR sharedSecret

7. Read bytes from offset 21+payloadLen to end of file: ciphertext (includes auth tag).

8. AES-256-GCM.open(key=aesKey, iv=IV, ciphertext)
   → compressed_plaintext, or null if auth tag verification fails.
   Error if null: DECRYPTION_FAILED (wrong key or corrupted file)
   Authentication tag is verified by the GCM open operation. No partial plaintext
   is returned before tag verification succeeds.

9. Zstd decompress compressed_plaintext.
   If the plaintext was not compressed at encryption time, Zstd decompression
   will fail. Callers may need to handle this case if they cannot determine
   whether compression was applied.
   Error if decompression fails: DECOMPRESSION_FAILED

10. Return plaintext bytes, and payload.n / payload.m for filename and MIME type.
    payload.n and payload.m may be null.
```

---

## 9. Cryptographic Parameters

| Primitive              | Algorithm                | Parameters                                                                                      |
| ---------------------- | ------------------------ | ----------------------------------------------------------------------------------------------- |
| Key encapsulation      | ML-KEM-768 (FIPS 203)    | Public key: 1184 bytes; Secret key: 2400 bytes; Ciphertext: 1088 bytes; Shared secret: 32 bytes |
| Symmetric encryption   | AES-256-GCM              | Key: 32 bytes; IV: 12 bytes; Auth tag: 16 bytes (appended to ciphertext)                        |
| Compression            | Zstd                     | Level 22 (maximum); conditional on MIME type                                                    |
| Deduplication hash     | SHA-256                  | Hex-encoded; computed over raw plaintext bytes pre-compression                                  |
| Public key fingerprint | SHA-256                  | Base64-encoded; used to identify recipients in group payloads                                   |
| CSPRNG                 | `crypto.getRandomValues` | Used for IV and group AES key generation                                                        |

Only ML-KEM-768 is supported in format version `0x01`. ML-KEM-512 and ML-KEM-1024 are not used by this implementation.

---

## 10. Security Considerations

**Authentication before use.** The AES-GCM authentication tag covers the entire ciphertext. Implementations must not expose or use any portion of the decrypted plaintext until GCM `open` returns successfully. A null return from `open` indicates tag verification failure; the container must be rejected.

**Wrong-key behaviour.** ML-KEM decapsulation with a wrong secret key returns a computationally indistinguishable but incorrect shared secret, with no error or signal. This is by design in ML-KEM. AES-GCM authentication failure is the only observable signal of key mismatch, and it is reliable.

**IV uniqueness.** Each file's IV is randomly generated from a CSPRNG. The probability of IV collision under the same key is negligible for any practical number of files, given 12-byte IVs and fresh key material per file (single mode) or a freshly generated group key per file (multi-recipient mode).

**Key material handling.** Secret keys and shared secrets must not be logged, persisted, or transmitted. The only persistent key material in a `.mjkb` binary is the encapsulated KEM ciphertext. The AES key is recoverable from it only by the holder of the corresponding ML-KEM secret key.

**Input validation.** Parsers must validate the magic bytes, version byte, and payload length before performing any allocations or cryptographic operations. The payload length field is a user-controlled value; parsers must verify it does not exceed the remaining file length.

**No associated data.** Version `0x01` does not supply associated data (AD) to AES-GCM. The authenticated ciphertext covers only the file plaintext, not the payload JSON or header fields. Future versions may introduce header authentication.

**No key revocation.** Once a `.mjkb` container is distributed to a recipient, there is no mechanism to revoke access without deleting or replacing the container. The format contains no certificate or revocation infrastructure.

---

## 11. File Identification

| Property                | Value                                                               |
| ----------------------- | ------------------------------------------------------------------- |
| Magic bytes             | `4D 4A 4B 42`                                                       |
| ASCII representation    | `MJKB`                                                              |
| Offset                  | `0x00`                                                              |
| Minimum valid file size | 23 bytes (21-byte header + 1-byte payload JSON + 1-byte ciphertext) |

A file may be identified as a `.mjkb` candidate by checking the first 4 bytes against the magic sequence. This check does not validate the container — full parsing is required for that.

---

## 12. MIME Type

**Proposed MIME type:** `application/vnd.majikah.bundle`

**File extension:** `.mjkb`

**Example HTTP header:**

```
Content-Type: application/vnd.majikah.bundle
```

This MIME type is not yet registered with IANA. Implementations should treat any file with the `.mjkb` extension and correct magic bytes as this type.

---

## 13. Versioning

The format version byte is at offset 4 in the binary. The current and only supported version is `0x01`.

A parser encountering any version byte other than `0x01` must reject the container with an `UNSUPPORTED_VERSION` error. Parsers must not attempt to decode unknown versions.

Changes to the binary layout, payload JSON schema, or cryptographic construction require a version increment. The following are subject to change in future versions:

- Payload JSON schema (new fields, changed key names)
- Supported KEM algorithms or parameter sets
- Compression algorithm selection mechanism
- Authentication of header fields via associated data

There is no backward compatibility guarantee between version `0x01` and any future version. Existing `.mjkb` files cannot be migrated in place — they must be decrypted and re-encrypted under the new format.

---

## 14. Reference Implementation

**Library:** `@majikah/majik-file` (TypeScript)

**Supported environments:** Browser (Chrome, Firefox, Safari, Edge), Electron. The reference implementation depends on `crypto.getRandomValues`, `Blob`, `URL.createObjectURL`, and optionally `HTMLCanvasElement`. It is not compatible with Node.js or server-side environments.

**Core operations:**

| Operation              | Function                                                           |
| ---------------------- | ------------------------------------------------------------------ |
| Encode `.mjkb`         | `encodeMjkb(iv, payload, ciphertext)` in `core/utils.ts`           |
| Decode `.mjkb`         | `decodeMjkb(raw)` in `core/utils.ts`                               |
| ML-KEM-768 encapsulate | `mlKemEncapsulate(publicKey)` → `{ sharedSecret, cipherText }`     |
| ML-KEM-768 decapsulate | `mlKemDecapsulate(cipherText, secretKey)` → `sharedSecret`         |
| AES-256-GCM encrypt    | `aesGcmEncrypt(key, iv, plaintext)` → ciphertext with tag appended |
| AES-256-GCM decrypt    | `aesGcmDecrypt(key, iv, ciphertext)` → plaintext or `null`         |

**Dependencies:**

- `@noble/post-quantum` — ML-KEM-768 implementation
- `@stablelib/aes` + `@stablelib/gcm` — AES-256-GCM implementation
- `@stablelib/sha256` — SHA-256 for file hashing and fingerprints
- `@bokuweb/zstd-wasm` — Zstd compression/decompression (WASM)

---

## Author

Made with 💙 by [@thezelijah](https://github.com/jedlsf)

**Developer:** Josef Elijah Fabian  
**GitHub:** [https://github.com/jedlsf](https://github.com/jedlsf)  
**Project Repository:** [https://github.com/Majikah/majik-file](https://github.com/Majikah/majik-file)  
**Business Email:** [business@thezelijah.world](mailto:business@thezelijah.world)  
**Website:** [https://www.thezelijah.world](https://www.thezelijah.world)