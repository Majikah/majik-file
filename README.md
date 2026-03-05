# Majik File

[![Developed by Zelijah](https://img.shields.io/badge/Developed%20by-Zelijah-red?logo=github&logoColor=white)](https://thezelijah.world) ![GitHub Sponsors](https://img.shields.io/github/sponsors/jedlsf?style=plastic&label=Sponsors&link=https%3A%2F%2Fgithub.com%2Fsponsors%2Fjedlsf)

Post-quantum file encryption for the Majik Message platform. Produces self-contained `.mjkb` binary files — sealed with **ML-KEM-768 + AES-256-GCM**, optionally Zstd-compressed, readable without any network access.

This library is designed to work within the **Majik Message ecosystem**. It expects callers to supply ML-KEM-768 key material from an identity store; it does not generate or persist keys itself.

![npm](https://img.shields.io/npm/v/@majikah/majik-file) ![npm downloads](https://img.shields.io/npm/dm/@majikah/majik-file) ![npm bundle size](https://img.shields.io/bundlephobia/min/%40majikah%2Fmajik-file) [![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) ![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue)


---
Contents

- [Majik File](#majik-file)
  - [How it works](#how-it-works)
  - [The .mjkb binary format](#the-mjkb-binary-format)
  - [Encryption modes](#encryption-modes)
    - [Single-recipient](#single-recipient)
    - [Group](#group)
  - [Compression behaviour](#compression-behaviour)
  - [Installation](#installation)
  - [Quick start](#quick-start)
    - [Encrypt a file (self, single recipient)](#encrypt-a-file-self-single-recipient)
    - [Decrypt a file](#decrypt-a-file)
    - [Encrypt for multiple recipients](#encrypt-for-multiple-recipients)
    - [Temporary files](#temporary-files)
    - [Chat images](#chat-images)
  - [API reference](#api-reference)
    - [`MajikFile.create(options)`](#majikfilecreateoptions)
      - [`CreateOptions`](#createoptions)
    - [`MajikFile.decrypt(source, identity)`](#majikfiledecryptsource-identity)
    - [`MajikFile.decryptWithMetadata(source, identity)`](#majikfiledecryptwithmetadatasource-identity)
    - [`MajikFile.fromJSON(json, binary?)`](#majikfilefromjsonjson-binary)
    - [Instance methods](#instance-methods)
    - [Static helpers](#static-helpers)
  - [Type reference](#type-reference)
    - [`MajikFileIdentity`](#majikfileidentity)
    - [`MajikFileRecipient`](#majikfilerecipient)
    - [`MajikFileGroupKey` (embedded in group `.mjkb`)](#majikfilegroupkey-embedded-in-group-mjkb)
    - [`MjkbSinglePayload`](#mjkbsinglepayload)
    - [`MjkbGroupPayload`](#mjkbgrouppayload)
    - [`MajikFileJSON`](#majikfilejson)
    - [`FileContext`](#filecontext)
    - [`MajikFileStats`](#majikfilestats)
  - [Error handling](#error-handling)
    - [Error codes](#error-codes)
  - [Storage model](#storage-model)
  - [Limitations and honest caveats](#limitations-and-honest-caveats)
  - [Cryptographic Parameters](#cryptographic-parameters)
  - [Related Projects](#related-projects)
    - [Majik Message](#majik-message)
    - [Majik Key](#majik-key)
    - [Majik Envelope](#majik-envelope)
  - [Contributing](#contributing)
  - [License](#license)
  - [Author](#author)
  - [About the Developer](#about-the-developer)
  - [Contact](#contact)


## How it works

```
raw bytes
  │
  ├─ SHA-256 hash (pre-compression — used for dedup)
  │
  ├─ [chat_image / chat_attachment only]
  │   WebP conversion via Canvas API (PNG/JPEG/GIF/BMP → WebP at quality 0.88)
  │   Skipped for SVG, HEIC, HEIF, JXL — browser cannot encode these
  │
  ├─ Zstd compress at level 22
  │   Skipped for pre-compressed formats (JPEG, WebP, AVIF, video, audio, archives, Office XML)
  │
  ├─ [single recipient]
  │   ML-KEM-768 encapsulate(ownerPublicKey)
  │   → sharedSecret (32 bytes) used directly as AES-256-GCM key
  │
  ├─ [group — 2+ recipients]
  │   Random 32-byte AES key encrypts the file once
  │   Per recipient: ML-KEM-768 encapsulate(recipientPublicKey)
  │   → encryptedAesKey = aesKey XOR sharedSecret
  │
  └─ AES-256-GCM encrypt (12-byte random IV, 16-byte auth tag)
       → .mjkb binary
```

The encrypted binary is self-contained: the IV, all key material, original filename, and MIME type are embedded inside the file. No sidecar files or database records are required to decrypt.

---

## The .mjkb binary format

Version: `0x01`

```
┌──────────────────────────────────────────────────────┐
│  4 bytes  │  Magic: ASCII "MJKB"  (0x4D 0x4A 0x4B 0x42)  │
│  1 byte   │  Version (currently 0x01)                      │
│ 12 bytes  │  AES-GCM IV (random per file)                  │
│  4 bytes  │  Payload JSON length (big-endian uint32)        │
│  N bytes  │  Payload JSON (UTF-8)                           │
│  M bytes  │  AES-GCM ciphertext (compressed plaintext + 16-byte auth tag) │
└──────────────────────────────────────────────────────┘

Fixed header: 21 bytes (before variable payload JSON)
```

**Single-recipient payload JSON:**
```json
{
  "mlKemCipherText": "<base64, 1088 bytes>",
  "n": "photo.png",
  "m": "image/png"
}
```

**Group payload JSON:**
```json
{
  "keys": [
    {
      "fingerprint": "<base64 SHA-256 of public key>",
      "mlKemCipherText": "<base64, 1088 bytes>",
      "encryptedAesKey": "<base64, 32 bytes>"
    }
  ],
  "n": "photo.png",
  "m": "image/png"
}
```

`n` and `m` use short keys to minimise binary overhead (~30–50 extra bytes per file). Both fields are `string | null` — null when encryption was called without providing `originalName` / `mimeType`.

**Per-recipient overhead in group mode:** ~1.5 KB (1088-byte ML-KEM ciphertext + 32-byte encrypted AES key, base64-encoded).

---

## Encryption modes

### Single-recipient

Used when no `recipients` are passed, or when `recipients` is empty after deduplication. The ML-KEM shared secret is used directly as the AES-256-GCM key. The owner is the only entity who can decrypt.

### Group

Used when one or more `recipients` are supplied. The file is encrypted once with a random 32-byte AES key. Each recipient — including the owner, who is always prepended automatically — gets their own ML-KEM encapsulation entry:

```
encryptedAesKey = groupAesKey XOR mlKemSharedSecret
```

This is safe because ML-KEM shared secrets are 32 uniformly random bytes, making the XOR a one-time pad for the group key. Each recipient can independently recover `groupAesKey` using only their own secret key.

**Recipient deduplication:** If the owner's own fingerprint appears in `recipients`, it is silently removed (not an error). Duplicate fingerprints in `recipients` are also silently deduplicated — first occurrence wins.

**Limit:** Maximum 100 recipients (excluding the owner) per file. Exceeding this throws `MajikFileError("INVALID_INPUT")`.

---

## Compression behaviour

Zstd compression at level 22 is applied selectively. Files whose MIME types indicate they are already compressed at the codec level are passed through uncompressed:

| Skipped (already compressed) | Compressed with Zstd lv.22 |
|---|---|
| JPEG, WebP, AVIF, HEIC, HEIF, JXL | PNG, BMP, TIFF, SVG, GIF |
| All video (mp4, webm, mkv, mov, …) | WAV, FLAC, AIFF |
| Lossy audio (mp3, aac, ogg, opus, …) | PDF, JSON, XML, CSV |
| ZIP, gzip, 7z, rar, bzip2, xz, zstd | Plain text, source code |
| .docx, .xlsx, .pptx, .epub | SQLite databases |

If `mimeType` is null or unknown, compression is applied (safer default).

---

## Installation

```bash
npm install @majikah/majik-file
# or
pnpm add @majikah/majik-file
```

This package requires a browser or browser-like environment (Electron, React Native with JSI) for:
- `crypto.randomUUID()` and `crypto.subtle` (Web Crypto)
- `Blob` / `URL.createObjectURL` for WebP conversion
- `HTMLCanvasElement` for image re-encoding (only needed for `chat_image` / `chat_attachment` contexts)

Node.js is not a supported target.

---

## Quick start

### Encrypt a file (self, single recipient)

```typescript
import { MajikFile } from '@majikah/majik-file'

// identity comes from your key store — MajikFile does not generate keys
const identity = {
  userId: 'user-uuid',
  fingerprint: 'base64-sha256-of-public-key',
  mlKemPublicKey: new Uint8Array(1184),  // ML-KEM-768 public key
  mlKemSecretKey: new Uint8Array(2400),  // ML-KEM-768 secret key
}

const fileBytes = await file.arrayBuffer()

const majikFile = await MajikFile.create({
  data: fileBytes,
  identity,
  context: 'user_upload',
  originalName: file.name,
  mimeType: file.type,
})

// Export the encrypted binary
const blob = majikFile.toMJKB()             // Blob — upload to R2
const metadata = majikFile.toJSON()         // MajikFileJSON — insert into Supabase
```

### Decrypt a file

```typescript
const { bytes, originalName, mimeType } = await MajikFile.decryptWithMetadata(
  mjkbBlob,
  { fingerprint: identity.fingerprint, mlKemSecretKey: identity.mlKemSecretKey }
)

const recovered = new Blob([bytes], { type: mimeType ?? 'application/octet-stream' })
```

### Encrypt for multiple recipients

```typescript
const majikFile = await MajikFile.create({
  data: fileBytes,
  identity: senderIdentity,
  recipients: [
    { fingerprint: 'recipient-a-fp', mlKemPublicKey: recipientAKey },
    { fingerprint: 'recipient-b-fp', mlKemPublicKey: recipientBKey },
  ],
  context: 'chat_attachment',
  originalName: 'report.pdf',
  mimeType: 'application/pdf',
})
```

Any of the three principals (sender, recipient A, recipient B) can decrypt using only their own `mlKemSecretKey`.

### Temporary files

```typescript
const majikFile = await MajikFile.create({
  data: fileBytes,
  identity,
  context: 'user_upload',
  isTemporary: true,
  expiresAt: MajikFile.buildExpiryDate(7), // 7 days from now
})
```

### Chat images

```typescript
const majikFile = await MajikFile.create({
  data: imageBytes,
  identity,
  context: 'chat_image',         // triggers automatic WebP conversion
  conversationId: 'conv-uuid',   // required for chat_image
  mimeType: 'image/png',
})
```

---

## API reference

### `MajikFile.create(options)`

```typescript
static async create(options: CreateOptions): Promise<MajikFile>
```

Encrypts raw bytes and returns a `MajikFile` instance with both `_binary` (the `.mjkb`) and metadata populated. Throws `MajikFileError` on validation or crypto failure.

#### `CreateOptions`

| Field | Type | Required | Description |
|---|---|---|---|
| `data` | `Uint8Array \| ArrayBuffer` | ✓ | Raw file bytes to encrypt |
| `identity` | `MajikFileIdentity` | ✓ | Owner's full identity (both keys) |
| `context` | `FileContext` | ✓ | `user_upload` \| `chat_attachment` \| `chat_image` \| `thread_attachment` |
| `recipients` | `MajikFileRecipient[]` | — | Additional recipients. Empty → single-recipient mode |
| `originalName` | `string` | — | Original filename (e.g. `"photo.png"`). Embedded in `.mjkb` payload |
| `mimeType` | `string` | — | MIME type. Inferred from `originalName` extension if omitted |
| `isTemporary` | `boolean` | — | Default `false`. Routes to `files/public/` R2 prefix |
| `isShared` | `boolean` | — | Default `false`. Enables `toggleSharing()` |
| `id` | `string` | — | Pre-computed UUID. Auto-generated if omitted |
| `bypassSizeLimit` | `boolean` | — | Default `false`. Bypasses the 100 MB file size cap |
| `expiresAt` | `string` | — | ISO-8601. Required when `isTemporary = true` |
| `chatMessageId` | `string` | — | FK → `majik_message_chat.id`. Mutually exclusive with `threadMessageId` |
| `threadMessageId` | `string` | — | FK → `majik_message_thread.id`. Mutually exclusive with `chatMessageId` |
| `conversationId` | `string` | — | Required when `context = "chat_image"`. Scopes the R2 key |

**Context behaviour:**

| Context | WebP conversion | R2 prefix |
|---|---|---|
| `user_upload` | No | `files/user/<userId>/<hash>.mjkb` |
| `chat_attachment` | Yes (images only) | `files/user/<userId>/<hash>.mjkb` |
| `chat_image` | Yes (always) | `images/chats/<conversationId>/<userId>_<hash>.mjkb` |
| `thread_attachment` | No | `files/user/<userId>/<hash>.mjkb` |

---

### `MajikFile.decrypt(source, identity)`

```typescript
static async decrypt(
  source: Blob | Uint8Array | ArrayBuffer,
  identity: Pick<MajikFileIdentity, 'fingerprint' | 'mlKemSecretKey'>
): Promise<Uint8Array>
```

Decrypts a `.mjkb` binary and returns the raw plaintext bytes. Does not return filename or MIME type — use `decryptWithMetadata()` if you need those.

**Note on wrong keys:** ML-KEM decapsulation never throws on a wrong key — it silently returns a garbage shared secret. AES-GCM authentication detects this and causes a `MajikFileError("DECRYPTION_FAILED")`.

---

### `MajikFile.decryptWithMetadata(source, identity)`

```typescript
static async decryptWithMetadata(
  source: Blob | Uint8Array | ArrayBuffer,
  identity: Pick<MajikFileIdentity, 'fingerprint' | 'mlKemSecretKey'>
): Promise<{
  bytes: Uint8Array
  originalName: string | null
  mimeType: string | null
}>
```

Preferred method for UI use. Returns decrypted bytes alongside `originalName` and `mimeType` read directly from the `.mjkb` payload JSON — no second parse required.

`originalName` and `mimeType` will be `null` for files encrypted without those fields (i.e. encrypted before the `n`/`m` payload fields were introduced, or when `originalName`/`mimeType` were not provided at encryption time). Callers should implement fallbacks.

---

### `MajikFile.fromJSON(json, binary?)`

```typescript
static fromJSON(
  json: MajikFileJSON,
  binary?: Uint8Array | ArrayBuffer | null
): MajikFile
```

Restores a `MajikFile` instance from a Supabase row. The binary is optional — if omitted, the instance is metadata-only (calling `toMJKB()` or `decryptBinary()` will throw `MISSING_BINARY`). R2 prefix validation is intentionally skipped here to tolerate rows from older schema versions.

```typescript
static async fromJSONWithBlob(json: MajikFileJSON, binary: Blob): Promise<MajikFile>
```

Async variant that accepts a `Blob` (e.g. fetched from R2).

---

### Instance methods

| Method | Returns | Description |
|---|---|---|
| `toJSON()` | `MajikFileJSON` | Serialise metadata for Supabase. Binary is excluded |
| `toMJKB()` | `Blob` | Export encrypted binary as `application/octet-stream` Blob for R2 upload |
| `toBinaryBytes()` | `Uint8Array` | Export encrypted binary as raw bytes |
| `decryptBinary(identity)` | `Promise<Uint8Array>` | Decrypt the in-memory binary. Throws if binary not loaded |
| `validate()` | `void` | Validate all metadata invariants. Throws `MajikFileError` on failure |
| `attachBinary(binary)` | `void` | Load or replace the encrypted binary in memory |
| `clearBinary()` | `void` | Free the in-memory binary after upload |
| `toggleSharing(token?)` | `string \| null` | Toggle share token on/off. Returns active token or null |
| `userIsOwner(userId)` | `boolean` | Check if `userId` matches this file's owner |
| `exceedsSize(limitMB)` | `boolean` | True if original size exceeds the given MB limit |
| `isDuplicateOf(other)` | `boolean` | Compare by SHA-256 `file_hash` |
| `getStats()` | `MajikFileStats` | Human-readable stats snapshot |
| `toString()` | `string` | Debug string: id, hash prefix, size, mode, storage type |

**Instance getters:**

| Getter | Type | Description |
|---|---|---|
| `id` | `string` | UUID primary key |
| `userId` | `string` | Owner's auth UUID |
| `r2Key` | `string` | Full R2 object key |
| `originalName` | `string \| null` | Original filename from `CreateOptions` |
| `mimeType` | `string \| null` | Resolved MIME type |
| `sizeOriginal` | `number` | Plaintext byte length |
| `sizeStored` | `number` | `.mjkb` byte length |
| `sizeKB / sizeMB / sizeGB / sizeTB` | `number` | Original size in various units (3 dp) |
| `fileHash` | `string` | SHA-256 hex of original bytes (pre-compression) |
| `encryptionIv` | `string` | Hex-encoded IV (audit record — authoritative IV is in the binary) |
| `storageType` | `StorageType` | `"permanent"` or `"temporary"` |
| `isShared` | `boolean` | Whether sharing is enabled |
| `shareToken` | `string \| null` | Active share token |
| `hasShareToken` | `boolean` | Shorthand for `shareToken !== null` |
| `context` | `FileContext \| null` | File context |
| `chatMessageId` | `string \| null` | FK to chat message |
| `threadMessageId` | `string \| null` | FK to thread message |
| `conversationId` | `string \| null` | Conversation scope (chat_image only) |
| `expiresAt` | `string \| null` | ISO-8601 expiry |
| `timestamp` | `string \| null` | ISO-8601 creation time |
| `lastUpdate` | `string \| null` | ISO-8601 last mutation time |
| `hasBinary` | `boolean` | Whether encrypted binary is loaded in memory |
| `isGroup` | `boolean` | Whether the file has multiple recipient key entries |
| `isSingle` | `boolean` | `!isGroup` |
| `isExpired` | `boolean` | Whether `expiresAt` is in the past |
| `isTemporary` | `boolean` | `storageType === "temporary"` |
| `isInlineViewable` | `boolean` | Whether MIME type can render inline in a browser |
| `safeFilename` | `string` | `<fileHash><ext>` — safe download name |

---

### Static helpers

| Method | Returns | Description |
|---|---|---|
| `MajikFile.buildExpiryDate(days?)` | `string` | ISO-8601 expiry, default 15 days from now |
| `MajikFile.formatBytes(bytes)` | `string` | Human-readable size (e.g. `"4.2 MB"`) |
| `MajikFile.inferMimeType(filename)` | `string \| null` | MIME from file extension |
| `MajikFile.isMjkbCandidate(data)` | `boolean` | Magic byte check — does not fully parse |
| `MajikFile.hasPublicKeyAccess(pk, fp)` | `boolean` | SHA-256 fingerprint match — not a decryption proof |
| `MajikFile.wouldBeDuplicate(bytes, hash)` | `boolean` | Pre-flight dedup check by SHA-256 |

---

## Type reference

### `MajikFileIdentity`

```typescript
interface MajikFileIdentity {
  userId: string          // auth.users UUID
  fingerprint: string     // base64 SHA-256 of mlKemPublicKey
  mlKemPublicKey: Uint8Array  // 1184 bytes — used during encryption
  mlKemSecretKey: Uint8Array  // 2400 bytes — used during decryption
}
```

### `MajikFileRecipient`

```typescript
interface MajikFileRecipient {
  fingerprint: string         // base64 SHA-256 of mlKemPublicKey
  mlKemPublicKey: Uint8Array  // 1184 bytes
  // No secret key — it never leaves the recipient's device
}
```

### `MajikFileGroupKey` (embedded in group `.mjkb`)

```typescript
interface MajikFileGroupKey {
  fingerprint: string      // identifies which recipient this entry belongs to
  mlKemCipherText: string  // base64, 1088 bytes
  encryptedAesKey: string  // base64, 32 bytes = groupAesKey XOR mlKemSharedSecret
}
```

### `MjkbSinglePayload`

```typescript
interface MjkbSinglePayload {
  mlKemCipherText: string  // base64, 1088 bytes
  n: string | null         // original filename
  m: string | null         // MIME type
}
```

### `MjkbGroupPayload`

```typescript
interface MjkbGroupPayload {
  keys: MajikFileGroupKey[]
  n: string | null         // original filename
  m: string | null         // MIME type
}
```

### `MajikFileJSON`

Mirrors the `majikah.majik_files` Supabase table exactly. The encrypted binary is intentionally absent — it lives in R2.

```typescript
interface MajikFileJSON {
  id: string
  user_id: string
  r2_key: string
  original_name: string | null
  mime_type: string | null
  size_original: number       // plaintext bytes
  size_stored: number         // .mjkb bytes (after compression + encryption overhead)
  file_hash: string           // SHA-256 hex of original bytes
  encryption_iv: string       // hex, 12 bytes — audit record; binary header is authoritative
  storage_type: 'permanent' | 'temporary'
  is_shared: boolean
  share_token: string | null
  context: FileContext | null
  chat_message_id: string | null
  thread_message_id: string | null
  conversation_id: string | null
  expires_at: string | null
  timestamp: string | null
  last_update: string | null
}
```

### `FileContext`

```typescript
type FileContext =
  | 'user_upload'        // general file vault — no WebP conversion, no size limit with bypassSizeLimit
  | 'chat_attachment'    // message attachment — images converted to WebP
  | 'chat_image'         // inline chat image — always converted to WebP, requires conversationId
  | 'thread_attachment'  // thread attachment — no WebP conversion
```

### `MajikFileStats`

```typescript
interface MajikFileStats {
  id: string
  originalName: string | null
  mimeType: string | null
  sizeOriginalHuman: string    // e.g. "4.2 MB"
  sizeStoredHuman: string      // e.g. "1.1 MB"
  compressionRatioPct: number  // percentage reduction, clamped to 0 minimum
  fileHash: string
  storageType: StorageType
  isGroup: boolean
  context: FileContext | null
  isShared: boolean
  isExpired: boolean
  expiresAt: string | null
  timestamp: string | null
  r2Key: string
}
```

---

## Error handling

All errors thrown by this library are instances of `MajikFileError`.

```typescript
import { MajikFileError } from '@majikah/majik-file'

try {
  const file = await MajikFile.create({ ... })
} catch (err) {
  if (err instanceof MajikFileError) {
    console.error(err.code)     // MajikFileErrorCode
    console.error(err.message)
    console.error(err.cause)    // original cause if available
  }
}
```

### Error codes

| Code | When thrown |
|---|---|
| `INVALID_INPUT` | Missing required fields, wrong key sizes, incompatible option combinations (e.g. both `chatMessageId` and `threadMessageId`), recipient limit exceeded |
| `VALIDATION_FAILED` | `validate()` found inconsistent state (all violations reported at once) |
| `ENCRYPTION_FAILED` | Unexpected error during the crypto or compression pipeline |
| `DECRYPTION_FAILED` | Wrong key, corrupted ciphertext (AES-GCM auth tag mismatch), missing fingerprint in group key list |
| `FORMAT_ERROR` | Magic byte mismatch, truncated binary, malformed payload JSON |
| `SIZE_EXCEEDED` | `data.byteLength > 100 MB` and `bypassSizeLimit` is false |
| `MISSING_BINARY` | `toMJKB()`, `toBinaryBytes()`, or `decryptBinary()` called when `_binary` is null |
| `UNSUPPORTED_VERSION` | `.mjkb` version byte is not `0x01` |

**Important:** A wrong decryption key does not throw `INVALID_INPUT` — it reaches `DECRYPTION_FAILED` via AES-GCM authentication failure. This is by design: ML-KEM decapsulation is deterministic and never throws on bad input.

---

## Storage model

This library produces two distinct artefacts that must be stored separately:

| Artefact | What it is | Where it goes |
|---|---|---|
| `toMJKB()` → Blob | Encrypted binary | Cloudflare R2 at `r2_key` |
| `toJSON()` → object | Metadata record | Supabase `majikah.majik_files` table |

The library does **not** perform R2 uploads or Supabase inserts itself — it only produces the data. Upload and persistence are the caller's responsibility (typically handled by `MajikMessage.encryptFile()`).

**R2 key structure:**

```
Permanent:  files/user/<userId>/<fileHash>.mjkb
Temporary:  files/public/<userId>_<fileHash>.mjkb
Chat image: images/chats/<conversationId>/<userId>_<fileHash>.mjkb
```

Temporary files (`files/public/`) are expected to be auto-deleted by an R2 lifecycle policy targeting that prefix after ~15 days. The library enforces `expiresAt` at the metadata level, but bucket-level deletion is an infrastructure concern.

**File immutability:** `.mjkb` files are write-once. There is no `update()` or `patch()` on encrypted fields. To replace a file, delete the R2 object and Supabase row, then call `MajikFile.create()` again.

**Deduplication:** `file_hash` is a SHA-256 hex digest of the original plaintext bytes, computed pre-compression and pre-WebP-conversion. This means the same source file always produces the same hash regardless of context. Use `MajikFile.wouldBeDuplicate(rawBytes, existingHash)` to short-circuit re-encryption.

---

## Limitations and honest caveats

**Key management is your problem.** This library assumes you hand it a valid ML-KEM-768 key pair. It does not generate, store, rotate, or protect keys. Identity unlocking, passphrase-based key derivation, and secure key storage are handled elsewhere in the Majik Message stack.

**No key revocation.** Once a `.mjkb` file is encrypted for a recipient, that recipient retains access as long as they have their secret key. There is no mechanism to revoke access to an already-distributed `.mjkb` binary short of deleting it from R2.

**Metadata is partially in-band, partially out-of-band.** The `.mjkb` binary embeds `originalName` (`n`) and `mimeType` (`m`) in the payload JSON. All other metadata (`user_id`, `r2_key`, `context`, etc.) lives only in Supabase. If you have a `.mjkb` file but no database row, you can decrypt the content but not recover those fields.

**Old binaries lack `n`/`m` fields.** The payload `n`/`m` fields were added in a later revision. Files encrypted before this change will return `null` for both fields from `decryptWithMetadata()`. Callers must handle this gracefully.

**WebP conversion is best-effort.** The Canvas API conversion path can fail silently (unsupported format, canvas unavailable in the environment). In all failure cases the original bytes are used unchanged — the conversion is never a hard requirement.

**No streaming.** The entire file is read into memory before encryption and held in memory after decryption. This is a deliberate simplicity trade-off; it is not suitable for multi-GB files even with `bypassSizeLimit: true`.

**`MajikFile.hasPublicKeyAccess()` is not a security primitive.** It hashes a public key and compares to a stored fingerprint. It does not prove the caller controls the corresponding secret key. Use `decrypt()` for cryptographic proof of access.

**Zstd WASM.** Compression depends on `@bokuweb/zstd-wasm`. In Vite projects, the WASM file requires the dev server's `fs.allow` list to include the package's `node_modules` directory, and the package should be excluded from `optimizeDeps`. See the Vite config section of your project setup.

**Format version.** The current `.mjkb` format is version `0x01`. Attempting to decode a binary with a different version byte throws `MajikFileError("UNSUPPORTED_VERSION")`. There is currently no migration path for old binaries.

---

## Cryptographic Parameters

| Primitive | Parameters | Role |
|---|---|---|
| ML-KEM-768 (FIPS 203) | PK: 1184 B, SK: 2400 B, CT: 1088 B | Key encapsulation — post-quantum |
| AES-256-GCM | 32-byte key, 12-byte IV, 16-byte auth tag | Symmetric authenticated encryption |
| Zstd | Level 22 (maximum) | Pre-encryption compression |
| SHA-256 | — | File deduplication hash, public key fingerprints |
| CSPRNG | `crypto.getRandomValues` | IV generation, group AES key generation |

ML-KEM-768 provides NIST security category 3 (roughly equivalent to AES-192). The hybrid construction (ML-KEM for key encapsulation + AES-256-GCM for bulk encryption) means the security of the scheme is bounded by both primitives — currently AES-256-GCM is the stronger of the two against classical adversaries, while ML-KEM-768 provides the post-quantum security.



## Related Projects

### [Majik Message](https://message.majikah.solutions)
Secure messaging platform using Majik Keys

![npm](https://img.shields.io/npm/v/@majikah/majik-message) ![npm downloads](https://img.shields.io/npm/dm/@majikah/majik-message) ![npm bundle size](https://img.shields.io/bundlephobia/min/%40majikah%2Fmajik-message) [![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) ![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue)

[Read more about Majik Message here](https://majikah.solutions/products/majik-message)

[![Majik Message Thumbnail](https://github.com/user-attachments/assets/d433c6b8-1841-4fa1-a6da-b348029d1dbe)](https://message.majikah.solutions)

> Click the image to try Majik Message live.

[Read Docs](https://majikah.solutions/products/majik-message/docs)


Also available on [Microsoft Store](https://apps.microsoft.com/detail/9pmjgvzzjspn) for free.

[Official Repository](https://github.com/Majikah/majik-message)
[SDK Library](https://www.npmjs.com/package/@majikah/majik-message)

---

### [Majik Key](https://majikah.solutions/sdk/majik-key)
**Majik Key** is a seed phrase account library for creating, managing, and parsing mnemonic-based cryptographic accounts (Majik Keys). Generate deterministic key pairs from BIP39 seed phrases with simple, developer-friendly APIs. Now supports ML-KEM-768 post-quantum key derivation alongside X25519.

![npm](https://img.shields.io/npm/v/@majikah/majik-key) ![npm downloads](https://img.shields.io/npm/dm/@majikah/majik-key) ![npm bundle size](https://img.shields.io/bundlephobia/min/%40majikah%2Fmajik-key) [![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) ![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue)

[Read Docs](https://majikah.solutions/sdk/majik-key/docs)
[Official Repository](https://github.com/Majikah/majik-key)
[SDK Library](https://www.npmjs.com/package/@majikah/majik-key)

---


### [Majik Envelope](https://majikah.solutions/sdk/majik-envelope)
**Majik Envelope** is the core cryptographic engine of the [Majik Message](https://github.com/Majikah/majik-message) platform. It provides a post-quantum secure "envelope" format that handles message encryption, multi-recipient key encapsulation, and transparent compression using NIST-standardized algorithms.

![npm](https://img.shields.io/npm/v/@majikah/majik-envelope) ![npm downloads](https://img.shields.io/npm/dm/@majikah/majik-envelope) ![npm bundle size](https://img.shields.io/bundlephobia/min/%40majikah%2Fmajik-envelope) [![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) ![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue)

[Read Docs](https://majikah.solutions/sdk/majik-envelope/docs)
[Official Repository](https://github.com/Majikah/majik-envelope)
[SDK Library](https://www.npmjs.com/package/@majikah/majik-envelope)

---

## Contributing

If you want to contribute or help extend support to more platforms, reach out via email. All contributions are welcome!  

---

## License

[Apache-2.0](LICENSE) — free for personal and commercial use.

---
## Author

Made with 💙 by [@thezelijah](https://github.com/jedlsf)

## About the Developer

- **Developer**: Josef Elijah Fabian
- **GitHub**: [https://github.com/jedlsf](https://github.com/jedlsf)
- **Project Repository**: [https://github.com/Majikah/majik-file](https://github.com/Majikah/majik-file)

---

## Contact

- **Business Email**: [business@thezelijah.world](mailto:business@thezelijah.world)
- **Official Website**: [https://www.thezelijah.world](https://www.thezelijah.world)
