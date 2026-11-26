# Majik File

[![Developed by Zelijah](https://img.shields.io/badge/Developed%20by-Zelijah-red?logo=github&logoColor=white&style=for-the-badge)](https://thezelijah.world) ![GitHub Sponsors](https://img.shields.io/github/sponsors/jedlsf?style=for-the-badge&label=Sponsors&link=https%3A%2F%2Fgithub.com%2Fsponsors%2Fjedlsf)


[![Static Badge](https://img.shields.io/badge/IANA-vnd.majikah.bundle-green?style=for-the-badge)](https://www.iana.org/assignments/media-types/application/vnd.majikah.bundle) 

**Platform-agnostic post-quantum file encryption.** Produces self-contained `.mjkb` binary files — sealed with **ML-KEM-768 + chunked AES-256-GCM**, optionally streaming Zstandard-compressed, readable without any network access.

> **Note on Architecture:** This library provides the core, decoupled `MajikFile` base class. It knows nothing about chat, threads, or storage backends. For Majikah messaging-specific implementations — including R2 keys, automatic WebP image conversions, and chat context routing — use `MajikMessageFile` (which subclasses `MajikFile`). 

![npm](https://img.shields.io/npm/v/@majikah/majik-file) ![npm downloads](https://img.shields.io/npm/dm/@majikah/majik-file) ![npm bundle size](https://img.shields.io/bundlephobia/min/%40majikah%2Fmajik-file) [![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) ![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue)

---

## Contents
- [Majik File](#majik-file)
  - [Contents](#contents)
  - [How it works](#how-it-works)
  - [The .mjkb binary format](#the-mjkb-binary-format)
    - [Common header](#common-header)
    - [V3 payload](#v3-payload)
    - [Legacy formats](#legacy-formats)
  - [Streaming API](#streaming-api)
  - [Extensibility \& Subclassing](#extensibility--subclassing)
  - [Installation](#installation)
  - [Quick start](#quick-start)
    - [1. Encrypt a file (single recipient)](#1-encrypt-a-file-single-recipient)
    - [2. Encrypt for a Group](#2-encrypt-for-a-group)
    - [3. Decrypt a file](#3-decrypt-a-file)
    - [4. Signatures \& Offline Verification](#4-signatures--offline-verification)
  - [API reference](#api-reference)
    - [`MajikFile.create(options)`](#majikfilecreateoptions)
    - [`MajikFile.decryptWithMetadata(source, identity)`](#majikfiledecryptwithmetadatasource-identity)
  - [Type reference](#type-reference)
    - [`MajikFileJSON`](#majikfilejson)
  - [Storage model](#storage-model)
  - [Related Projects](#related-projects)
    - [Majik Message](#majik-message)
    - [Majik Key](#majik-key)
    - [Majik Envelope](#majik-envelope)
  - [License](#license)
  - [Author](#author)
  - [Contact](#contact)

---

## How it works

```mermaid
flowchart TD
    A[Raw Bytes]

    A --> B["SHA-256 Hash<br/>(Pre-compression for stable deduplication)"]

    B --> C["Extensibility Hook<br/>_preProcess(raw)<br/><br/>Default: No-op<br/>Example: WebP conversion"]

    C --> D{"Already Compressed?"}

    D -- No --> E["Zstd Compression<br/>Adaptive Level"]
    D -- Yes --> F["Skip Compression"]

    E --> G{"Recipients"}
    F --> G

    G -- "Single Recipient" --> H["ML-KEM-768 Encapsulate<br/>Owner Public Key"]

    H --> I["Shared Secret (32 bytes)<br/>Used directly as AES-256-GCM key"]

    I --> J["AES-256-GCM Encrypt<br/>12-byte Random IV<br/>16-byte Authentication Tag"]

    G -- "Group (2+ Recipients)" --> K["Generate Random<br/>32-byte AES Key"]

    K --> L["Encrypt File Once<br/>Using AES-256-GCM"]

    L --> M["For Each Recipient<br/>ML-KEM-768 Encapsulate<br/>Recipient Public Key"]

    M --> N["Encrypted AES Key<br/>AES Key XOR Shared Secret"]

    N --> O["Store Encrypted AES Keys"]

    O --> P[".mjkb Binary"]

    J --> P
```

The encrypted binary is completely self-contained.

---

## The .mjkb binary format

New files are written as **MJKB v3**. V3 uses the same ML-KEM-768 recipient
encapsulation as v2, but encrypts the compressed or raw stream as independently
authenticated AES-256-GCM chunks. V1 and v2 remain supported for decryption.

### Common header

```
┌──────────────────────────────────────────────────────────┐
│  4 bytes  │ Magic: ASCII "MJKB"                           │
│  1 byte   │ Version: 0x03                                 │
│ 12 bytes  │ Random nonce base                             │
│  4 bytes  │ Payload JSON length (big-endian uint32)       │
│  N bytes  │ UTF-8 payload JSON                            │
│  ...      │ Chunk records, then authenticated manifest   │
└──────────────────────────────────────────────────────────┘
```

### V3 payload

Single-recipient payloads carry `mlKemCipherText`; group payloads carry a
`keys` array with one ML-KEM encapsulation and wrapped AES key per recipient.
Both payload variants then carry `n`, `m`, `z`, `chunkSize`, and
`streamSuite`. The current stream suite is
`AES-256-GCM-CHUNKED-1`. The standard Zstandard codec is implicit, so `ca`
is omitted.

Each record is a big-endian uint32 ciphertext length followed by the AES-GCM
ciphertext and 16-byte tag. The nonce counter is derived from the 12-byte base
nonce and the zero-based chunk index. Associated data binds the payload hash,
chunk index, and plaintext chunk length.

The final record uses a zero length sentinel, followed by a 56-byte manifest
(chunk count, compressed byte count, original byte count, and SHA-256 of the
original stream) and an authentication-only AES-GCM tag. The manifest is
mandatory; incomplete, reordered, altered, or trailing data is rejected.

### Legacy formats

- **V1** remains read-only. It used the legacy `c` field and inferred
  decompression from context and MIME metadata.
- **V2** remains readable and can still be written explicitly through
  `MajikFile.createV2()`. Its body is one whole-buffer AES-GCM ciphertext.

---

## Streaming API

For large files, use the reader/writer API rather than the in-memory
`MajikFile.create()` convenience method. It processes source and output
incrementally and uses the same Zstandard streaming implementation as the
Rust SDK.

```ts
import {
  encryptReaderToWriter,
  decryptReaderToWriter,
} from "@majikah/majik-file";

// Browser File System Access API handles are used here as an example.
const encryptedOutput = await encryptedFileHandle.createWritable();
await encryptReaderToWriter(
  sourceFile.stream(),
  encryptedOutput,
  ownerPublicIdentity,
  recipients,
  sourceFile.name,
  sourceFile.type,
  {
    totalBytes: sourceFile.size,
    onProgress: ({ bytesProcessed, totalBytes }) => {
      console.log(bytesProcessed, totalBytes);
    },
  },
);

const encryptedFile = await encryptedInputHandle.getFile();
const plaintextOutput = await plaintextFileHandle.createWritable();
await decryptReaderToWriter(
  encryptedFile.stream(),
  plaintextOutput,
  { fingerprint, mlKemSecretKey },
);
```

The streaming functions accept a `ReadableStream<Uint8Array>` or
`AsyncIterable<Uint8Array>` source and a `WritableStream<Uint8Array>`
destination. They support cancellation, progress callbacks, byte ceilings,
single-recipient and group encryption, and optional standard Zstandard
compression. Use a temporary destination and only publish it after the
operation resolves: decryption may have written earlier authenticated chunks
before a later manifest or stream-integrity failure is discovered.

## Extensibility & Subclassing

`MajikFile` is engineered to be extended by platforms (like Majik Message) without duplicating cryptographic logic. Subclasses compose the crypto pipeline by overriding protected static hooks:

*   `_preProcess(raw, mimeType)`: Alter bytes before compression (e.g., image resizing).
*   `_resolveCompressionPolicy(mimeType)`: Override default MIME-based compression rules.

When invoking `MySubclass.create()`, the base `_encryptCore()` correctly routes to the subclass's overrides via late-bound static dispatch.

---

## Installation

```bash
npm install @majikah/majik-file
```

---

## Quick start

### 1. Encrypt a file (single recipient)

```typescript
import { MajikFile } from '@majikah/majik-file'

// Identity must be supplied (MajikFile does not manage keys)
const identity = {
  publicKey: 'owner-address',
  fingerprint: 'base64-sha256-of-public-key',
  mlKemPublicKey: new Uint8Array(1184),
  mlKemSecretKey: new Uint8Array(2400), 
}

const fileBytes = await file.arrayBuffer()

const majikFile = await MajikFile.create({
  data: fileBytes,
  userId: 'user-uuid',
  identity,
  originalName: file.name,
  mimeType: file.type,
})

// Export the encrypted binary and metadata
const blob = majikFile.toMJKB()             
const metadata = majikFile.toJSON()         
```

### 2. Encrypt for a Group

```typescript
const majikFile = await MajikFile.create({
  data: fileBytes,
  userId: 'sender-uuid',
  identity: senderIdentity,
  recipients: [
    { fingerprint: 'recipient-a-fp', mlKemPublicKey: recipientAKey, publicKey: 'addr-a' },
    { fingerprint: 'recipient-b-fp', mlKemPublicKey: recipientBKey, publicKey: 'addr-b' },
  ],
})
```

### 3. Decrypt a file

```typescript
const { bytes, originalName, mimeType } = await MajikFile.decryptWithMetadata(
  mjkbBlob,
  { fingerprint: identity.fingerprint, mlKemSecretKey: identity.mlKemSecretKey }
)

const recovered = new Blob([bytes], { type: mimeType ?? 'application/octet-stream' })
```

### 4. Signatures & Offline Verification

`.mjkb` files support appending a cryptographic signature trailer (MJKS) for tamper-evident offline verification.

```typescript
// Sign an existing file
await majikFile.sign(signingKey)

// Export with the appended signature trailer
const signedBlob = majikFile.toSignedMJKB()

// Verify later without a database round-trip
const isValid = await MajikFile.verifySignedMJKB(signedBlob, publicKeys)
```

---

## API reference

### `MajikFile.create(options)`

```typescript
static async create(options: MajikFileCreateOptions): Promise<MajikFile>
```

| Field | Type | Required | Description |
|---|---|---|---|
| `data` | `Uint8Array \| ArrayBuffer` | ✓ | Raw file bytes to encrypt |
| `userId` | `string` | ✓ | Owner's UUID |
| `identity` | `MajikFileIdentity` | ✓ | Owner's full identity |
| `recipients` | `MajikFileRecipient[]` | — | Group recipients. Empty → single-recipient |
| `originalName` | `string` | — | Original filename (embedded in `.mjkb`) |
| `mimeType` | `string` | — | MIME type |
| `id` | `string` | — | UUID record ID. Auto-generated if omitted |
| `bypassSizeLimit` | `boolean` | — | Default `false`. Bypasses 100MB cap |
| `compressionLevel`| `number` | — | Zstd level to apply if compressible |

---

### `MajikFile.decryptWithMetadata(source, identity)`

```typescript
static async decryptWithMetadata(
  source: Blob | Uint8Array | ArrayBuffer,
  identity: MajikFileDecryptIdentity
): Promise<{
  bytes: Uint8Array
  originalName: string | null
  mimeType: string | null
  signature: MajikSignature | null
}>
```

Returns decrypted bytes alongside the file's metadata and signature, directly from the binary payload.

---

## Type reference

### `MajikFileJSON`

The serialised JSON representation of a generic file record. *Notice the lack of platform-specific storage keys (like R2 paths) — those belong to subclasses.*

```typescript
interface MajikFileJSON {
  id: string
  schema_version: number
  kind: "file"
  user_id: string
  original_name: string | null
  mime_type: string | null
  size_original: number
  size_stored: number
  file_hash: string
  encryption_iv: string
  participants: string[]
  kem_alg: string
  cipher_alg: string
  timestamp: string | null
  last_update: string | null
  signature: string | null
}
```

---

## Storage model

`MajikFile` separates the cryptographic artefact from the storage representation:
- **`toMJKB()`** returns the encrypted binary blob (upload this to object storage like R2/S3).
- **`toJSON()`** returns the metadata structure (store this in a database like Supabase).

It is up to the platform implementing `MajikFile` to manage where and how these artifacts are persisted and retrieved.

---

## Related Projects

### [Majik Message](https://apps.microsoft.com/detail/9pmjgvzzjspn)
A secure software product available on Windows and WebApp, powered by these exact post-quantum file encryption techniques.

### [Majik Key](https://majikah.solutions/sdk/majik-key)
Seed phrase account library for generating deterministic ML-KEM-768 keypairs.

### [Majik Envelope](https://majikah.solutions/sdk/majik-envelope)
The core cryptographic engine handling message encryption and multi-recipient key encapsulation.

---

## License

[Apache-2.0](LICENSE) — free for personal and commercial use.

---

## Author

Developed by **Josef Elijah Fabian (Zelijah)** | [Majikah Solutions OPC](https://majikah.solutions/about)

**Developer**: [Josef Elijah Fabian](https://github.com/jedlsf)
**GitHub**: [https://github.com/Majikah](https://github.com/Majikah)
**Project Repository**: [https://github.com/Majikah/majik-file](https://github.com/Majikah/majik-file)

---

## Contact

- **Business Email**: [business@majikah.solutions](mailto:business@majikah.solutions)
- **Official Website**: [https://www.thezelijah.world](https://www.thezelijah.world)
- **Majikah Ecosystem**: [https://majikah.solutions](https://majikah.solutions)