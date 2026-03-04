# Majik File

[![Developed by Zelijah](https://img.shields.io/badge/Developed%20by-Zelijah-red?logo=github&logoColor=white)](https://thezelijah.world) ![GitHub Sponsors](https://img.shields.io/github/sponsors/jedlsf?style=plastic&label=Sponsors&link=https%3A%2F%2Fgithub.com%2Fsponsors%2Fjedlsf)

**Majik File** is the core cryptographic engine for secure file handling in the [Majik Message](https://github.com/Majikah/majik-message) ecosystem. It provides a **post-quantum secure "MJKB" format** designed for file encryption, multi-recipient key encapsulation, and transparent compression using NIST-standardized algorithms.

![npm](https://img.shields.io/npm/v/@majikah/majik-file) ![npm downloads](https://img.shields.io/npm/dm/@majikah/majik-file) ![npm bundle size](https://img.shields.io/bundlephobia/min/%40majikah%2Fmajik-file) [![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) ![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue)


---
- [Majik File](#majik-file)
  - [Overview](#overview)
    - [Key Features](#key-features)
  - [Installation](#installation)
  - [Usage Guide](#usage-guide)
    - [Creating a MajikFile](#creating-a-majikfile)
    - [Accessing metadata](#accessing-metadata)
    - [Encrypting and exporting](#encrypting-and-exporting)
    - [Decrypting a MajikFile](#decrypting-a-majikfile)
    - [Sharing](#sharing)
    - [Duplicate Detection](#duplicate-detection)
    - [Stats](#stats)
    - [Static Helpers](#static-helpers)
  - [Notes](#notes)
  - [Related Projects](#related-projects)
    - [Majik Message](#majik-message)
    - [Majik Key](#majik-key)
    - [Majik Envelope](#majik-envelope)
  - [Contributing](#contributing)
  - [License](#license)
  - [Author](#author)
  - [About the Developer](#about-the-developer)
  - [Contact](#contact)


---

## Overview

**Majik File** implements a **File Envelope Format**, which uses **ML-KEM-768 (FIPS-203)** for **post-quantum secure key encapsulation**.  

It abstracts the complexity of:  

- Managing shared secrets  
- AES-GCM initialization vectors  
- Multi-recipient key wrapping  
- File compression/decompression  

This allows developers to **securely encrypt and share files with minimal cryptographic overhead**.

---

### Key Features

- **Single-recipient encryption**: ML-KEM encapsulation → AES-256-GCM key → encrypted `.mjkb`.
- **Group encryption (2+ recipients)**:
  - Random AES-256 key encrypts file once
  - Per recipient: ML-KEM encapsulate → AES key XOR sharedSecret
- **Write-once immutability**: `.mjkb` binaries are never patched in-place.
- **Automatic deduplication**: Files are checked by SHA-256 hash before encryption.
- **Context-aware storage**:
  - `user_upload`, `chat_attachment`, `chat_image`, `thread_attachment`
- **Optional image conversion**: Chat images/attachments converted to WebP for efficiency.
- **Compression**: Zstd at level 22 for compressible formats.
- **Expiry and sharing**:
  - Temporary files with expiry date
  - Shareable links with auto-generated tokens
- **Inline viewable MIME detection** and safe download filename derivation.

---

## Installation

```bash
npm install @majikah/majik-file

```

---

## Usage Guide

### Creating a MajikFile

The library automatically chooses between "Single" and "Group" logic based on the number of recipients.

```ts
import { MajikFile } from "@majikah/majik-file";

const file = await MajikFile.create({
  data: myFileBlob,           // Blob, ArrayBuffer, or Uint8Array
  identity: {
    userId: "user_123",
    fingerprint: "BASE64_FINGERPRINT",
    mlKemPublicKey: publicKey // Uint8Array of length 1184 bytes
  },
  context: "user_upload",     // or "chat_attachment", "chat_image", "thread_attachment"
  originalName: "photo.png",
  recipients: [               // Optional: for group encryption
    {
      fingerprint: "recipient_fingerprint",
      mlKemPublicKey: recipientPublicKey
    }
  ],
  isTemporary: true,          // Optional
  expiresAt: MajikFile.buildExpiryDate(15)
});


```

### Accessing metadata

For group messages, a senderFingerprint is required for metadata.

```ts
console.log(file.id);
console.log(file.originalName);
console.log(file.sizeMB);
console.log(file.isGroup);
console.log(file.isExpired);
console.log(file.safeFilename);


```


### Encrypting and exporting


```ts
// Export .mjkb binary for R2 upload
const mjkbBlob = file.toMJKB();

// Export raw Uint8Array
const rawBytes = file.toBinaryBytes();



```

### Decrypting a MajikFile

To decrypt, you simply provide the recipient's identity (their private ML-KEM key and fingerprint).

```ts
import { MajikFile } from "@majikah/majik-file";

const decrypted = await MajikFile.decrypt(
  mjkbBlob,
  {
    fingerprint: "BASE64_FINGERPRINT",
    mlKemSecretKey: secretKey // Uint8Array of length 2400 bytes
  }
);

// If you already loaded the binary into memory
await file.decryptBinary({
  fingerprint: "BASE64_FINGERPRINT",
  mlKemSecretKey: secretKey
});

```

### Sharing

Enable sharing (auto-generates token if not provided)

```ts

const token = file.toggleSharing();

// Disable sharing
file.toggleSharing();

```

### Duplicate Detection

```ts

if (file.isDuplicateOf(otherFile)) {
  console.log("Duplicate file detected");
}

if (MajikFile.wouldBeDuplicate(newRawBytes, existingHash)) {
  console.log("New data is a duplicate");
}


```

### Stats

```ts

console.log(file.getStats());


```


### Static Helpers

```ts
import { MajikFile } from "@majikah/majik-file";

MajikFile.buildExpiryDate(15);   // ISO expiry date string
MajikFile.formatBytes(1024);     // "1 KB"
MajikFile.inferMimeType("file.png"); // "image/png"
MajikFile.isMjkbCandidate(someBytes); // true/false
MajikFile.hasPublicKeyAccess(pubKey, ownerFingerprint); // true/false

```


---
## Notes

.mjkb format:

```
[4   magic "MJKB"]
[1   version]
[12  AES-GCM IV]
[4   payload JSON length (big-endian uint32)]
[N   payload JSON — MjkbSinglePayload | MjkbGroupPayload]
[M   AES-GCM ciphertext (Zstd-compressed file + 16-byte auth tag)]

```

- Owner is always first recipient in group encryption.
- Files cannot be updated in place — delete + re-create for modifications.
- Chat images always use conversation-scoped R2 prefix.

---

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
