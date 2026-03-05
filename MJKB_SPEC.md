# MJKB — Majik Binary Container Format

**File Extension:** `.mjkb`  
**Media Type (proposed):** `application/vnd.majikah.bundle`  
**Category:** Secure binary container format  
**Specification Version:** 1.0  
**Status:** Draft / Implementation-aligned

---

- [MJKB — Majik Binary Container Format](#mjkb--majik-binary-container-format)
  - [1. Overview](#1-overview)
  - [2. Design Goals](#2-design-goals)
          - [Security](#security)
          - [Portability](#portability)
          - [Efficiency](#efficiency)
          - [Simplicity](#simplicity)
  - [3. High-Level Architecture](#3-high-level-architecture)
  - [4. Cryptographic Model](#4-cryptographic-model)
      - [4.1 Key Encapsulation](#41-key-encapsulation)
      - [4.2 Symmetric Encryption](#42-symmetric-encryption)
      - [4.3 Randomness](#43-randomness)
  - [5. Binary Layout](#5-binary-layout)
      - [Container Layout](#container-layout)
  - [6. Field Definitions](#6-field-definitions)
      - [6.1 Magic Bytes](#61-magic-bytes)
      - [6.2 Format Version](#62-format-version)
      - [6.3 Flags](#63-flags)
      - [6.4 KEM Ciphertext Length](#64-kem-ciphertext-length)
      - [6.5 Metadata Length](#65-metadata-length)
      - [6.6 IV Length](#66-iv-length)
      - [6.7 Initialization Vector](#67-initialization-vector)
      - [6.8 KEM Ciphertext](#68-kem-ciphertext)
      - [6.9 Metadata Section](#69-metadata-section)
      - [6.10 Encrypted Payload](#610-encrypted-payload)
      - [6.11 Authentication Tag](#611-authentication-tag)
  - [7. Compression (Optional)](#7-compression-optional)
  - [8. Parsing Algorithm](#8-parsing-algorithm)
          - [1. verify magic bytes](#1-verify-magic-bytes)
          - [2. verify format version](#2-verify-format-version)
          - [3. read flags](#3-read-flags)
          - [4. read section lengths](#4-read-section-lengths)
          - [5. read IV](#5-read-iv)
          - [6. read KEM ciphertext](#6-read-kem-ciphertext)
          - [7. read metadata](#7-read-metadata)
          - [8. read encrypted payload](#8-read-encrypted-payload)
          - [9. read authentication tag](#9-read-authentication-tag)
          - [10. decapsulate symmetric key](#10-decapsulate-symmetric-key)
          - [11. decrypt payload](#11-decrypt-payload)
          - [12. verify authentication tag](#12-verify-authentication-tag)
  - [9. Security Considerations](#9-security-considerations)
  - [10. MIME Type](#10-mime-type)
  - [11. File Identification](#11-file-identification)
  - [13. Reference Implementation](#13-reference-implementation)
  - [14. Versioning](#14-versioning)
  - [Author](#author)
  - [About the Developer](#about-the-developer)
  - [Contact](#contact)

---

## 1. Overview

**MJKB (Majik Binary Container)** is a secure binary container format designed for **confidential file transport, storage, and messaging**. The format provides:

- Post-quantum secure key encapsulation
- Authenticated encryption for payload confidentiality and integrity
- Optional compression
- Self-contained metadata and file payload
- Deterministic container parsing
- Cross-platform compatibility

MJKB is primarily intended for use in secure messaging systems, encrypted file sharing, and distributed storage environments where confidentiality and integrity are critical.

The format is implemented in the **MajikFile library** and used within the **MajikMessage ecosystem**.

---

## 2. Design Goals

MJKB was designed with the following goals:

###### Security
- Post-quantum key exchange using ML-KEM
- Authenticated encryption via AES-GCM
- Tamper detection

###### Portability
- Platform-independent binary format
- Deterministic parsing
- Language-agnostic implementation

###### Efficiency
- Binary encoding
- Optional compression
- Streaming-friendly layout

###### Simplicity
- Minimal header
- Explicit length encoding
- No nested container complexity

---

## 3. High-Level Architecture

An MJKB container contains the following logical components:

```
MJKB File
│
├── Header
├── Key Encapsulation Section
├── Metadata Section
└── Encrypted Payload
```

The encrypted payload may contain:

- file contents
- message attachments
- structured data
- binary blobs

---

## 4. Cryptographic Model

MJKB uses a **hybrid encryption architecture**.

#### 4.1 Key Encapsulation

A symmetric encryption key is derived using a **post-quantum Key Encapsulation Mechanism (KEM)**.

Algorithm: **ML-KEM (CRYSTALS-Kyber)**
Typical configuration: **ML-KEM-768**

Process:

```
sender generates random AES key
↓
AES key encapsulated using recipient public key
↓
ciphertext stored in container

```


Recipient performs:
```
decapsulation → recover AES key → decrypt payload
```

---

#### 4.2 Symmetric Encryption

Payload encryption uses: **AES-256-GCM**

Properties:
- 256-bit key
- 96-bit IV
- 128-bit authentication tag
- authenticated encryption with associated data (AEAD)

---

#### 4.3 Randomness

All cryptographic randomness must come from a **cryptographically secure random number generator (CSPRNG)**.

Examples:

- WebCrypto
- libsodium
- Node.js crypto
- OS entropy sources

---

## 5. Binary Layout

All integers are **big-endian** unless otherwise stated.

#### Container Layout


| Magic Bytes (4)           |
| ------------------------- |
| Format Version (1)        |
| Flags (1)                 |
| KEM Ciphertext Length (4) |
| Metadata Length (4)       |
| IV Length (1)             |
| IV                        |
| KEM Ciphertext            |
| Metadata                  |
| Encrypted Payload         |
| Authentication Tag (16)   |


---

## 6. Field Definitions

#### 6.1 Magic Bytes

Length: 4 bytes
Value: ASCII "MJKB"
Hex: 4D 4A 4B 42

Purpose:

- Format identification
- MIME detection
- File validation


#### 6.2 Format Version

Length: 1 byte
Current version: 0x01


Future versions must remain backward compatible where possible.


#### 6.3 Flags
Length: 1 byte

Bit flags indicating optional features.

Example allocation:

| Bit | Meaning             |
| --- | ------------------- |
| 0   | Compression enabled |
| 1   | Metadata encrypted  |
| 2–7 | Reserved            |

Unused bits MUST be zero.


#### 6.4 KEM Ciphertext Length
Specifies length of the encapsulated ML-KEM ciphertext.

Typical values:


ML-KEM-512 : 768 bytes
ML-KEM-768 : 1088 bytes
ML-KEM-1024 : 1568 bytes

#### 6.5 Metadata Length
Length: 4 bytes


Defines byte length of metadata section.

Metadata is optional.

If absent: 
value = 0


#### 6.6 IV Length


Length: 1 byte


For AES-GCM the IV length is typically:


12 bytes



#### 6.7 Initialization Vector


Length: variable


Random IV used for AES-GCM encryption.

Must never repeat with the same key.


#### 6.8 KEM Ciphertext

Contains the encapsulated symmetric key.

Generated using:


ML-KEM Encapsulate(recipient_public_key)


Stored exactly as returned by the KEM implementation.

---

#### 6.9 Metadata Section

Optional metadata.

Format:


UTF-8 JSON


Example:

```json
{
  "filename": "photo.png",
  "mime": "image/png",
  "size": 245991,
  "timestamp": 1735754421
}
```
Metadata SHOULD remain small.

#### 6.10 Encrypted Payload

The payload is encrypted using:

AES-256-GCM

Encryption input:

plaintext_payload

Output:

ciphertext

The authentication tag is stored separately.

#### 6.11 Authentication Tag
Length: 16 bytes

Produced by AES-GCM.

Used to verify payload integrity.

If verification fails:

container MUST be rejected

---

## 7. Compression (Optional)

If compression flag is set:

payload → compressed → encrypted

Compression occurs before encryption.

Recommended algorithms:

Zstandard (zstd)

Benefits:

improved transfer efficiency

smaller encrypted payload

---

## 8. Parsing Algorithm

Recommended decoding procedure:

###### 1. verify magic bytes
###### 2. verify format version
###### 3. read flags
###### 4. read section lengths
###### 5. read IV
###### 6. read KEM ciphertext
###### 7. read metadata
###### 8. read encrypted payload
###### 9. read authentication tag
###### 10. decapsulate symmetric key
###### 11. decrypt payload
###### 12. verify authentication tag

If any validation fails:

parsing **MUST** terminate

---

## 9. Security Considerations

Implementations must enforce:

- Input Validation: Malformed containers must be rejected.

- Memory Limits: Payload size must be validated before allocation.

- Cryptographic Safety: Keys must not be logged or exposed.

- Authentication: Authentication tag verification must occur before payload usage.

- Randomness: All cryptographic randomness must be CSPRNG derived.

## 10. MIME Type

Proposed MIME type:

application/vnd.majikah.bundle

Associated extension:

.mjkb

Example HTTP usage:

Content-Type: application/vnd.majikah.bundle

## 11. File Identification

Magic number: 4D 4A 4B 42

ASCII: MJKB

Offset: 0x00

12. Example Container

| Magic Bytes (4)           |
| ------------------------- |
| Format Version (1)        |
| Flags (1)                 |
| KEM Ciphertext Length (4) |
| Metadata Length (4)       |
| IV Length (1)             |
| IV                        |
| KEM Ciphertext            |
| Metadata                  |
| Encrypted Payload         |
| Authentication Tag (16)   |

## 13. Reference Implementation

Reference implementations are provided in:

- TypeScript
- Node.js
- Browser environments
- Electron environments

Library: MajikFile

Core cryptographic operations include:

- ML-KEM encapsulation/decapsulation
- AES-GCM encryption
- secure random generation

## 14. Versioning

Future versions of MJKB may introduce:

- multiple recipients
- streaming containers
- chunked encryption
- authenticated metadata
- additional compression algorithms
- Version upgrades must remain parseable by version-aware implementations.

15. Compatibility

MJKB is designed to operate across:
- Web applications
- Desktop applications
- Mobile applications
- Server environments
- Edge runtimes

The format avoids architecture-specific encoding.

16. Intended Use Cases

MJKB is suitable for:
- encrypted file attachments
- secure messaging
- encrypted storage blobs
- distributed storage objects
- encrypted backups
- secure file transfer

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



