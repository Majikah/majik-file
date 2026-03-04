// ─── .mjkb Format Constants ───────────────────────────────────────────────────

/** Current .mjkb binary format version. */
export const MJKB_VERSION = 1 as const;

/**
 * .mjkb magic bytes: ASCII "MJKB" (0x4D 0x4A 0x4B 0x42).
 * Present at the very start of every .mjkb file for format identification.
 */
export const MJKB_MAGIC = new Uint8Array([0x4d, 0x4a, 0x4b, 0x42]);

/**
 * Fixed header size before the variable-length payload JSON section:
 *   4    magic "MJKB"
 *   1    version
 *   12   AES-GCM IV
 *   4    payload JSON length (big-endian uint32)
 * = 21 bytes
 *
 * @deprecated Use MJKB_FIXED_HEADER in utils.ts — this constant is kept only
 * for backwards-compatibility with any external code that referenced it.
 */
export const MJKB_HEADER_SIZE = 4 + 1 + 12 + 4; // 21 (new variable-payload format)

// ─── ML-KEM-768 Key Sizes ─────────────────────────────────────────────────────

/** ML-KEM-768 public key length in bytes. */
export const ML_KEM_PK_LEN = 1184;

/** ML-KEM-768 secret key length in bytes. */
export const ML_KEM_SK_LEN = 2400;

/** ML-KEM-768 ciphertext length in bytes. */
export const ML_KEM_CT_LEN = 1088;

// ─── AES-GCM ─────────────────────────────────────────────────────────────────

/** AES-256-GCM key length in bytes. */
export const AES_KEY_LEN = 32;

/** AES-GCM IV length in bytes. */
export const IV_LENGTH = 12;

// ─── Compression ─────────────────────────────────────────────────────────────

/** Maximum Zstd compression level (highest ratio, slowest). */
export const ZSTD_MAX_LEVEL = 22;

// ─── File Size Limits ─────────────────────────────────────────────────────────

/** Default maximum file size: 100 MB in bytes. Bypassable via CreateOptions. */
export const MAX_FILE_SIZE_BYTES = 100 * 1024 * 1024;

// ─── R2 Storage Prefixes ─────────────────────────────────────────────────────

/**
 * R2 bucket key prefixes.
 *
 * PERMANENT  →  files/user/<userId>/<fileHash>.mjkb
 *   Retained indefinitely. Scoped to the user's sub-directory.
 *
 * TEMPORARY  →  files/public/<userId>_<fileHash>.mjkb
 *   Auto-deleted after ~15 days by the bucket lifecycle policy
 *   targeting all objects under the `files/public/` prefix.
 */
export const R2_PREFIX = {
  PERMANENT: "files/user",
  TEMPORARY: "files/public",
  /**
   * Encrypted WebP chat images.
   * Structure: images/chats/<conversationId>/<userId>_<fileHash>.mjkb
   *
   * Scoped per conversation so all images in a conversation can be
   * batch-deleted (e.g. when a conversation is removed).
   * These files use temporary storage by default with the standard
   * 15-day R2 lifecycle policy, but can be made permanent if needed.
   */
  CHAT_IMAGE: "images/chats",
} as const;

export type R2Prefix = (typeof R2_PREFIX)[keyof typeof R2_PREFIX];

// ─── MIME Type Sets ───────────────────────────────────────────────────────────

/**
 * MIME types that can be rendered inline in a modern browser without
 * requiring a download. Used by MajikFile.isInlineViewable.
 */
export const INLINE_VIEWABLE_MIME_TYPES = new Set([
  // Images
  "image/png",
  "image/jpeg",
  "image/gif",
  "image/webp",
  "image/avif",
  "image/svg+xml",
  "image/bmp",
  "image/tiff",
  "image/x-icon",
  // Documents
  "application/pdf",
  // Text
  "text/plain",
  "text/html",
  "text/css",
  "text/csv",
  "text/xml",
  "text/markdown",
  // Video
  "video/mp4",
  "video/webm",
  "video/ogg",
  "video/quicktime",
  // Audio
  "audio/mpeg",
  "audio/ogg",
  "audio/wav",
  "audio/webm",
  "audio/aac",
  "audio/flac",
]);

/**
 * Comprehensive MIME type registry for popular file formats.
 * Used for validation, labelling, and icon selection in the UI.
 * Organised by category.
 */
export const KNOWN_MIME_TYPES = new Set([
  // ── Images ─────────────────────────────────────────────────────────────
  "image/png",
  "image/jpeg",
  "image/gif",
  "image/webp",
  "image/avif",
  "image/svg+xml",
  "image/bmp",
  "image/tiff",
  "image/x-icon",
  "image/heic",
  "image/heif",
  "image/jxl",
  "image/vnd.adobe.photoshop", // .psd
  "image/x-xcf", // GIMP .xcf
  "image/x-raw", // Camera RAW generic
  "image/x-canon-cr2", // Canon RAW
  "image/x-nikon-nef", // Nikon RAW
  "image/x-sony-arw", // Sony RAW

  // ── Video ───────────────────────────────────────────────────────────────
  "video/mp4",
  "video/webm",
  "video/ogg",
  "video/quicktime", // .mov
  "video/x-msvideo", // .avi
  "video/x-matroska", // .mkv
  "video/x-flv", // .flv
  "video/3gpp", // .3gp
  "video/3gpp2", // .3g2
  "video/mpeg", // .mpeg .mpg
  "video/x-ms-wmv", // .wmv
  "video/mp2t", // .ts (MPEG transport stream)
  "video/x-m4v", // .m4v

  // ── Audio ───────────────────────────────────────────────────────────────
  "audio/mpeg", // .mp3
  "audio/ogg", // .ogg
  "audio/wav", // .wav
  "audio/webm",
  "audio/aac", // .aac
  "audio/flac", // .flac
  "audio/x-m4a", // .m4a
  "audio/midi", // .mid .midi
  "audio/x-midi",
  "audio/aiff", // .aiff .aif
  "audio/x-aiff",
  "audio/opus", // .opus
  "audio/amr", // .amr
  "audio/mp4", // .m4a (alternate)

  // ── Documents ───────────────────────────────────────────────────────────
  "application/pdf", // .pdf
  "application/msword", // .doc
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document", // .docx
  "application/vnd.ms-excel", // .xls
  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", // .xlsx
  "application/vnd.ms-powerpoint", // .ppt
  "application/vnd.openxmlformats-officedocument.presentationml.presentation", // .pptx
  "application/vnd.oasis.opendocument.text", // .odt
  "application/vnd.oasis.opendocument.spreadsheet", // .ods
  "application/vnd.oasis.opendocument.presentation", // .odp
  "application/rtf", // .rtf
  "text/rtf",

  // ── Text / Code ──────────────────────────────────────────────────────────
  "text/plain", // .txt
  "text/html", // .html .htm
  "text/css", // .css
  "text/csv", // .csv
  "text/xml", // .xml
  "text/markdown", // .md .markdown
  "text/javascript", // .js .mjs
  "application/javascript",
  "application/typescript", // .ts
  "application/json", // .json
  "application/xml", // .xml (alternate)
  "application/yaml", // .yaml .yml
  "text/yaml",
  "application/toml", // .toml
  "application/graphql", // .graphql
  "text/x-python", // .py
  "text/x-java-source", // .java
  "text/x-c", // .c
  "text/x-c++", // .cpp .cxx
  "text/x-csharp", // .cs
  "text/x-go", // .go
  "text/x-rust", // .rs
  "text/x-swift", // .swift
  "text/x-kotlin", // .kt
  "text/x-ruby", // .rb
  "text/x-php", // .php
  "text/x-sh", // .sh .bash
  "text/x-powershell", // .ps1
  "application/x-httpd-php", // .php (alternate)
  "application/x-sql", // .sql
  "text/x-lua", // .lua

  // ── Archives & Compressed ────────────────────────────────────────────────
  "application/zip", // .zip
  "application/x-rar-compressed", // .rar
  "application/x-rar",
  "application/x-7z-compressed", // .7z
  "application/x-tar", // .tar
  "application/gzip", // .gz
  "application/x-gzip",
  "application/x-bzip2", // .bz2
  "application/x-xz", // .xz
  "application/x-lzip", // .lz
  "application/x-zstd", // .zst
  "application/vnd.rar",

  // ── Executables & Installers ─────────────────────────────────────────────
  "application/x-msdownload", // .exe .dll
  "application/vnd.microsoft.portable-executable", // .exe (alternate)
  "application/x-msi", // .msi
  "application/x-apple-diskimage", // .dmg
  "application/x-debian-package", // .deb
  "application/x-rpm", // .rpm
  "application/x-sh", // .sh
  "application/x-executable",
  "application/octet-stream", // generic binary / unknown

  // ── Fonts ────────────────────────────────────────────────────────────────
  "font/ttf", // .ttf
  "font/otf", // .otf
  "font/woff", // .woff
  "font/woff2", // .woff2
  "application/font-woff",
  "application/vnd.ms-fontobject", // .eot

  // ── 3D & Design ──────────────────────────────────────────────────────────
  "model/gltf+json", // .gltf
  "model/gltf-binary", // .glb
  "model/obj", // .obj
  "model/stl", // .stl
  "application/x-blender", // .blend (Blender)
  "application/vnd.ms-3mfdocument", // .3mf (3D printing)
  "application/x-fbx", // .fbx (Autodesk)

  // ── Adobe Creative Suite ─────────────────────────────────────────────────
  "image/vnd.adobe.photoshop", // .psd (Photoshop)
  "application/postscript", // .ai (Illustrator) .eps .ps
  "application/x-indesign", // .indd (InDesign)
  "video/x-adobe-premiere", // .prproj (Premiere)
  "application/x-adobe-after-effects", // .aep (After Effects)
  "application/x-xd", // .xd (Adobe XD)

  // ── Figma / Sketch / Design Tools ────────────────────────────────────────
  "application/x-figma", // .fig
  "application/x-sketch", // .sketch
  "application/x-affinity-designer", // Affinity Designer
  "application/x-affinity-photo", // Affinity Photo

  // ── VS Code / IDEs / Config ──────────────────────────────────────────────
  "application/json", // .json (settings, package.json, tsconfig)
  "application/x-vsix", // .vsix (VS Code extension)
  "application/x-ipynb+json", // .ipynb (Jupyter notebook)
  "text/x-dockerfile", // Dockerfile
  "application/x-env", // .env

  // ── Database ─────────────────────────────────────────────────────────────
  "application/x-sqlite3", // .sqlite .db
  "application/vnd.sqlite3",

  // ── eBook ────────────────────────────────────────────────────────────────
  "application/epub+zip", // .epub
  "application/x-mobipocket-ebook", // .mobi
  "application/vnd.amazon.ebook", // .azw

  // ── Productivity / Other ─────────────────────────────────────────────────
  "application/x-abiword", // .abw (AbiWord)
  "application/vnd.visio", // .vsd (Visio)
  "application/x-iwork-pages-sffpages", // .pages (Apple Pages)
  "application/x-iwork-numbers-sffnumbers", // .numbers (Apple Numbers)
  "application/x-iwork-keynote-sffkey", // .key (Apple Keynote)

  // ── Cryptographic / Certificates ─────────────────────────────────────────
  "application/x-pem-file", // .pem
  "application/x-pkcs12", // .pfx .p12
  "application/pkix-cert", // .cer .crt
  "application/x-x509-ca-cert",
]);

/**
 * Map from common file extension → canonical MIME type.
 * Use this when a file is uploaded without a MIME type and you need to infer
 * one from the filename extension.
 */
export const EXTENSION_TO_MIME: Readonly<Record<string, string>> = {
  // Images
  png: "image/png",
  jpg: "image/jpeg",
  jpeg: "image/jpeg",
  gif: "image/gif",
  webp: "image/webp",
  avif: "image/avif",
  svg: "image/svg+xml",
  bmp: "image/bmp",
  tiff: "image/tiff",
  tif: "image/tiff",
  ico: "image/x-icon",
  heic: "image/heic",
  heif: "image/heif",
  jxl: "image/jxl",
  psd: "image/vnd.adobe.photoshop",
  xcf: "image/x-xcf",
  cr2: "image/x-canon-cr2",
  nef: "image/x-nikon-nef",
  arw: "image/x-sony-arw",
  // Video
  mp4: "video/mp4",
  webm: "video/webm",
  ogg: "video/ogg",
  mov: "video/quicktime",
  avi: "video/x-msvideo",
  mkv: "video/x-matroska",
  flv: "video/x-flv",
  "3gp": "video/3gpp",
  mpeg: "video/mpeg",
  mpg: "video/mpeg",
  wmv: "video/x-ms-wmv",
  m4v: "video/x-m4v",
  // Audio
  mp3: "audio/mpeg",
  wav: "audio/wav",
  aac: "audio/aac",
  flac: "audio/flac",
  m4a: "audio/x-m4a",
  mid: "audio/midi",
  midi: "audio/midi",
  aiff: "audio/aiff",
  aif: "audio/aiff",
  opus: "audio/opus",
  amr: "audio/amr",
  // Documents
  pdf: "application/pdf",
  doc: "application/msword",
  docx: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  xls: "application/vnd.ms-excel",
  xlsx: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  ppt: "application/vnd.ms-powerpoint",
  pptx: "application/vnd.openxmlformats-officedocument.presentationml.presentation",
  odt: "application/vnd.oasis.opendocument.text",
  ods: "application/vnd.oasis.opendocument.spreadsheet",
  odp: "application/vnd.oasis.opendocument.presentation",
  rtf: "application/rtf",
  // Text / Code
  txt: "text/plain",
  html: "text/html",
  htm: "text/html",
  css: "text/css",
  csv: "text/csv",
  xml: "text/xml",
  md: "text/markdown",
  markdown: "text/markdown",
  js: "text/javascript",
  mjs: "text/javascript",
  ts: "application/typescript",
  json: "application/json",
  yaml: "text/yaml",
  yml: "text/yaml",
  toml: "application/toml",
  graphql: "application/graphql",
  gql: "application/graphql",
  py: "text/x-python",
  java: "text/x-java-source",
  c: "text/x-c",
  cpp: "text/x-c++",
  cxx: "text/x-c++",
  cs: "text/x-csharp",
  go: "text/x-go",
  rs: "text/x-rust",
  swift: "text/x-swift",
  kt: "text/x-kotlin",
  rb: "text/x-ruby",
  php: "text/x-php",
  sh: "text/x-sh",
  bash: "text/x-sh",
  ps1: "text/x-powershell",
  sql: "application/x-sql",
  lua: "text/x-lua",
  // Archives
  zip: "application/zip",
  rar: "application/x-rar-compressed",
  "7z": "application/x-7z-compressed",
  tar: "application/x-tar",
  gz: "application/gzip",
  bz2: "application/x-bzip2",
  xz: "application/x-xz",
  zst: "application/x-zstd",
  // Executables
  exe: "application/x-msdownload",
  dll: "application/x-msdownload",
  msi: "application/x-msi",
  dmg: "application/x-apple-diskimage",
  deb: "application/x-debian-package",
  rpm: "application/x-rpm",
  // Fonts
  ttf: "font/ttf",
  otf: "font/otf",
  woff: "font/woff",
  woff2: "font/woff2",
  eot: "application/vnd.ms-fontobject",
  // 3D & Design
  gltf: "model/gltf+json",
  glb: "model/gltf-binary",
  obj: "model/obj",
  stl: "model/stl",
  blend: "application/x-blender",
  fbx: "application/x-fbx",
  // Adobe
  ai: "application/postscript",
  eps: "application/postscript",
  indd: "application/x-indesign",
  xd: "application/x-xd",
  // Design tools
  fig: "application/x-figma",
  sketch: "application/x-sketch",
  // VS Code / IDE
  vsix: "application/x-vsix",
  ipynb: "application/x-ipynb+json",
  // Database
  sqlite: "application/x-sqlite3",
  db: "application/x-sqlite3",
  // eBook
  epub: "application/epub+zip",
  mobi: "application/x-mobipocket-ebook",
  // Apple productivity
  pages: "application/x-iwork-pages-sffpages",
  numbers: "application/x-iwork-numbers-sffnumbers",
  key: "application/x-iwork-keynote-sffkey",
  // Crypto / Certs
  pem: "application/x-pem-file",
  pfx: "application/x-pkcs12",
  p12: "application/x-pkcs12",
  cer: "application/pkix-cert",
  crt: "application/pkix-cert",
};

// ─── File-level Constants ────────────────────────────────────────────────────

/**
 * Maximum number of recipients for a group-encrypted file.
 * Prevents pathological payload sizes (each recipient adds ~1.5 KB to the
 * .mjkb binary: 1088-byte ML-KEM CT + 32-byte encrypted AES key in base64).
 */
export const MAX_RECIPIENTS = 100;

/**
 * MIME type prefixes and exact types that are already compressed at the
 * codec level. Applying Zstd to these yields negligible savings and
 * measurable CPU/memory overhead — especially on mobile.
 */
export const INCOMPRESSIBLE_MIME_TYPES = new Set([
  // Pre-compressed image codecs
  "image/jpeg",
  "image/jpg",
  "image/webp",
  "image/avif",
  "image/heic",
  "image/heif",
  "image/jxl",
  // All video (codec-level compression throughout)
  "video/mp4",
  "video/webm",
  "video/ogg",
  "video/quicktime",
  "video/x-msvideo",
  "video/x-matroska",
  "video/x-flv",
  "video/3gpp",
  "video/3gpp2",
  "video/mpeg",
  "video/x-ms-wmv",
  "video/mp2t",
  "video/x-m4v",
  // Lossy/pre-compressed audio
  "audio/mpeg", // mp3
  "audio/aac",
  "audio/ogg",
  "audio/opus",
  "audio/webm",
  "audio/x-m4a",
  "audio/mp4",
  "audio/amr",
  // Archives (already compressed)
  "application/zip",
  "application/gzip",
  "application/x-gzip",
  "application/x-rar-compressed",
  "application/x-rar",
  "application/vnd.rar",
  "application/x-7z-compressed",
  "application/x-bzip2",
  "application/x-xz",
  "application/x-lzip",
  "application/x-zstd",
  // Pre-compressed document formats
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document", // .docx
  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", // .xlsx
  "application/vnd.openxmlformats-officedocument.presentationml.presentation", // .pptx
  "application/epub+zip",
]);

/**
 * Image MIME types that can be re-encoded to WebP in the browser.
 * Used by the chat attachment path to normalise all images to WebP before
 * encryption, reducing payload size for non-WebP sources.
 */
export const WEBP_CONVERTIBLE_IMAGE_TYPES = new Set([
  "image/png",
  "image/jpeg",
  "image/jpg",
  "image/gif",
  "image/bmp",
  "image/tiff",
  "image/x-icon",
  "image/svg+xml",
]);
