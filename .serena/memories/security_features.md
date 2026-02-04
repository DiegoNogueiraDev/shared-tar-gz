# Security Features - Shared-tar-gz

## Stealth Mode (Anti-Observability)
The application includes a comprehensive stealth mode that prevents data interception by monitoring tools.

### Enabled by Default
- `STEALTH_MODE=true` - Main stealth mode toggle
- `DISABLE_LOGS=true` - No IP/timestamp logging when stealth mode is active

### Anti-Fingerprinting Headers
- Generic `Server: nginx` header
- No `X-Powered-By` header
- `Referrer-Policy: no-referrer`
- `Cache-Control: no-store` to prevent timing analysis
- `Permissions-Policy: interest-cohort=()` to disable FLoC

### Traffic Analysis Prevention
- **Padding**: Random 1KB-8KB padding added to encrypted files
- **Timing Jitter**: 50-500ms random delays on all sensitive endpoints
- **Generic filenames**: In stealth mode, files use randomized names like `file_abc123.tar.gz`

## Encryption (AES-256-GCM)
Modern authenticated encryption replacing deprecated `createCipher`.

### Key Features
- **Algorithm**: AES-256-GCM (authenticated encryption)
- **Key Derivation**: PBKDF2 with SHA-512, 100,000 iterations
- **IV**: 16 bytes cryptographically random
- **Salt**: 32 bytes per encryption operation
- **Auth Tag**: 16 bytes for integrity verification

### Encrypted File Format
```
[salt:32] + [iv:16] + [authTag:16] + [paddingLength:4] + [padding:variable] + [encryptedData]
```

### Decryption
- Client-side decryption tool: `public/decrypt.js`
- Key delivered via `X-Secure-Bundle` or `X-Decryption-Key` header

## Environment Variables

### Security Configuration
```bash
STEALTH_MODE=true          # Enable full stealth mode (default: true)
DISABLE_LOGS=true          # Disable all logging (default: follows STEALTH_MODE)
PADDING_ENABLED=true       # Add random padding (default: true)
TIMING_JITTER=true         # Add random delays (default: true)
ENABLE_ENCRYPTION=true     # Enable AES-256-GCM encryption (default: true)
ENABLE_HTTPS=true          # Enable HTTPS (requires certs)
JWT_SECRET=your_secret     # JWT signing key (auto-generated if not set)
TOKEN_EXPIRY=24h           # Token lifetime
MAX_DOWNLOADS=10           # Max downloads per file
WHITELISTED_IPS=ip1,ip2    # IP whitelist (empty = all allowed)
MAX_FILE_SIZE=53687091200  # Max file size in bytes (50GB default)
```

## Large File Support (1GB+)

The application supports files up to 50GB with intelligent handling:

### Two Modes Based on File Size
1. **Buffer Mode** (files < 100MB): Full file loaded into memory, encrypted, and sent
2. **Streaming Mode** (files > 100MB): File is read and encrypted in chunks to conserve memory

### Streaming Encryption
- Uses `fs.createReadStream()` to read file in chunks
- Cipher operates in streaming mode with `cipher.update()` per chunk
- Auth tag appended at end of stream
- Minimal padding (1KB) for large files to save bandwidth

### Configuration
```bash
MAX_FILE_SIZE=107374182400  # 100GB example
```

## Rate Limiting
- General: 100 requests per 15 minutes per IP
- Downloads: 5 downloads per minute per IP

## What Data is Protected
In stealth mode, the following data is NOT logged or exposed:
- Client IP addresses
- Timestamps of access
- Original filenames
- File sizes
- User agents
- Referrer information
