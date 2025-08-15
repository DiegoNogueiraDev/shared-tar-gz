# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

### Running the application
- **Start server**: `npm start` (production mode, random port 20000-65535)
- **Development mode**: `npm run dev` (auto-reload with nodemon)
- **Install dependencies**: `npm install`

### Network access
- Server uses **random port** between 20000-65535 on each startup
- Port is displayed in console and saved to `.port` file
- Access via: `http://localhost:[RANDOM_PORT]`
- For network access: Check console output for the assigned port

### Security Configuration (Environment Variables)
- `ENABLE_HTTPS=true` - Enable HTTPS (requires SSL certificates)
- `JWT_SECRET=your_secret` - Custom JWT secret (auto-generated if not set)
- `TOKEN_EXPIRY=24h` - Token expiration time
- `MAX_DOWNLOADS=10` - Maximum downloads per file
- `ENABLE_ENCRYPTION=true` - Enable file encryption (default: true)
- `WHITELISTED_IPS=ip1,ip2,ip3` - Comma-separated list of allowed IPs
- `MAX_FILE_SIZE=53687091200` - Maximum file size in bytes (default: 50GB)

## Architecture

### Core Components
- **server.js**: Main Express server with enhanced security features
- **public/index.html**: Complete frontend SPA with security indicators
- **In-memory storage**: Uses Map() for shared files with security tokens

### Security Features

#### Port Security
- **Random Port Generation**: Cryptographically secure random port (20000-65535)
- **Port Detection**: Current port saved to `.port` file
- **Dynamic Assignment**: New port on each server restart

#### Authentication & Authorization
- **JWT Tokens**: Secure token-based authentication for all downloads
- **Token Expiration**: Configurable token lifetime (default: 24h)
- **Access Control**: IP whitelisting support
- **Rate Limiting**: 100 requests/15min, 5 downloads/1min per IP

#### File Security
- **Encryption**: AES-256 encryption for file transfers (configurable)
- **File Size Limits**: Maximum 50GB per file (configurable via MAX_FILE_SIZE)
- **Download Limits**: Configurable max downloads per file (default: 10)
- **Secure Headers**: Helmet.js security headers
- **Input Validation**: Strict file path and extension validation

#### Monitoring & Logging
- **Access Logs**: All requests logged with IP and timestamp
- **Security Events**: Failed access attempts tracked
- **Download Monitoring**: Real-time download counters
- **Graceful Shutdown**: Clean server termination with resource cleanup

### API Endpoints (Enhanced)
- `POST /share`: Create secure share link with JWT token
- `GET /download/:fileId?token=jwt`: Download with token verification
- `GET /files`: List files with security status
- `DELETE /files/:fileId`: Remove file from sharing list

### File Sharing Flow (Secure)
1. User provides absolute file path via web interface
2. Server validates .tar.gz extension, size, and file existence
3. Generates UUID + JWT token with expiration
4. Optional file encryption with unique key
5. Files tracked with security metadata
6. Downloads require valid token and respect rate limits
7. Automatic cleanup when limits exceeded or tokens expire

### Frontend Architecture (Enhanced)
- Security indicators showing active protection features
- Real-time security status display
- Enhanced file information (encryption, limits, expiration)
- Visual distinction between active and expired files
- Security warnings for sensitive operations

### Development Notes
- All security features are enabled by default
- Use environment variables for production configuration
- Monitor console output for security events and port assignments
- Rate limiting and IP restrictions help prevent abuse
- File encryption adds overhead but enhances security for sensitive transfers

### Large File Support
- **Default Limit**: 50GB per file (configurable)
- **Configuration**: Set MAX_FILE_SIZE environment variable in bytes
- **Examples**:
  - 10GB: `MAX_FILE_SIZE=10737418240`
  - 100GB: `MAX_FILE_SIZE=107374182400`
- **Performance**: Large files use streaming for better memory efficiency
- **Display**: File sizes automatically shown in MB/GB format

### Troubleshooting
- Check `.port` file for current server port
- Console logs show detailed security events
- Rate limit errors indicate too many requests from same IP
- Token verification failures suggest expired or invalid links
- File not found errors may indicate cleanup due to download limits
- Large file uploads may take time - monitor console for progress