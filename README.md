# 🔒 Shared TAR.GZ - Secure File Sharing

Advanced Node.js application for secure sharing of .tar.gz files with enhanced security features, random ports, and large file support.

## 🚀 Key Features

### 🛡️ Security Features
- **🎲 Random Port Generation**: Uses cryptographically secure random ports (20000-65535)
- **🔐 JWT Authentication**: Token-based access control for all downloads
- **🔒 AES-256 Encryption**: Optional file encryption during transfer
- **🛡️ Rate Limiting**: Protection against brute force attacks (100 req/15min, 5 downloads/min)
- **🔍 Access Logging**: Complete monitoring with IP tracking and timestamps
- **🚫 IP Whitelisting**: Optional IP restriction support
- **⛑️ Security Headers**: Helmet.js implementation with CSP protection

### 📁 File Management
- **📦 Large File Support**: Up to 50GB per file (configurable)
- **✅ .tar.gz Validation**: Strict file type enforcement
- **📊 Download Limits**: Configurable maximum downloads per file
- **⏰ Token Expiration**: Automatic link expiration (24h default)
- **🗑️ Auto Cleanup**: Automatic removal when limits exceeded

### 🎨 Enhanced Interface
- **📱 Responsive Design**: Modern, mobile-friendly interface
- **🔍 Security Indicators**: Real-time security status display
- **📈 File Analytics**: Size, download count, and encryption status
- **⚠️ Security Warnings**: User-friendly security notifications

## 📋 Prerequisites

- Node.js (version 14 or higher)
- npm or yarn

## 🛠️ Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd shared-tar-gz
```

2. Install dependencies:
```bash
npm install
```

## 🏃 Quick Start

### Production Mode
```bash
npm start
```

### Development Mode (with auto-reload)
```bash
npm run dev
```

The server will start on a **random port between 20000-65535**. Check the console output for the assigned port.

## ⚙️ Configuration

Configure the application using environment variables:

```bash
# Security Configuration
ENABLE_HTTPS=true                    # Enable HTTPS (requires SSL certificates)
JWT_SECRET=your_secure_secret        # Custom JWT secret key
TOKEN_EXPIRY=24h                     # Token expiration time
MAX_DOWNLOADS=10                     # Maximum downloads per file
ENABLE_ENCRYPTION=true               # Enable file encryption

# File Configuration
MAX_FILE_SIZE=53687091200           # Maximum file size in bytes (50GB)

# Access Control
WHITELISTED_IPS=192.168.1.100,192.168.1.101  # Comma-separated allowed IPs
```

### File Size Examples
```bash
# 10GB limit
MAX_FILE_SIZE=10737418240

# 50GB limit (default)
MAX_FILE_SIZE=53687091200

# 100GB limit
MAX_FILE_SIZE=107374182400
```

## 🔧 API Endpoints

### File Sharing
- `POST /share` - Create secure share link with JWT token
- `GET /download/:fileId?token=jwt` - Download with token verification
- `GET /files` - List files with security status
- `DELETE /files/:fileId` - Remove file from sharing list

### Security Features
- Rate limiting on all endpoints
- JWT token validation for downloads
- IP whitelisting (if configured)
- Comprehensive access logging

## 🌐 Network Access

### Local Access
```bash
http://localhost:[RANDOM_PORT]
```

### Network Access
1. Check console output for the assigned port
2. Find your local IP:
```bash
ip addr show
```
3. Share with network users:
```bash
http://[YOUR_IP]:[RANDOM_PORT]
```

## 📖 Usage

1. **Start the server** using `npm start`
2. **Note the random port** displayed in the console
3. **Access the web interface** at `http://localhost:[PORT]`
4. **Enter the full path** to your .tar.gz file
5. **Generate a secure link** with built-in token authentication
6. **Share the secure URL** with authorized users
7. **Monitor downloads** through the web interface

## 🔒 Security Best Practices

- **Random Ports**: Each restart uses a new random port for security
- **Token Protection**: Never share tokens separately from URLs
- **File Validation**: Only .tar.gz files are accepted
- **Size Limits**: Configure appropriate file size limits
- **IP Restrictions**: Use IP whitelisting in sensitive environments
- **Monitor Logs**: Check console output for security events
- **Regular Restarts**: Restart server to clear shared file cache

## 📁 Project Structure

```
shared-tar-gz/
├── server.js              # Main secure server with all features
├── package.json           # Dependencies and security packages
├── CLAUDE.md              # Development guidance
├── README.md              # This file
└── public/
    └── index.html         # Enhanced security-aware frontend
```

## 🐛 Troubleshooting

### Common Issues
- **Port conflicts**: New random port is assigned automatically
- **Rate limiting**: Wait 15 minutes if hitting rate limits
- **Token errors**: Links expire after configured time (default 24h)
- **Large files**: Monitor console for upload progress
- **File not found**: Check if download limit was exceeded

### Debug Information
- Current port saved to `.port` file
- All security events logged to console
- Failed access attempts tracked and logged

## 🔄 Development

### Security Dependencies
- `helmet` - Security headers
- `express-rate-limit` - Rate limiting
- `jsonwebtoken` - JWT authentication
- `bcryptjs` - Password hashing utilities

### Development Commands
```bash
npm run dev     # Development with auto-reload
npm start       # Production mode
```

## 📄 License

MIT License - See LICENSE file for details

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Implement security-focused changes
4. Add comprehensive tests
5. Submit a pull request

## 🔐 Security Notice

This application implements multiple security layers but should be used responsibly:
- Only share files with trusted parties
- Use IP whitelisting in corporate environments
- Monitor access logs regularly
- Keep the application updated
- Use HTTPS in production environments

---

**🚀 Ready to share files securely with enhanced protection!**