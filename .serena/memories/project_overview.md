# Shared-tar-gz Project Overview

## Purpose
A secure and anonymous file sharing application for .tar.gz files over the network.
The application allows users to share compressed tar archives via randomly generated URLs with enhanced security features.

## Tech Stack
- **Runtime**: Node.js
- **Framework**: Express.js 4.x
- **Security**: 
  - Helmet.js for HTTP headers
  - JWT (jsonwebtoken) for authentication
  - bcryptjs for hashing
  - express-rate-limit for rate limiting
  - crypto (built-in) for encryption
- **Other**: uuid for file IDs, multer for uploads

## Architecture
- **server.js**: Main Express server (single file architecture)
- **public/index.html**: Frontend SPA
- **In-memory storage**: Uses Map() for file tracking

## Key Security Features
- Random port generation (20000-65535)
- AES-256 file encryption
- JWT token-based authentication
- Rate limiting (100 req/15min, 5 downloads/min)
- IP whitelisting support
- Helmet.js security headers
