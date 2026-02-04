# Suggested Commands

## Development
- `npm install` - Install dependencies
- `npm run dev` - Start development server (with nodemon auto-reload)
- `npm start` - Start production server

## Server Access
- Server uses random port between 20000-65535
- Check `.port` file for current port
- Access: `http://localhost:[PORT]`

## Environment Variables
```bash
ENABLE_HTTPS=true         # Enable HTTPS
JWT_SECRET=your_secret    # Custom JWT secret
TOKEN_EXPIRY=24h          # Token expiration
MAX_DOWNLOADS=10          # Max downloads per file
ENABLE_ENCRYPTION=true    # Enable file encryption
WHITELISTED_IPS=ip1,ip2   # Allowed IPs
MAX_FILE_SIZE=53687091200 # Max file size (50GB default)
```

## Testing
- Use Playwright MCP for regression tests
- Browser-based testing at http://localhost:[PORT]

## Git Commands
- `git status` - Check changes
- `git add .` - Stage changes
- `git commit -m "message"` - Commit
- `git push` - Push to remote
