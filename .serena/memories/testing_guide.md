# Testing Guide - Shared-tar-gz

## Manual Testing

### Start the Server
```bash
npm start
# Or for development with auto-reload:
npm run dev
```

### Check Port
```bash
cat .port
# Returns the random port (20000-65535)
```

### Test File Sharing
1. Open browser at `http://localhost:[PORT]`
2. Enter path to a .tar.gz file
3. Click "Gerar Link Seguro"
4. Copy the generated URL
5. Open URL to download

### Test Encryption
1. Download a shared file
2. Check response headers for `X-Secure-Bundle` or `X-Decryption-Key`
3. Use decrypt.js to decrypt:
   ```bash
   node public/decrypt.js downloaded_file.enc "decryption_key"
   ```

## Playwright Regression Tests

### Test Scenarios to Implement
1. **Page Load Test**
   - Navigate to server URL
   - Verify security badges are visible
   - Check stealth mode indicator

2. **File Share Test**
   - Fill file path input
   - Submit form
   - Verify success message
   - Verify URL is generated

3. **File List Test**
   - Click refresh button
   - Verify files are listed
   - Check stealth mode hides metadata

4. **Download Test**
   - Click download button
   - Verify file downloads
   - Check encryption headers

5. **Security Header Test**
   - Fetch any endpoint
   - Verify anti-fingerprint headers
   - Check no identifying info in response

6. **Error Handling Test**
   - Submit invalid file path
   - Verify error message
   - Submit non-.tar.gz file
   - Verify rejection

## Security Verification

### Headers to Check
- `Server` should be generic (not Express)
- No `X-Powered-By` header
- `Referrer-Policy: no-referrer`
- `Cache-Control: no-store`

### Console Log Verification
In stealth mode:
- No IP addresses should appear
- No timestamps with requests
- No filenames in logs

### Network Traffic Analysis
- File sizes should vary due to padding
- Response times should vary due to jitter
- No identifying metadata in responses
