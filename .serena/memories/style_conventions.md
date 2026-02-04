# Code Style and Conventions

## JavaScript/Node.js
- ES6+ syntax (const, let, arrow functions)
- CommonJS modules (require/module.exports)
- Async/await for asynchronous operations
- camelCase for variables and functions
- UPPER_CASE for constants/config

## Express.js Patterns
- Middleware functions: `function name(req, res, next)`
- Route handlers: `app.method('/path', handler)`
- Error responses: `res.status(code).json({ error: 'message' })`
- Success responses: `res.json({ success: true, data })`

## Security Patterns
- Always validate file paths and extensions
- Use JWT for authentication
- Apply rate limiting to sensitive routes
- Log security events to console
- Use crypto for encryption operations

## Naming
- Files: lowercase with hyphens (e.g., `server.js`)
- Functions: descriptive verbs (e.g., `generateSecureToken`)
- Constants: descriptive nouns (e.g., `CONFIG`, `JWT_SECRET`)

## Comments
- Use `//` for single-line comments
- Portuguese language for user-facing messages
- English for technical comments
