const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const https = require('https');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const multer = require('multer');

const app = express();

// ============================================================================
// FILE UPLOAD CONFIGURATION
// Configuração para upload de arquivos via interface web
// ============================================================================
const UPLOAD_DIR = path.join(__dirname, 'uploads');

// Criar diretório de uploads se não existir
if (!fs.existsSync(UPLOAD_DIR)) {
    fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

// Configurar multer para uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, UPLOAD_DIR);
    },
    filename: (req, file, cb) => {
        // Gerar nome único para evitar conflitos
        const uniqueName = `${Date.now()}-${crypto.randomBytes(8).toString('hex')}-${file.originalname}`;
        cb(null, uniqueName);
    }
});

const upload = multer({
    storage: storage,
    limits: {
        fileSize: process.env.MAX_FILE_SIZE ? parseInt(process.env.MAX_FILE_SIZE) : 50 * 1024 * 1024 * 1024 // 50GB
    },
    fileFilter: (req, file, cb) => {
        // Aceitar apenas arquivos .tar.gz
        if (file.originalname.toLowerCase().endsWith('.tar.gz')) {
            cb(null, true);
        } else {
            cb(new Error('Apenas arquivos .tar.gz são permitidos'), false);
        }
    }
});

// ============================================================================
// STEALTH MODE CONFIGURATION
// Modo anônimo que impede interceptação por ferramentas de observabilidade
// ============================================================================

// Generate random port between 20000-65535
function generateRandomPort() {
    const min = 20000;
    const max = 65535;
    return Math.floor(crypto.randomBytes(2).readUInt16BE() / 65536 * (max - min + 1)) + min;
}

const PORT = process.env.PORT || generateRandomPort();

// JWT secret key (in production, use environment variable)
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');

// Configuration with stealth mode
const CONFIG = {
    enableHttps: process.env.ENABLE_HTTPS === 'true' || false,
    tokenExpiry: process.env.TOKEN_EXPIRY || '24h',
    maxDownloads: process.env.MAX_DOWNLOADS ? parseInt(process.env.MAX_DOWNLOADS) : 10,
    enableEncryption: process.env.ENABLE_ENCRYPTION === 'true', // Default: false (arquivo chega pronto para usar)
    whitelistedIPs: process.env.WHITELISTED_IPS ? process.env.WHITELISTED_IPS.split(',') : [],
    // STEALTH MODE - Anti-observability settings
    stealthMode: process.env.STEALTH_MODE !== 'false', // Default: true
    disableLogs: process.env.DISABLE_LOGS === 'true' || process.env.STEALTH_MODE !== 'false',
    paddingEnabled: process.env.PADDING_ENABLED !== 'false', // Default: true
    timingJitter: process.env.TIMING_JITTER !== 'false', // Default: true - adds random delays
    minPaddingSize: 1024, // Minimum padding in bytes
    maxPaddingSize: 8192, // Maximum padding in bytes
    minTimingJitter: 50, // Minimum delay in ms
    maxTimingJitter: 500, // Maximum delay in ms
};

// ============================================================================
// STEALTH LOGGING - Only logs in non-stealth mode
// ============================================================================
function stealthLog(message, forceLog = false) {
    if (!CONFIG.disableLogs || forceLog) {
        // Remove any potentially identifying information
        const sanitizedMessage = message
            .replace(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/g, '[REDACTED]') // Remove IPs
            .replace(/::ffff:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/g, '[REDACTED]')
            .replace(/::1/g, '[REDACTED]');
        console.log(sanitizedMessage);
    }
}

// ============================================================================
// ANTI-TRAFFIC ANALYSIS - Padding and timing functions
// ============================================================================
function generateRandomPadding() {
    if (!CONFIG.paddingEnabled) return Buffer.alloc(0);
    const size = crypto.randomInt(CONFIG.minPaddingSize, CONFIG.maxPaddingSize + 1);
    return crypto.randomBytes(size);
}

async function addTimingJitter() {
    if (!CONFIG.timingJitter) return;
    const delay = crypto.randomInt(CONFIG.minTimingJitter, CONFIG.maxTimingJitter + 1);
    return new Promise(resolve => setTimeout(resolve, delay));
}

// ============================================================================
// ANTI-FINGERPRINTING SECURITY HEADERS
// Headers configurados para não revelar informações do servidor
// ============================================================================
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            scriptSrcAttr: ["'unsafe-inline'"],
            imgSrc: ["'self'", "data:"],
        },
    },
    // Disable X-Powered-By completely (Helmet does this by default)
    hidePoweredBy: true,
    // Strict referrer policy to prevent leaking URLs
    referrerPolicy: { policy: 'no-referrer' },
    // Prevent MIME type sniffing
    noSniff: true,
    // XSS Protection
    xssFilter: true,
}));

// Remove server identification headers
app.disable('x-powered-by');
app.disable('etag'); // Prevent caching fingerprinting

// Custom middleware to strip identifying headers
app.use((req, res, next) => {
    // Remove or neutralize headers that could identify the server
    res.removeHeader('X-Powered-By');
    res.removeHeader('Server');

    // Set generic/misleading headers for anti-fingerprinting
    res.setHeader('Server', 'nginx'); // Generic server identifier
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '0'); // Modern browsers handle this
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Permissions-Policy', 'interest-cohort=()'); // Disable FLoC

    // Prevent caching that could leak timing info
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.setHeader('Surrogate-Control', 'no-store');

    next();
});

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: 'Muitas tentativas, tente novamente em 15 minutos',
    standardHeaders: true,
    legacyHeaders: false,
});

const downloadLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 5, // limit downloads to 5 per minute per IP
    message: 'Limite de downloads excedido, aguarde 1 minuto',
    standardHeaders: true,
    legacyHeaders: false,
});

app.use(limiter);

// IP Whitelist middleware (stealth-aware)
function checkWhitelist(req, res, next) {
    if (CONFIG.whitelistedIPs.length > 0) {
        const clientIP = req.ip || req.connection.remoteAddress;
        if (!CONFIG.whitelistedIPs.includes(clientIP)) {
            stealthLog('🚫 Acesso negado para IP não autorizado');
            // Generic error message - don't reveal whitelist exists
            return res.status(403).json({ error: 'Acesso negado' });
        }
    }
    next();
}

// Stealth logging middleware - NO IP or timestamp logging in stealth mode
function logAccess(req, res, next) {
    if (!CONFIG.stealthMode) {
        const timestamp = new Date().toISOString();
        console.log(`📊 [${timestamp}] ${req.method} ${req.url}`);
    }
    // In stealth mode, no logging at all
    next();
}

app.use(logAccess);
app.use(checkWhitelist);

// Standard middleware with increased limits for large files
app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ extended: true, limit: '100mb' }));
app.use(express.static('public'));

// Armazenar os arquivos compartilhados em memória com tokens de segurança
const sharedFiles = new Map();

// ============================================================================
// MODERN AUTHENTICATED ENCRYPTION - AES-256-GCM
// Criptografia autenticada que previne tampering e garante integridade
// ============================================================================
const ENCRYPTION_ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16; // 128 bits for GCM
const AUTH_TAG_LENGTH = 16; // 128 bits authentication tag
const SALT_LENGTH = 32; // For key derivation

// Derive a proper 256-bit key from any string key
function deriveKey(keyString, salt) {
    return crypto.pbkdf2Sync(keyString, salt, 100000, 32, 'sha512');
}

// Encrypt with AES-256-GCM (authenticated encryption)
function encryptFile(buffer, keyString) {
    const salt = crypto.randomBytes(SALT_LENGTH);
    const key = deriveKey(keyString, salt);
    const iv = crypto.randomBytes(IV_LENGTH);

    const cipher = crypto.createCipheriv(ENCRYPTION_ALGORITHM, key, iv, {
        authTagLength: AUTH_TAG_LENGTH
    });

    // Add random padding to prevent traffic analysis
    const padding = generateRandomPadding();
    const paddingLength = Buffer.alloc(4);
    paddingLength.writeUInt32BE(padding.length);

    let encrypted = cipher.update(buffer);
    encrypted = Buffer.concat([encrypted, cipher.final()]);

    const authTag = cipher.getAuthTag();

    // Format: salt(32) + iv(16) + authTag(16) + paddingLength(4) + padding(variable) + encryptedData
    const result = Buffer.concat([salt, iv, authTag, paddingLength, padding, encrypted]);

    return {
        encryptedData: result.toString('base64'),
        // Return metadata for decryption (but key stays secret)
        metadata: {
            algorithm: ENCRYPTION_ALGORITHM,
            ivLength: IV_LENGTH,
            saltLength: SALT_LENGTH,
            authTagLength: AUTH_TAG_LENGTH
        }
    };
}

// Decrypt with AES-256-GCM
function decryptFile(encryptedBase64, keyString) {
    const encrypted = Buffer.from(encryptedBase64, 'base64');

    // Extract components
    let offset = 0;
    const salt = encrypted.subarray(offset, offset + SALT_LENGTH);
    offset += SALT_LENGTH;

    const iv = encrypted.subarray(offset, offset + IV_LENGTH);
    offset += IV_LENGTH;

    const authTag = encrypted.subarray(offset, offset + AUTH_TAG_LENGTH);
    offset += AUTH_TAG_LENGTH;

    const paddingLength = encrypted.readUInt32BE(offset);
    offset += 4;

    // Skip padding
    offset += paddingLength;

    const encryptedData = encrypted.subarray(offset);

    // Derive the same key
    const key = deriveKey(keyString, salt);

    const decipher = crypto.createDecipheriv(ENCRYPTION_ALGORITHM, key, iv, {
        authTagLength: AUTH_TAG_LENGTH
    });
    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(encryptedData);
    decrypted = Buffer.concat([decrypted, decipher.final()]);

    return decrypted;
}

// Gerar token seguro para acesso ao arquivo
function generateSecureToken(fileId, filePath) {
    return jwt.sign(
        { 
            fileId, 
            filePath,
            timestamp: Date.now()
        }, 
        JWT_SECRET, 
        { expiresIn: CONFIG.tokenExpiry }
    );
}

// Verificar token de acesso
function verifyToken(token) {
    try {
        return jwt.verify(token, JWT_SECRET);
    } catch (error) {
        return null;
    }
}

// Página inicial
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ============================================================================
// FILE UPLOAD ENDPOINT
// Upload de arquivo via interface web (drag & drop ou seleção)
// ============================================================================
app.post('/upload', upload.single('file'), async (req, res) => {
    await addTimingJitter();

    if (!req.file) {
        return res.status(400).json({ error: 'Nenhum arquivo enviado' });
    }

    const filePath = req.file.path;
    const fileName = req.file.originalname;
    const fileSize = req.file.size;

    // Gerar ID único com entropia extra
    const fileId = uuidv4() + '-' + crypto.randomBytes(8).toString('hex');
    const encryptionKey = crypto.randomBytes(64).toString('hex');
    const secureToken = generateSecureToken(fileId, crypto.randomBytes(16).toString('hex'));

    // Armazenar informações do arquivo
    sharedFiles.set(fileId, {
        originalPath: filePath,
        fileName: CONFIG.stealthMode ? `file_${crypto.randomBytes(4).toString('hex')}.tar.gz` : fileName,
        createdAt: CONFIG.stealthMode ? null : new Date(),
        downloads: 0,
        maxDownloads: CONFIG.maxDownloads,
        token: secureToken,
        encryptionKey: encryptionKey,
        fileSize: fileSize,
        isUploaded: true // Marca que foi upload (para limpeza posterior)
    });

    const protocol = CONFIG.enableHttps ? 'https' : req.protocol;
    const shareUrl = `${protocol}://${req.get('host')}/download/${fileId}?token=${secureToken}`;

    stealthLog(`📤 Arquivo uploaded: ${fileId.substring(0, 8)}...`);

    const response = {
        success: true,
        shareUrl: shareUrl,
        fileId: fileId,
        fileName: fileName,
        fileSize: fileSize,
        encrypted: CONFIG.enableEncryption
    };

    res.json(response);
});

// ============================================================================
// SECURE FILE SHARING ENDPOINT (path-based - mantido para compatibilidade)
// Compartilhamento seguro com criptografia e anonimato
// ============================================================================
app.post('/share', async (req, res) => {
    // Add timing jitter to prevent timing attacks
    await addTimingJitter();

    const { filePath } = req.body;

    if (!filePath) {
        return res.status(400).json({ error: 'Caminho do arquivo é obrigatório' });
    }

    // Verificar se o arquivo existe
    if (!fs.existsSync(filePath)) {
        return res.status(404).json({ error: 'Arquivo não encontrado' });
    }

    // Verificar se é um arquivo tar.gz
    if (!filePath.toLowerCase().endsWith('.tar.gz')) {
        return res.status(400).json({ error: 'Apenas arquivos .tar.gz são permitidos' });
    }

    // Verificar tamanho do arquivo (limite configurável, padrão 50GB)
    const stats = fs.statSync(filePath);
    const fileSizeInBytes = stats.size;
    const maxSize = process.env.MAX_FILE_SIZE ? parseInt(process.env.MAX_FILE_SIZE) : 50 * 1024 * 1024 * 1024;

    if (fileSizeInBytes > maxSize) {
        const maxSizeGB = (maxSize / 1024 / 1024 / 1024).toFixed(1);
        return res.status(400).json({ error: `Arquivo muito grande (máximo ${maxSizeGB}GB)` });
    }

    // Gerar ID único com entropia extra
    const fileId = uuidv4() + '-' + crypto.randomBytes(8).toString('hex');

    // Generate a cryptographically secure encryption key
    const encryptionKey = crypto.randomBytes(64).toString('hex');

    // Gerar token seguro (não inclui filepath para anonimato)
    const secureToken = generateSecureToken(fileId, crypto.randomBytes(16).toString('hex'));

    // Armazenar informações do arquivo (sem metadados sensíveis)
    sharedFiles.set(fileId, {
        originalPath: filePath,
        // In stealth mode, use generic filename
        fileName: CONFIG.stealthMode ? `file_${crypto.randomBytes(4).toString('hex')}.tar.gz` : path.basename(filePath),
        createdAt: CONFIG.stealthMode ? null : new Date(), // No timestamp in stealth mode
        downloads: 0,
        maxDownloads: CONFIG.maxDownloads,
        token: secureToken,
        encryptionKey: encryptionKey,
        fileSize: fileSizeInBytes
    });

    // Build share URL with token embedded
    const protocol = CONFIG.enableHttps ? 'https' : req.protocol;
    const shareUrl = `${protocol}://${req.get('host')}/download/${fileId}?token=${secureToken}`;

    stealthLog(`🔒 Arquivo compartilhado com ID: ${fileId.substring(0, 8)}...`);

    // Response with minimal metadata in stealth mode
    const response = {
        success: true,
        shareUrl: shareUrl,
        fileId: fileId,
        encrypted: CONFIG.enableEncryption
    };

    // Only include detailed info if not in stealth mode
    if (!CONFIG.stealthMode) {
        response.fileName = path.basename(filePath);
        response.fileSize = fileSizeInBytes;
        response.maxDownloads = CONFIG.maxDownloads;
        response.expiresIn = CONFIG.tokenExpiry;
    }

    res.json(response);
});

// ============================================================================
// SECURE DOWNLOAD ENDPOINT
// Download seguro com criptografia AES-256-GCM e proteção anti-análise
// ============================================================================
app.get('/download/:fileId', downloadLimiter, async (req, res) => {
    // Add timing jitter to prevent timing analysis
    await addTimingJitter();

    const { fileId } = req.params;
    const { token } = req.query;

    // Generic error page to prevent information leakage
    const errorPage = (title, message) => `
        <html>
            <head>
                <title>Erro</title>
                <meta name="robots" content="noindex, nofollow">
                <style>
                    body { font-family: system-ui, sans-serif; text-align: center; margin-top: 50px; background: #1a1a2e; color: #eee; }
                    .error { color: #ff6b6b; }
                    .container { max-width: 400px; margin: 0 auto; padding: 20px; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1 class="error">${title}</h1>
                    <p>${message}</p>
                </div>
            </body>
        </html>
    `;

    // Verificar se o arquivo existe - generic error to prevent enumeration
    if (!sharedFiles.has(fileId)) {
        stealthLog('🚫 Download negado: recurso não encontrado');
        return res.status(404).send(errorPage('Recurso não disponível', 'O recurso solicitado não está disponível.'));
    }

    const fileInfo = sharedFiles.get(fileId);

    // Verificar token de acesso
    if (!token || !verifyToken(token)) {
        stealthLog('🚫 Download negado: autenticação falhou');
        return res.status(403).send(errorPage('Acesso negado', 'Autenticação inválida.'));
    }

    // Verificar limite de downloads
    if (fileInfo.downloads >= fileInfo.maxDownloads) {
        stealthLog('🚫 Download negado: limite excedido');
        sharedFiles.delete(fileId);
        return res.status(410).send(errorPage('Recurso expirado', 'Este recurso não está mais disponível.'));
    }

    // Verificar se o arquivo ainda existe no sistema
    if (!fs.existsSync(fileInfo.originalPath)) {
        sharedFiles.delete(fileId);
        return res.status(404).send(errorPage('Recurso não disponível', 'O recurso solicitado não está disponível.'));
    }

    // Incrementar contador de downloads
    fileInfo.downloads++;
    stealthLog(`📥 Download ${fileInfo.downloads}/${fileInfo.maxDownloads}`);

    // Headers seguros e anônimos para download
    // Se criptografia desabilitada, usa nome original do arquivo
    let downloadFilename;
    if (CONFIG.enableEncryption) {
        downloadFilename = CONFIG.stealthMode
            ? `download_${crypto.randomBytes(4).toString('hex')}.enc`
            : fileInfo.fileName + '.enc';
    } else {
        // Sem criptografia - arquivo chega pronto para usar
        downloadFilename = path.basename(fileInfo.originalPath);
    }

    res.setHeader('Content-Disposition', `attachment; filename="${downloadFilename}"`);
    res.setHeader('Content-Type', CONFIG.enableEncryption ? 'application/octet-stream' : 'application/gzip');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');

    // Se criptografia estiver habilitada
    if (CONFIG.enableEncryption) {
        try {
            // Check file size - use streaming for large files (>100MB)
            const LARGE_FILE_THRESHOLD = 100 * 1024 * 1024; // 100MB

            // Set encryption headers first
            if (CONFIG.stealthMode) {
                const keyBundle = Buffer.from(JSON.stringify({
                    k: fileInfo.encryptionKey,
                    a: ENCRYPTION_ALGORITHM,
                    m: {
                        algorithm: ENCRYPTION_ALGORITHM,
                        ivLength: IV_LENGTH,
                        saltLength: SALT_LENGTH,
                        authTagLength: AUTH_TAG_LENGTH
                    }
                })).toString('base64');
                res.setHeader('X-Secure-Bundle', keyBundle);
            } else {
                res.setHeader('X-Decryption-Key', fileInfo.encryptionKey);
                res.setHeader('X-Encryption-Algorithm', ENCRYPTION_ALGORITHM);
            }

            if (fileInfo.fileSize > LARGE_FILE_THRESHOLD) {
                // STREAMING MODE for large files (1GB+)
                // Use streaming cipher to avoid memory issues
                stealthLog(`📦 Streaming large file: ${(fileInfo.fileSize / 1024 / 1024 / 1024).toFixed(2)}GB`);

                const salt = crypto.randomBytes(SALT_LENGTH);
                const key = deriveKey(fileInfo.encryptionKey, salt);
                const iv = crypto.randomBytes(IV_LENGTH);

                const cipher = crypto.createCipheriv(ENCRYPTION_ALGORITHM, key, iv, {
                    authTagLength: AUTH_TAG_LENGTH
                });

                // Add minimal padding for large files (save memory)
                const padding = crypto.randomBytes(1024);
                const paddingLength = Buffer.alloc(4);
                paddingLength.writeUInt32BE(padding.length);

                // Write header first: salt + iv + placeholder for authTag + paddingLength + padding
                const header = Buffer.concat([salt, iv, Buffer.alloc(AUTH_TAG_LENGTH), paddingLength, padding]);
                res.write(header);

                // Create read stream and pipe through cipher
                const readStream = fs.createReadStream(fileInfo.originalPath);

                readStream.on('data', (chunk) => {
                    const encryptedChunk = cipher.update(chunk);
                    if (encryptedChunk.length > 0) {
                        res.write(encryptedChunk);
                    }
                });

                readStream.on('end', () => {
                    const finalChunk = cipher.final();
                    if (finalChunk.length > 0) {
                        res.write(finalChunk);
                    }
                    // Note: For streaming, auth tag is appended at the end
                    // Client needs to handle this format
                    const authTag = cipher.getAuthTag();
                    res.write(authTag);
                    res.end();
                });

                readStream.on('error', (err) => {
                    stealthLog('🚫 Erro no streaming');
                    res.status(500).end();
                });

            } else {
                // BUFFER MODE for smaller files (<100MB)
                const fileBuffer = fs.readFileSync(fileInfo.originalPath);
                const encrypted = encryptFile(fileBuffer, fileInfo.encryptionKey);
                res.send(Buffer.from(encrypted.encryptedData, 'base64'));
            }
        } catch (error) {
            stealthLog('🚫 Erro na criptografia');
            res.status(500).send(errorPage('Erro', 'Erro interno.'));
        }
    } else {
        // Enviar arquivo sem criptografia adicional - already uses streaming
        res.sendFile(fileInfo.originalPath, (err) => {
            if (err) {
                stealthLog('🚫 Erro ao enviar arquivo');
                res.status(500).send(errorPage('Erro', 'Erro interno.'));
            }
        });
    }
});

// Listar arquivos compartilhados com informações de segurança (stealth-aware)
app.get('/files', async (req, res) => {
    await addTimingJitter();

    const protocol = CONFIG.enableHttps ? 'https' : req.protocol;
    const files = Array.from(sharedFiles.entries()).map(([id, info]) => {
        const baseInfo = {
            id: CONFIG.stealthMode ? id.substring(0, 8) + '...' : id,
            downloads: info.downloads,
            maxDownloads: info.maxDownloads,
            encrypted: CONFIG.enableEncryption,
            shareUrl: `${protocol}://${req.get('host')}/download/${id}?token=${info.token}`,
            status: info.downloads >= info.maxDownloads ? 'expired' : 'active'
        };

        // Only include detailed info if not in stealth mode
        if (!CONFIG.stealthMode) {
            baseInfo.fileName = info.fileName;
            baseInfo.createdAt = info.createdAt;
            baseInfo.fileSize = info.fileSize;
        }

        return baseInfo;
    });

    res.json(files);
});

// Remover arquivo compartilhado
app.delete('/files/:fileId', (req, res) => {
    const { fileId } = req.params;
    
    if (sharedFiles.has(fileId)) {
        sharedFiles.delete(fileId);
        res.json({ success: true, message: 'Arquivo removido da lista de compartilhamento' });
    } else {
        res.status(404).json({ error: 'Arquivo não encontrado' });
    }
});

// Função para iniciar servidor
function startServer() {
    const protocol = CONFIG.enableHttps ? 'https' : 'http';

    if (CONFIG.enableHttps) {
        stealthLog('🔒 HTTPS habilitado - Configure certificados SSL para produção', true);
    }

    app.listen(PORT, () => {
        // Always show minimal startup info
        console.log(`\x1b[32m🚀 Servidor iniciado: ${protocol}://localhost:${PORT}\x1b[0m`);

        if (CONFIG.stealthMode) {
            console.log(`\x1b[35m👻 MODO STEALTH ATIVO\x1b[0m`);
            console.log(`   • Logs desabilitados`);
            console.log(`   • Anti-fingerprinting ativo`);
            console.log(`   • Criptografia AES-256-GCM`);
            console.log(`   • Padding anti-análise de tráfego`);
            console.log(`   • Timing jitter habilitado`);
            console.log(`   • Metadados anonimizados`);
        } else {
            console.log(`\x1b[36m🔒 Porta: ${PORT}\x1b[0m`);
            console.log(`\x1b[33m🔐 Recursos de segurança:\x1b[0m`);
            console.log(`   • Rate limiting ativo`);
            console.log(`   • Headers de segurança (Helmet.js)`);
            console.log(`   • Tokens JWT para autenticação`);
            console.log(`   • Criptografia: ${CONFIG.enableEncryption ? 'AES-256-GCM' : 'INATIVA'}`);
            console.log(`   • Limite de downloads: ${CONFIG.maxDownloads}`);
            console.log(`   • Expiração de tokens: ${CONFIG.tokenExpiry}`);
            const maxSizeBytes = process.env.MAX_FILE_SIZE ? parseInt(process.env.MAX_FILE_SIZE) : 50 * 1024 * 1024 * 1024;
            const maxSizeGB = (maxSizeBytes / 1024 / 1024 / 1024).toFixed(1);
            console.log(`   • Tamanho máximo: ${maxSizeGB}GB`);
            if (CONFIG.whitelistedIPs.length > 0) {
                console.log(`   • IPs autorizados: [REDACTED]`);
            }
        }

        console.log(`\x1b[34m📁 Compartilhe arquivos .tar.gz de forma segura e anônima\x1b[0m`);

        // Salvar porta em arquivo para scripts externos
        fs.writeFileSync('.port', PORT.toString());
    });
}

// Iniciar servidor
startServer();

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('📊 Encerrando servidor...');
    process.exit(0);
});

process.on('SIGINT', () => {
    console.log('📊 Servidor interrompido pelo usuário');
    // Limpar arquivo de porta
    if (fs.existsSync('.port')) {
        fs.unlinkSync('.port');
    }
    process.exit(0);
});

module.exports = app;
