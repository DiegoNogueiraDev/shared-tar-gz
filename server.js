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

const app = express();

// Generate random port between 20000-65535
function generateRandomPort() {
    const min = 20000;
    const max = 65535;
    return Math.floor(crypto.randomBytes(2).readUInt16BE() / 65536 * (max - min + 1)) + min;
}

const PORT = process.env.PORT || generateRandomPort();

// JWT secret key (in production, use environment variable)
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');

// Configuration
const CONFIG = {
    enableHttps: process.env.ENABLE_HTTPS === 'true' || false,
    tokenExpiry: process.env.TOKEN_EXPIRY || '24h',
    maxDownloads: process.env.MAX_DOWNLOADS ? parseInt(process.env.MAX_DOWNLOADS) : 10,
    enableEncryption: process.env.ENABLE_ENCRYPTION === 'true' || true,
    whitelistedIPs: process.env.WHITELISTED_IPS ? process.env.WHITELISTED_IPS.split(',') : []
};

// Security middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:"],
        },
    },
}));

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

// IP Whitelist middleware
function checkWhitelist(req, res, next) {
    if (CONFIG.whitelistedIPs.length > 0) {
        const clientIP = req.ip || req.connection.remoteAddress;
        if (!CONFIG.whitelistedIPs.includes(clientIP)) {
            console.log(`🚫 Acesso negado para IP: ${clientIP}`);
            return res.status(403).json({ error: 'Acesso negado - IP não autorizado' });
        }
    }
    next();
}

// Logging middleware
function logAccess(req, res, next) {
    const timestamp = new Date().toISOString();
    const ip = req.ip || req.connection.remoteAddress;
    console.log(`📊 [${timestamp}] ${req.method} ${req.url} - IP: ${ip}`);
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

// Função para criptografar arquivos (se habilitado)
function encryptFile(buffer, key) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipher('aes-256-cbc', key);
    let encrypted = cipher.update(buffer);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return { iv: iv.toString('hex'), encryptedData: encrypted.toString('hex') };
}

function decryptFile(encryptedData, iv, key) {
    const decipher = crypto.createDecipher('aes-256-cbc', key);
    let decrypted = decipher.update(Buffer.from(encryptedData, 'hex'));
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

// Endpoint para compartilhar arquivo com segurança aprimorada
app.post('/share', (req, res) => {
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
    const maxSize = process.env.MAX_FILE_SIZE ? parseInt(process.env.MAX_FILE_SIZE) : 50 * 1024 * 1024 * 1024; // 50GB default
    
    if (fileSizeInBytes > maxSize) {
        const maxSizeGB = (maxSize / 1024 / 1024 / 1024).toFixed(1);
        return res.status(400).json({ error: `Arquivo muito grande (máximo ${maxSizeGB}GB)` });
    }

    // Gerar ID único e chave de criptografia
    const fileId = uuidv4();
    const fileName = path.basename(filePath);
    const encryptionKey = crypto.randomBytes(32).toString('hex');
    
    // Gerar token seguro
    const secureToken = generateSecureToken(fileId, filePath);
    
    // Armazenar informações do arquivo
    sharedFiles.set(fileId, {
        originalPath: filePath,
        fileName: fileName,
        createdAt: new Date(),
        downloads: 0,
        maxDownloads: CONFIG.maxDownloads,
        token: secureToken,
        encryptionKey: encryptionKey,
        fileSize: fileSizeInBytes
    });

    // Retornar URL de compartilhamento com token
    const protocol = CONFIG.enableHttps ? 'https' : req.protocol;
    const shareUrl = `${protocol}://${req.get('host')}/download/${fileId}?token=${secureToken}`;
    
    const displaySize = fileSizeInBytes > 1024 * 1024 * 1024 
        ? `${(fileSizeInBytes / 1024 / 1024 / 1024).toFixed(2)} GB`
        : `${(fileSizeInBytes / 1024 / 1024).toFixed(2)} MB`;
    console.log(`🔒 Arquivo compartilhado: ${fileName} (${displaySize})`);
    
    res.json({
        success: true,
        shareUrl: shareUrl,
        fileName: fileName,
        fileId: fileId,
        fileSize: fileSizeInBytes,
        maxDownloads: CONFIG.maxDownloads,
        expiresIn: CONFIG.tokenExpiry,
        encrypted: CONFIG.enableEncryption
    });
});

// Endpoint para download com segurança aprimorada
app.get('/download/:fileId', downloadLimiter, (req, res) => {
    const { fileId } = req.params;
    const { token } = req.query;
    
    // Verificar se o arquivo existe
    if (!sharedFiles.has(fileId)) {
        console.log(`🚫 Download negado: Arquivo ${fileId} não encontrado`);
        return res.status(404).send(`
            <html>
                <head>
                    <title>Arquivo não encontrado</title>
                    <style>
                        body { font-family: Arial, sans-serif; text-align: center; margin-top: 50px; }
                        .error { color: #e74c3c; }
                    </style>
                </head>
                <body>
                    <h1 class="error">🚫 Arquivo não encontrado</h1>
                    <p>O link pode ter expirado, o arquivo foi removido ou o token é inválido.</p>
                </body>
            </html>
        `);
    }

    const fileInfo = sharedFiles.get(fileId);
    
    // Verificar token de acesso
    if (!token || !verifyToken(token)) {
        console.log(`🚫 Download negado: Token inválido para arquivo ${fileInfo.fileName}`);
        return res.status(403).send(`
            <html>
                <head>
                    <title>Acesso negado</title>
                    <style>
                        body { font-family: Arial, sans-serif; text-align: center; margin-top: 50px; }
                        .error { color: #e74c3c; }
                    </style>
                </head>
                <body>
                    <h1 class="error">🔒 Acesso negado</h1>
                    <p>Token de acesso inválido ou expirado.</p>
                </body>
            </html>
        `);
    }
    
    // Verificar limite de downloads
    if (fileInfo.downloads >= fileInfo.maxDownloads) {
        console.log(`🚫 Download negado: Limite excedido para arquivo ${fileInfo.fileName}`);
        sharedFiles.delete(fileId); // Remove arquivo após limite
        return res.status(410).send(`
            <html>
                <head>
                    <title>Limite de downloads excedido</title>
                    <style>
                        body { font-family: Arial, sans-serif; text-align: center; margin-top: 50px; }
                        .error { color: #e74c3c; }
                    </style>
                </head>
                <body>
                    <h1 class="error">📊 Limite excedido</h1>
                    <p>Este arquivo atingiu o limite máximo de downloads (${fileInfo.maxDownloads}).</p>
                </body>
            </html>
        `);
    }
    
    // Verificar se o arquivo ainda existe no sistema
    if (!fs.existsSync(fileInfo.originalPath)) {
        sharedFiles.delete(fileId);
        return res.status(404).send(`
            <html>
                <head>
                    <title>Arquivo não encontrado</title>
                    <style>
                        body { font-family: Arial, sans-serif; text-align: center; margin-top: 50px; }
                        .error { color: #e74c3c; }
                    </style>
                </head>
                <body>
                    <h1 class="error">📁 Arquivo removido</h1>
                    <p>O arquivo foi removido do servidor.</p>
                </body>
            </html>
        `);
    }

    // Incrementar contador de downloads
    fileInfo.downloads++;
    const clientIP = req.ip || req.connection.remoteAddress;
    console.log(`📥 Download ${fileInfo.downloads}/${fileInfo.maxDownloads}: ${fileInfo.fileName} - IP: ${clientIP}`);
    
    // Configurar headers seguros para download
    res.setHeader('Content-Disposition', `attachment; filename="${fileInfo.fileName}"`);
    res.setHeader('Content-Type', 'application/gzip');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    
    // Se criptografia estiver habilitada, criptografar o arquivo
    if (CONFIG.enableEncryption) {
        try {
            const fileBuffer = fs.readFileSync(fileInfo.originalPath);
            const encrypted = encryptFile(fileBuffer, fileInfo.encryptionKey);
            
            // Incluir chave de descriptografia no header (apenas para demonstração)
            // Em produção, a chave deveria ser enviada separadamente
            res.setHeader('X-Decryption-Key', fileInfo.encryptionKey);
            res.setHeader('X-IV', encrypted.iv);
            
            res.send(Buffer.from(encrypted.encryptedData, 'hex'));
        } catch (error) {
            console.error('🚫 Erro na criptografia:', error);
            res.status(500).send('Erro interno do servidor');
        }
    } else {
        // Enviar arquivo sem criptografia
        res.sendFile(fileInfo.originalPath, (err) => {
            if (err) {
                console.error('🚫 Erro ao enviar arquivo:', err);
                res.status(500).send('Erro interno do servidor');
            }
        });
    }
});

// Listar arquivos compartilhados com informações de segurança
app.get('/files', (req, res) => {
    const protocol = CONFIG.enableHttps ? 'https' : req.protocol;
    const files = Array.from(sharedFiles.entries()).map(([id, info]) => ({
        id,
        fileName: info.fileName,
        createdAt: info.createdAt,
        downloads: info.downloads,
        maxDownloads: info.maxDownloads,
        fileSize: info.fileSize,
        encrypted: CONFIG.enableEncryption,
        shareUrl: `${protocol}://${req.get('host')}/download/${id}?token=${info.token}`,
        status: info.downloads >= info.maxDownloads ? 'expired' : 'active'
    }));
    
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
        // Para HTTPS, seria necessário certificados SSL
        // Este é um exemplo básico - em produção use certificados válidos
        console.log('🔒 HTTPS habilitado - Configure certificados SSL para produção');
    }
    
    app.listen(PORT, () => {
        console.log(`[32m🚀 Servidor seguro iniciado em ${protocol}://localhost:${PORT}[0m`);
        console.log(`[36m🔒 Porta aleatória: ${PORT} (20000-65535)[0m`);
        console.log(`[33m🔐 Recursos de segurança:[0m`);
        console.log(`   • Rate limiting ativo`);
        console.log(`   • Headers de segurança (Helmet.js)`);
        console.log(`   • Tokens JWT para autenticação`);
        console.log(`   • Criptografia de arquivos: ${CONFIG.enableEncryption ? 'ATIVA' : 'INATIVA'}`);
        console.log(`   • Limite de downloads por arquivo: ${CONFIG.maxDownloads}`);
        console.log(`   • Expiração de tokens: ${CONFIG.tokenExpiry}`);
        const maxSizeBytes = process.env.MAX_FILE_SIZE ? parseInt(process.env.MAX_FILE_SIZE) : 50 * 1024 * 1024 * 1024;
        const maxSizeGB = (maxSizeBytes / 1024 / 1024 / 1024).toFixed(1);
        console.log(`   • Tamanho máximo de arquivo: ${maxSizeGB}GB`);
        if (CONFIG.whitelistedIPs.length > 0) {
            console.log(`   • IPs autorizados: ${CONFIG.whitelistedIPs.join(', ')}`);
        }
        console.log(`[34m📁 Compartilhe arquivos .tar.gz com segurança aprimorada[0m`);
        
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
