const http = require('http');
const fs = require('fs');
const path = require('path');
const os = require('os');

// Configuration
const PORT = 3000;
const FILE_NAME = 'mcp-export-20250903-191350.tar.gz';
const FILE_PATH = path.join(__dirname, FILE_NAME);

// Get local IP address
function getLocalIP() {
    const interfaces = os.networkInterfaces();
    for (const name of Object.keys(interfaces)) {
        for (const interface of interfaces[name]) {
            if (interface.family === 'IPv4' && !interface.internal) {
                return interface.address;
            }
        }
    }
    return 'localhost';
}

// Create HTTP server
const server = http.createServer((req, res) => {
    const url = req.url;
    
    if (url === '/') {
        // Serve a simple HTML page with download link
        const html = `
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Compartilhamento de Arquivo</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
        }
        .download-btn {
            display: inline-block;
            background-color: #007bff;
            color: white;
            padding: 15px 30px;
            text-decoration: none;
            border-radius: 5px;
            font-size: 18px;
            margin: 20px 0;
            transition: background-color 0.3s;
        }
        .download-btn:hover {
            background-color: #0056b3;
        }
        .file-info {
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>📁 Compartilhamento de Arquivo</h1>
        <div class="file-info">
            <h3>Arquivo Disponível:</h3>
            <p><strong>${FILE_NAME}</strong></p>
            <p>Tamanho: ${(fs.statSync(FILE_PATH).size / (1024 * 1024)).toFixed(2)} MB</p>
        </div>
        <a href="/download" class="download-btn">⬇️ Baixar Arquivo</a>
        <p><small>Servidor rodando em: http://${getLocalIP()}:${PORT}</small></p>
    </div>
</body>
</html>`;
        
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(html);
        
    } else if (url === '/download') {
        // Serve the tar.gz file for download
        if (!fs.existsSync(FILE_PATH)) {
            res.writeHead(404, { 'Content-Type': 'text/plain' });
            res.end('Arquivo não encontrado');
            return;
        }

        const stat = fs.statSync(FILE_PATH);
        const fileSize = stat.size;

        res.writeHead(200, {
            'Content-Type': 'application/gzip',
            'Content-Disposition': `attachment; filename="${FILE_NAME}"`,
            'Content-Length': fileSize,
            'Cache-Control': 'no-cache'
        });

        const readStream = fs.createReadStream(FILE_PATH);
        readStream.pipe(res);

        readStream.on('error', (err) => {
            console.error('Erro ao ler arquivo:', err);
            res.writeHead(500, { 'Content-Type': 'text/plain' });
            res.end('Erro interno do servidor');
        });

        console.log(`Download iniciado: ${FILE_NAME} (${(fileSize / (1024 * 1024)).toFixed(2)} MB)`);
        
    } else {
        // 404 for other routes
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('Página não encontrada');
    }
});

// Start server
server.listen(PORT, () => {
    const localIP = getLocalIP();
    console.log('🚀 Servidor de compartilhamento iniciado!');
    console.log(`📁 Arquivo: ${FILE_NAME}`);
    console.log(`🌐 Acesse: http://${localIP}:${PORT}`);
    console.log(`💻 Local: http://localhost:${PORT}`);
    console.log('✨ Pressione Ctrl+C para parar o servidor');
});

// Handle graceful shutdown
process.on('SIGINT', () => {
    console.log('\n👋 Encerrando servidor...');
    server.close(() => {
        console.log('🛑 Servidor encerrado.');
        process.exit(0);
    });
});

// Handle uncaught errors
process.on('uncaughtException', (err) => {
    console.error('❌ Erro não capturado:', err);
    process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('❌ Rejeição não tratada em:', promise, 'razão:', reason);
    process.exit(1);
});