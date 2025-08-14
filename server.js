const express = require('express');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 35884;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// Armazenar os arquivos compartilhados em memória
const sharedFiles = new Map();

// Página inicial
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Endpoint para compartilhar arquivo
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

    // Gerar ID único para o arquivo
    const fileId = uuidv4();
    const fileName = path.basename(filePath);
    
    // Armazenar informações do arquivo
    sharedFiles.set(fileId, {
        originalPath: filePath,
        fileName: fileName,
        createdAt: new Date(),
        downloads: 0
    });

    // Retornar URL de compartilhamento
    const shareUrl = `${req.protocol}://${req.get('host')}/download/${fileId}`;
    
    res.json({
        success: true,
        shareUrl: shareUrl,
        fileName: fileName,
        fileId: fileId
    });
});

// Endpoint para download
app.get('/download/:fileId', (req, res) => {
    const { fileId } = req.params;
    
    if (!sharedFiles.has(fileId)) {
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
                    <h1 class="error">Arquivo não encontrado</h1>
                    <p>O link pode ter expirado ou o arquivo foi removido.</p>
                </body>
            </html>
        `);
    }

    const fileInfo = sharedFiles.get(fileId);
    
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
                    <h1 class="error">Arquivo não encontrado</h1>
                    <p>O arquivo foi removido do servidor.</p>
                </body>
            </html>
        `);
    }

    // Incrementar contador de downloads
    fileInfo.downloads++;
    
    // Configurar headers para download
    res.setHeader('Content-Disposition', `attachment; filename="${fileInfo.fileName}"`);
    res.setHeader('Content-Type', 'application/gzip');
    
    // Enviar arquivo
    res.sendFile(fileInfo.originalPath, (err) => {
        if (err) {
            console.error('Erro ao enviar arquivo:', err);
            res.status(500).send('Erro interno do servidor');
        }
    });
});

// Listar arquivos compartilhados
app.get('/files', (req, res) => {
    const files = Array.from(sharedFiles.entries()).map(([id, info]) => ({
        id,
        fileName: info.fileName,
        createdAt: info.createdAt,
        downloads: info.downloads,
        shareUrl: `${req.protocol}://${req.get('host')}/download/${id}`
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

// Iniciar servidor
app.listen(PORT, () => {
    console.log(`🚀 Servidor rodando em http://localhost:${PORT}`);
    console.log(`📁 Compartilhe arquivos .tar.gz através de URLs aleatórias`);
});

module.exports = app;
