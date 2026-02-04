/**
 * Ferramenta de Descriptografia para Shared-tar-gz
 * Descriptografa arquivos baixados do servidor usando AES-256-GCM
 *
 * Uso:
 *   node decrypt.js <arquivo_criptografado> <chave> [arquivo_saida]
 *
 * A chave pode ser encontrada no header X-Secure-Bundle ou X-Decryption-Key
 * do download.
 */

const crypto = require('crypto');
const fs = require('fs');

// Configurações de criptografia (devem corresponder ao servidor)
const ENCRYPTION_ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16;
const SALT_LENGTH = 32;
const AUTH_TAG_LENGTH = 16;

// Deriva a chave usando PBKDF2
function deriveKey(keyString, salt) {
    return crypto.pbkdf2Sync(keyString, salt, 100000, 32, 'sha512');
}

// Detecta se o conteúdo é base64 ou binário
function isBase64(str) {
    if (typeof str !== 'string') return false;
    const base64Regex = /^[A-Za-z0-9+/]+=*$/;
    return base64Regex.test(str.replace(/\s/g, ''));
}

// Descriptografa o arquivo (aceita binário ou base64)
function decryptFile(encryptedInput, keyString) {
    let encrypted;

    // Se for string, tenta decodificar de base64
    if (typeof encryptedInput === 'string') {
        if (isBase64(encryptedInput)) {
            encrypted = Buffer.from(encryptedInput, 'base64');
        } else {
            encrypted = Buffer.from(encryptedInput, 'binary');
        }
    } else if (Buffer.isBuffer(encryptedInput)) {
        encrypted = encryptedInput;
    } else {
        throw new Error('Formato de entrada inválido');
    }

    let offset = 0;
    const salt = encrypted.subarray(offset, offset + SALT_LENGTH);
    offset += SALT_LENGTH;

    const iv = encrypted.subarray(offset, offset + IV_LENGTH);
    offset += IV_LENGTH;

    const authTag = encrypted.subarray(offset, offset + AUTH_TAG_LENGTH);
    offset += AUTH_TAG_LENGTH;

    const paddingLength = encrypted.readUInt32BE(offset);
    offset += 4;

    // Pular padding
    offset += paddingLength;

    const encryptedData = encrypted.subarray(offset);

    // Derivar a mesma chave
    const key = deriveKey(keyString, salt);

    const decipher = crypto.createDecipheriv(ENCRYPTION_ALGORITHM, key, iv, {
        authTagLength: AUTH_TAG_LENGTH
    });
    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(encryptedData);
    decrypted = Buffer.concat([decrypted, decipher.final()]);

    return decrypted;
}

// Parse do X-Secure-Bundle header
function parseSecureBundle(bundleBase64) {
    try {
        const decoded = Buffer.from(bundleBase64, 'base64').toString('utf8');
        return JSON.parse(decoded);
    } catch (e) {
        return null;
    }
}

// Função principal
function main() {
    const args = process.argv.slice(2);

    if (args.length < 2) {
        console.log(`
╔══════════════════════════════════════════════════════════════════╗
║           Ferramenta de Descriptografia - Shared-tar-gz          ║
╚══════════════════════════════════════════════════════════════════╝

Uso:
  node decrypt.js <arquivo_criptografado> <chave> [arquivo_saida]

Parâmetros:
  arquivo_criptografado  - Arquivo .enc baixado do servidor
  chave                  - Chave de descriptografia (do header X-Decryption-Key
                           ou do campo 'k' do X-Secure-Bundle)
  arquivo_saida          - (Opcional) Nome do arquivo de saída
                           Padrão: remove extensão .enc

Exemplo:
  node decrypt.js download_abc123.enc minha_chave_secreta arquivo.tar.gz

Nota: Se você recebeu um X-Secure-Bundle, primeiro decodifique-o de base64
para obter a chave 'k' no JSON resultante.
`);
        process.exit(1);
    }

    const inputFile = args[0];
    let decryptionKey = args[1];
    let outputFile = args[2];

    // Se a chave parecer ser um X-Secure-Bundle (base64 JSON)
    if (decryptionKey.length > 100) {
        const bundle = parseSecureBundle(decryptionKey);
        if (bundle && bundle.k) {
            decryptionKey = bundle.k;
            console.log('✓ Chave extraída do X-Secure-Bundle');
        }
    }

    // Definir arquivo de saída padrão
    if (!outputFile) {
        outputFile = inputFile.replace(/\.enc$/, '');
        if (outputFile === inputFile) {
            outputFile = inputFile + '.decrypted.tar.gz';
        }
    }

    // Verificar se o arquivo de entrada existe
    if (!fs.existsSync(inputFile)) {
        console.error(`❌ Arquivo não encontrado: ${inputFile}`);
        process.exit(1);
    }

    console.log(`
📂 Arquivo de entrada: ${inputFile}
📁 Arquivo de saída:   ${outputFile}
🔐 Descriptografando...
`);

    try {
        // Ler arquivo criptografado como BINÁRIO (não utf8)
        const encryptedData = fs.readFileSync(inputFile);

        // Descriptografar
        const decrypted = decryptFile(encryptedData, decryptionKey);

        // Salvar arquivo descriptografado
        fs.writeFileSync(outputFile, decrypted);

        console.log(`✅ Arquivo descriptografado com sucesso!`);
        console.log(`   Tamanho: ${(decrypted.length / 1024 / 1024).toFixed(2)} MB`);
        console.log(`   Salvo em: ${outputFile}`);

    } catch (error) {
        console.error(`❌ Erro na descriptografia: ${error.message}`);
        console.error(`
Possíveis causas:
  - Chave de descriptografia incorreta
  - Arquivo corrompido
  - Arquivo não foi criptografado com este servidor
`);
        process.exit(1);
    }
}

// Executar se chamado diretamente
if (require.main === module) {
    main();
}

module.exports = { decryptFile, parseSecureBundle };
