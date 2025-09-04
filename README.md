# Servidor de Compartilhamento de Arquivo TAR.GZ

Script Node.js simples para compartilhar arquivos tar.gz na rede local.

## Como usar

1. **Instalar Node.js** (se não tiver instalado)

2. **Executar o servidor:**
   ```bash
   node file-share-server.js
   ```

3. **Acessar o servidor:**
   - **Local**: http://localhost:3000
   - **Rede local**: http://SEU_IP_LOCAL:3000

## Funcionalidades

- ✅ Interface web simples e responsiva
- ✅ Download do arquivo tar.gz com um clique
- ✅ Detecção automática do IP local
- ✅ Headers apropriados para download de arquivo
- ✅ Tratamento de erros
- ✅ Informações do arquivo (nome e tamanho)

## Arquivo atual

- **Nome**: `mcp-export-20250903-191350.tar.gz`
- **Localização**: Mesmo diretório do script
- **Tamanho**: ~276 MB

## Como parar o servidor

Pressione `Ctrl+C` no terminal onde o servidor está rodando.

## Personalização

Para compartilhar um arquivo diferente, edite a variável `FILE_NAME` no script:

```javascript
const FILE_NAME = 'seu-arquivo.tar.gz';
```

## Requisitos

- Node.js (versão 12 ou superior)
- Arquivo tar.gz no mesmo diretório do script