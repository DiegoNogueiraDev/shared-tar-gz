# Shared TAR.GZ

Aplicação Node.js para compartilhar arquivos .tar.gz através de URLs aleatórias na rede local.

## 🚀 Funcionalidades

- ✅ Interface web intuitiva para compartilhar arquivos
- ✅ Geração de URLs aleatórias para cada arquivo
- ✅ Download seguro através de links únicos
- ✅ Listagem de arquivos compartilhados
- ✅ Contador de downloads
- ✅ Remoção de arquivos da lista de compartilhamento
- ✅ Validação de arquivos .tar.gz
- ✅ Design responsivo

## 📋 Pré-requisitos

- Node.js (versão 14 ou superior)
- npm ou yarn

## 🛠️ Instalação

1. Navegue até o diretório do projeto:
```bash
cd /home/diego/Documentos/shared-tar-gz
```

2. Instale as dependências:
```bash
npm install
```

## 🏃 Execução

### Modo de produção:
```bash
npm start
```

### Modo de desenvolvimento (com auto-reload):
```bash
npm run dev
```

O servidor será iniciado em `http://localhost:3000`

## 📖 Como usar

1. Acesse `http://localhost:3000` no navegador
2. Digite o caminho completo para um arquivo .tar.gz
3. Clique em "Gerar Link de Compartilhamento"
4. Copie o link gerado e compartilhe com outros usuários na rede
5. Os usuários podem acessar o link para fazer o download do arquivo

## 🌐 Acesso na rede

Para permitir acesso de outros computadores na rede, você pode:

1. **Descobrir seu IP local:**
```bash
ip addr show
```

2. **Iniciar o servidor especificando o host:**
```bash
PORT=3000 node server.js
```

3. **Outros computadores podem acessar via:**
```
http://[SEU_IP]:3000
```

## 📁 Estrutura do projeto

```
shared-tar-gz/
├── server.js          # Servidor Express principal
├── package.json       # Configurações do projeto
├── README.md          # Este arquivo
└── public/
    └── index.html     # Interface web
```

## 🔧 API Endpoints

- `GET /` - Interface web principal
- `POST /share` - Compartilhar um arquivo
- `GET /download/:fileId` - Download do arquivo
- `GET /files` - Listar arquivos compartilhados
- `DELETE /files/:fileId` - Remover arquivo da lista

## 🛡️ Segurança

- Apenas arquivos .tar.gz são aceitos
- URLs são geradas com UUIDs aleatórios
- Validação de existência de arquivos
- Não há persistência de dados (reiniciar o servidor limpa a lista)

## 📝 Exemplo de uso

```bash
# 1. Instalar dependências
npm install

# 2. Iniciar servidor
npm start

# 3. Acessar http://localhost:3000
# 4. Inserir caminho: /home/usuario/arquivo.tar.gz
# 5. Compartilhar o link gerado
```

## 🤝 Contribuição

Sinta-se à vontade para contribuir com melhorias!

## 📄 Licença

MIT License
