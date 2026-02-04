# Secure File Share - Compartilhamento Seguro e Anonimo

## Proposito

Ferramenta para compartilhamento seguro e **completamente anonimo** de arquivos `.tar.gz` em redes locais. Desenvolvida para transferencias que **nao podem ser detectadas por ferramentas de monitoramento e observabilidade**, incluindo:

- Ferramentas de DLP (Data Loss Prevention)
- Agentes de monitoramento de endpoint
- Sistemas de observabilidade de jornada do usuario
- Proxies e inspetores de trafego SSL
- Qualquer software de vigilancia corporativa

**Caso de uso principal:** Transferir arquivos entre maquinas na mesma rede domestica de forma invisivel, mesmo quando uma das maquinas possui software de monitoramento instalado.

---

## Niveis de Seguranca Garantidos

### Nivel 1: Modo Stealth (Anti-Deteccao)

| Recurso | Descricao |
|---------|-----------|
| **Sem logs de IP** | Nenhum endereco IP e registrado |
| **Sem timestamps** | Nenhuma data/hora e gravada |
| **Sem fingerprinting** | Headers genericos (Server: nginx) |
| **Sem X-Powered-By** | Nao revela tecnologia usada |
| **Referrer-Policy: no-referrer** | Nao vaza URLs de origem |
| **Cache-Control: no-store** | Nenhum rastro em cache do navegador |

### Nivel 2: Anti-Fingerprinting

| Header | Valor | Efeito |
|--------|-------|--------|
| Server | nginx | Mascara o Node.js |
| X-Powered-By | removido | Oculta framework |
| Permissions-Policy | interest-cohort=() | Bloqueia FLoC/tracking |
| X-DNS-Prefetch-Control | off | Impede DNS leaks |

### Nivel 3: Protecao de Trafego

| Recurso | Descricao |
|---------|-----------|
| **Padding aleatorio** | Adiciona 1KB-8KB de dados aleatorios |
| **Timing jitter** | Delay aleatorio de 50-500ms |
| **Porta aleatoria** | Nova porta (20000-65535) a cada reinicio |
| **Token JWT** | Links expiram em 24h |
| **Rate limiting** | 100 req/15min geral, 5 downloads/min |

### Nivel 4: Protecao do Arquivo

| Recurso | Descricao |
|---------|-----------|
| **AES-256-GCM** | Criptografia opcional (desativada por padrao) |
| **PBKDF2** | Derivacao de chave com 100.000 iteracoes |
| **Validacao .tar.gz** | Apenas arquivos tar.gz aceitos |
| **Limite de downloads** | Maximo 10 downloads por arquivo |
| **Tamanho maximo** | Ate 50GB por arquivo |

---

## Instalacao

```bash
# Clone o repositorio
git clone <repository-url>
cd shared-tar-gz

# Instale as dependencias
npm install
```

---

## Como Usar

### Passo 1: Iniciar o Servidor

```bash
npm start
```

O servidor inicia em uma **porta aleatoria** entre 20000-65535. A porta atual e exibida no console e salva no arquivo `.port`.

### Passo 2: Acessar a Interface

Abra no navegador:
```
http://localhost:[PORTA]
```

Ou veja a porta atual:
```bash
cat .port
```

### Passo 3: Fazer Upload do Arquivo

1. **Arraste e solte** seu arquivo `.tar.gz` na area indicada
2. **Ou clique** no botao "Selecionar Arquivo"
3. O upload inicia automaticamente

### Passo 4: Compartilhar o Link

Apos o upload:
1. Um link seguro com token JWT e gerado
2. Copie o link usando o botao "Copiar Link"
3. Compartilhe apenas com pessoas autorizadas

### Passo 5: Download (Outro Computador)

1. Acesse o link compartilhado no navegador
2. O arquivo baixa automaticamente
3. **Pronto para usar** - basta extrair:

```bash
tar -xzf arquivo_baixado.tar.gz
```

---

## Topologia de Rede Recomendada

```
[Seu Notebook]                    [PC Cliente]
      |                                 |
      | Servidor na porta XXXXX         |
      |                                 |
      +---------- Rede Domestica -------+
                      |
              [Roteador/Switch]
```

**Importante:** O PC cliente pode ter VPN corporativa ou software de monitoramento. A transferencia permanece invisivel porque:

1. Conexao e local (nao passa pela VPN)
2. Headers nao revelam informacoes
3. Nenhum log e gerado no servidor
4. Porta aleatoria dificulta deteccao
5. Trafego parece requisicao HTTP comum para servidor nginx

---

## Configuracao Avancada

### Variaveis de Ambiente

```bash
# Desativar modo stealth (nao recomendado)
STEALTH_MODE=false

# Ativar criptografia (requer decriptacao manual)
ENABLE_ENCRYPTION=true

# Alterar expiracao do token
TOKEN_EXPIRY=48h

# Limite de downloads por arquivo
MAX_DOWNLOADS=5

# Tamanho maximo do arquivo (em bytes)
MAX_FILE_SIZE=107374182400  # 100GB

# Restringir a IPs especificos
WHITELISTED_IPS=192.168.1.100,192.168.1.101
```

### Exemplos de Tamanho

| Limite | Valor |
|--------|-------|
| 10 GB | `MAX_FILE_SIZE=10737418240` |
| 50 GB | `MAX_FILE_SIZE=53687091200` (padrao) |
| 100 GB | `MAX_FILE_SIZE=107374182400` |

---

## Interface Web

A interface exibe badges de seguranca ativos:

- **Modo Stealth** - Sem logs ou rastreamento
- **Token JWT** - Links protegidos e temporarios
- **Anti-Fingerprint** - Headers mascarados
- **Rate Limiting** - Protecao contra abuso

### Lista de Arquivos Compartilhados

Para cada arquivo:
- Status (Ativo/Expirado)
- Contador de downloads (X/10)
- Botoes: Download, Copiar Link, Remover

---

## API Endpoints

| Metodo | Endpoint | Descricao |
|--------|----------|-----------|
| POST | `/upload` | Upload de arquivo via formulario |
| GET | `/download/:id?token=jwt` | Download com verificacao de token |
| GET | `/files` | Lista arquivos compartilhados |
| DELETE | `/files/:id` | Remove arquivo da lista |

---

## Solucao de Problemas

### Erro "Token expirado"
Links expiram em 24h. Faca novo upload.

### Erro "Rate limit excedido"
Aguarde 15 minutos ou reinicie o servidor.

### Arquivo corrompido apos download
Verifique se `ENABLE_ENCRYPTION=true` nao esta ativo. Se estiver, use o script de decriptacao em `public/decrypt.js`.

### Porta em uso
O servidor gera automaticamente uma nova porta aleatoria. Verifique `.port` para a porta atual.

### Upload travado
Para arquivos grandes (>1GB), o upload usa streaming. Aguarde - arquivos de ate 50GB sao suportados.

---

## Seguranca vs Usabilidade

| Configuracao | Seguranca | Usabilidade |
|--------------|-----------|-------------|
| Padrao (recomendado) | Alta | Alta |
| Com criptografia | Maxima | Media (requer decrypt) |
| Sem stealth | Media | Alta |

**Recomendacao:** Use as configuracoes padrao. O arquivo chega pronto para descompactar.

---

## Dependencias de Seguranca

- `helmet` - Headers de seguranca HTTP
- `express-rate-limit` - Limitacao de requisicoes
- `jsonwebtoken` - Autenticacao JWT
- `multer` - Upload seguro de arquivos
- `uuid` - Identificadores unicos

---

## Estrutura do Projeto

```
shared-tar-gz/
├── server.js           # Servidor Express com todas as protecoes
├── package.json        # Dependencias
├── .port               # Porta atual do servidor
├── uploads/            # Diretorio de uploads (criado automaticamente)
├── public/
│   ├── index.html      # Interface web com drag & drop
│   └── decrypt.js      # Script de decriptacao (modo opcional)
└── README.md           # Esta documentacao
```

---

## Comparacao com Outras Solucoes

| Recurso | Secure File Share | FTP | HTTP Simples | Cloud |
|---------|-------------------|-----|--------------|-------|
| Anonimato total | Sim | Nao | Nao | Nao |
| Sem logs | Sim | Nao | Nao | Nao |
| Anti-fingerprint | Sim | Nao | Nao | Nao |
| Porta aleatoria | Sim | Nao | Nao | N/A |
| Funciona offline | Sim | Sim | Sim | Nao |
| Suporte 50GB+ | Sim | Sim | Depende | Sim |

---

## Licenca

MIT License

---

**Desenvolvido para transferencias seguras e invisiveis em redes locais.**
