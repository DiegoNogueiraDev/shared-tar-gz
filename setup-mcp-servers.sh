#!/bin/bash
# ============================================================
# Script para configurar MCP Servers no Claude Code
# Adiciona os servidores MCP em qualquer projeto
# ============================================================
#
# USO:
#   ./setup-mcp-servers.sh [caminho_do_projeto]
#
# Se não fornecer o caminho, usa o diretório atual
#
# SERVIDORES CONFIGURADOS:
#   - context7: Documentação de bibliotecas em tempo real
#   - playwright: Automação de browser e testes E2E
#   - serena: Análise semântica de código
#   - knowledge-graph: Grafo de conhecimento persistente
#
# ============================================================

set -e

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configurações
CLAUDE_CONFIG="$HOME/.claude.json"
CONTEXT7_API_KEY="ctx7sk-89fb448e-195b-4515-8d5c-35334f93156a"

# Função para exibir mensagens
info() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Verificar dependências
check_dependencies() {
    info "Verificando dependências..."

    # Node.js/npm
    if ! command -v npm &> /dev/null; then
        error "npm não encontrado. Instale o Node.js primeiro."
    fi
    success "npm encontrado: $(npm -v)"

    # npx
    if ! command -v npx &> /dev/null; then
        error "npx não encontrado."
    fi
    success "npx encontrado"

    # uvx (para serena)
    if ! command -v uvx &> /dev/null; then
        warn "uvx não encontrado. Serena não será configurado."
        warn "Instale com: pip install uv"
        HAS_UVX=false
    else
        success "uvx encontrado"
        HAS_UVX=true
    fi

    # jq para manipular JSON
    if ! command -v jq &> /dev/null; then
        error "jq não encontrado. Instale com: sudo dnf install jq (Fedora) ou sudo apt install jq (Ubuntu)"
    fi
    success "jq encontrado: $(jq --version)"
}

# Determinar o caminho do projeto
get_project_path() {
    if [ -n "$1" ]; then
        PROJECT_PATH=$(realpath "$1")
    else
        PROJECT_PATH=$(pwd)
    fi

    if [ ! -d "$PROJECT_PATH" ]; then
        error "Diretório não existe: $PROJECT_PATH"
    fi

    info "Projeto: $PROJECT_PATH"
}

# Criar backup do arquivo de configuração
backup_config() {
    if [ -f "$CLAUDE_CONFIG" ]; then
        BACKUP_FILE="${CLAUDE_CONFIG}.backup.$(date +%Y%m%d_%H%M%S)"
        cp "$CLAUDE_CONFIG" "$BACKUP_FILE"
        success "Backup criado: $BACKUP_FILE"
    fi
}

# Configurar MCP servers usando jq
configure_mcp_servers() {
    info "Configurando MCP servers para: $PROJECT_PATH"

    # Criar arquivo de configuração se não existir
    if [ ! -f "$CLAUDE_CONFIG" ]; then
        echo '{"projects":{}}' > "$CLAUDE_CONFIG"
        success "Arquivo de configuração criado"
    fi

    # Definir os MCP servers
    MCP_SERVERS=$(cat <<EOF
{
    "context7": {
        "type": "stdio",
        "command": "npx",
        "args": ["-y", "@upstash/context7-mcp", "--api-key", "$CONTEXT7_API_KEY"],
        "env": {}
    },
    "playwright": {
        "type": "stdio",
        "command": "npx",
        "args": ["@playwright/mcp@latest"],
        "env": {}
    },
    "knowledge-graph": {
        "type": "stdio",
        "command": "npx",
        "args": ["-y", "knowledgegraph-mcp"]
    }
}
EOF
)

    # Adicionar serena se uvx estiver disponível
    if [ "$HAS_UVX" = true ]; then
        MCP_SERVERS=$(echo "$MCP_SERVERS" | jq --arg path "$PROJECT_PATH" '. + {
            "serena": {
                "type": "stdio",
                "command": "uvx",
                "args": ["--from", "git+https://github.com/oraios/serena", "serena", "start-mcp-server", "--context", "ide-assistant", "--project", $path],
                "env": {}
            }
        }')
    fi

    # Estrutura base do projeto
    PROJECT_CONFIG=$(cat <<EOF
{
    "allowedTools": [],
    "mcpContextUris": [],
    "mcpServers": $MCP_SERVERS,
    "enabledMcpjsonServers": [],
    "disabledMcpjsonServers": [],
    "hasTrustDialogAccepted": true,
    "projectOnboardingSeenCount": 0,
    "hasClaudeMdExternalIncludesApproved": false,
    "hasClaudeMdExternalIncludesWarningShown": false,
    "hasCompletedProjectOnboarding": true
}
EOF
)

    # Atualizar o arquivo de configuração
    TEMP_FILE=$(mktemp)
    jq --arg path "$PROJECT_PATH" --argjson config "$PROJECT_CONFIG" \
        '.projects[$path] = (.projects[$path] // {}) * $config' \
        "$CLAUDE_CONFIG" > "$TEMP_FILE"

    mv "$TEMP_FILE" "$CLAUDE_CONFIG"
    success "MCP servers configurados!"
}

# Listar servidores configurados
list_servers() {
    echo ""
    info "Servidores MCP configurados:"
    echo ""
    echo -e "  ${GREEN}1. context7${NC}"
    echo "     Documentação de bibliotecas em tempo real"
    echo "     Comando: npx -y @upstash/context7-mcp"
    echo ""
    echo -e "  ${GREEN}2. playwright${NC}"
    echo "     Automação de browser e testes E2E"
    echo "     Comando: npx @playwright/mcp@latest"
    echo ""
    echo -e "  ${GREEN}3. knowledge-graph${NC}"
    echo "     Grafo de conhecimento persistente"
    echo "     Comando: npx -y knowledgegraph-mcp"
    echo ""
    if [ "$HAS_UVX" = true ]; then
        echo -e "  ${GREEN}4. serena${NC}"
        echo "     Análise semântica de código"
        echo "     Comando: uvx serena start-mcp-server"
        echo ""
    fi
}

# Mostrar instruções finais
show_instructions() {
    echo ""
    echo "============================================================"
    echo -e "${GREEN}CONFIGURAÇÃO CONCLUÍDA!${NC}"
    echo "============================================================"
    echo ""
    echo "Para usar os MCP servers:"
    echo ""
    echo "  1. Abra o projeto no VS Code:"
    echo -e "     ${YELLOW}code $PROJECT_PATH${NC}"
    echo ""
    echo "  2. Inicie o Claude Code:"
    echo -e "     ${YELLOW}claude${NC}"
    echo ""
    echo "  3. Verifique os servidores com:"
    echo -e "     ${YELLOW}/mcp${NC}"
    echo ""
    echo "Os servidores devem aparecer como 'connected'"
    echo "============================================================"
}

# Main
main() {
    echo ""
    echo "============================================================"
    echo "  SETUP MCP SERVERS - Claude Code"
    echo "============================================================"
    echo ""

    check_dependencies
    get_project_path "$1"
    backup_config
    configure_mcp_servers
    list_servers
    show_instructions
}

# Executar
main "$@"
