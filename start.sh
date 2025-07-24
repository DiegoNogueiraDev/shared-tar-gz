#!/bin/bash

# Script para iniciar o servidor de compartilhamento de arquivos TAR.GZ
# Autor: Diego

echo "🚀 Iniciando servidor de compartilhamento TAR.GZ..."
echo ""

# Verificar se Node.js está instalado
if ! command -v node &> /dev/null; then
    echo "❌ Node.js não está instalado. Por favor, instale o Node.js primeiro."
    exit 1
fi

# Verificar se npm está instalado
if ! command -v npm &> /dev/null; then
    echo "❌ npm não está instalado. Por favor, instale o npm primeiro."
    exit 1
fi

# Navegar para o diretório do projeto
cd "$(dirname "$0")"

# Verificar se as dependências estão instaladas
if [ ! -d "node_modules" ]; then
    echo "📦 Instalando dependências..."
    npm install
    echo ""
fi

# Obter o IP local
LOCAL_IP=$(ip route get 1.1.1.1 | grep -oP 'src \K\S+' 2>/dev/null || echo "localhost")

echo "🌐 Informações de acesso:"
echo "   Local: http://localhost:3000"
echo "   Rede:  http://$LOCAL_IP:3000"
echo ""
echo "📝 Como usar:"
echo "   1. Acesse uma das URLs acima no navegador"
echo "   2. Digite o caminho completo para um arquivo .tar.gz"
echo "   3. Clique em 'Gerar Link de Compartilhamento'"
echo "   4. Compartilhe o link gerado com outros usuários"
echo ""
echo "🛑 Para parar o servidor, pressione Ctrl+C"
echo ""

# Iniciar o servidor
npm start
