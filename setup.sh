#!/usr/bin/env bash
# CTI Agentic System — Linux/Mac Setup Script
# Run once:  chmod +x setup.sh && ./setup.sh

set -euo pipefail

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
step()  { echo -e "\n${CYAN}==> $1${NC}"; }
ok()    { echo -e "  ${GREEN}OK${NC}  $1"; }
warn()  { echo -e "  ${YELLOW}WARN${NC}  $1"; }
fail()  { echo -e "  ${RED}FAIL${NC}  $1"; exit 1; }

echo ""
echo -e "${GREEN}================================================${NC}"
echo -e "${GREEN} CTI Agentic System — Auto Setup (Linux/Mac)  ${NC}"
echo -e "${GREEN}================================================${NC}"

# ── 1. Python check ────────────────────────────────────────────────────────────
step "Checking Python 3.10+"
if ! command -v python3 &>/dev/null; then
    fail "python3 not found. Install from https://python.org or via your package manager."
fi
PYVER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PYMAJ=$(echo "$PYVER" | cut -d. -f1)
PYMIN=$(echo "$PYVER" | cut -d. -f2)
if [ "$PYMAJ" -lt 3 ] || { [ "$PYMAJ" -eq 3 ] && [ "$PYMIN" -lt 10 ]; }; then
    fail "Python 3.10+ required. Found: $PYVER"
fi
ok "Python $PYVER"

# ── 2. uv install ──────────────────────────────────────────────────────────────
step "Checking uv (fast Python package manager)"
UV_CMD=""
if command -v uv &>/dev/null; then
    ok "uv already installed: $(uv --version)"
    UV_CMD="uv"
else
    warn "uv not found. Installing..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="$HOME/.local/bin:$PATH"
    if command -v uv &>/dev/null; then
        ok "uv installed: $(uv --version)"
        UV_CMD="uv"
    else
        warn "uv install failed — falling back to pip"
    fi
fi

# ── 3. Python dependencies ─────────────────────────────────────────────────────
step "Installing Python dependencies"
if [ -n "$UV_CMD" ]; then
    uv sync
    ok "Dependencies installed via uv"
else
    python3 -m pip install -r requirements.txt
    ok "Dependencies installed via pip"
fi

# ── 4. Ollama install ──────────────────────────────────────────────────────────
step "Checking Ollama"
if command -v ollama &>/dev/null; then
    ok "Ollama already installed: $(ollama --version 2>/dev/null || echo 'version unknown')"
else
    warn "Ollama not found. Installing via official script..."
    curl -fsSL https://ollama.com/install.sh | sh
    if ! command -v ollama &>/dev/null; then
        fail "Ollama install failed. Install manually from https://ollama.com/download then re-run."
    fi
    ok "Ollama installed"
fi

# ── 5. Start Ollama service ────────────────────────────────────────────────────
step "Starting Ollama service"
if curl -sf http://localhost:11434/api/tags >/dev/null 2>&1; then
    ok "Ollama already running"
else
    ollama serve &>/dev/null &
    ok "Ollama service started (background PID $!)"
    sleep 5
fi

# ── 6. Pull llama3.2:3b ────────────────────────────────────────────────────────
step "Pulling llama3.2:3b model (~2 GB, first time only)"
ollama pull llama3.2:3b
ok "llama3.2:3b ready"

# ── 7. Copy .env if missing ────────────────────────────────────────────────────
if [ ! -f ".env" ]; then
    cp .env.example .env
    ok ".env created from .env.example"
fi

# ── Done ───────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}================================================${NC}"
echo -e "${GREEN} Setup complete! Starting CTI Agentic System...${NC}"
echo -e "${GREEN} Dashboard will open at http://localhost:8888  ${NC}"
echo -e "${GREEN}================================================${NC}"
echo ""

if [ -n "$UV_CMD" ]; then
    uv run main.py
else
    python3 main.py
fi
