#!/usr/bin/env bash
#═══════════════════════════════════════════════════════════════
# GHOST RECON v2.0 — Dependency Installer
# Run: chmod +x install.sh && ./install.sh
#═══════════════════════════════════════════════════════════════

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BLUE='\033[0;34m'; NC='\033[0m'

log_info()    { echo -e "${BLUE}[ℹ]${NC} $1"; }
log_success() { echo -e "${GREEN}[✓]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[⚠]${NC} $1"; }
log_error()   { echo -e "${RED}[✗]${NC} $1"; }

TOOLS_DIR="$HOME/tools"
GO_BIN="$HOME/go/bin"

echo -e "\n${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║${NC}  GHOST RECON v2.0 — Dependency Installer               ${BLUE}║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}\n"

# ── Check Go ──
install_go_tool() {
  local name="$1"
  local pkg="$2"
  if command -v "$name" &>/dev/null; then
    log_success "$name already installed"
  else
    log_info "Installing $name..."
    go install "$pkg" 2>/dev/null && log_success "$name installed" || log_warn "Failed to install $name"
  fi
}

# ── Check Go installation ──
if ! command -v go &>/dev/null; then
  log_warn "Go not found. Installing Go 1.22..."
  wget -q "https://go.dev/dl/go1.22.5.linux-amd64.tar.gz" -O /tmp/go.tar.gz
  sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf /tmp/go.tar.gz
  export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
  echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
  log_success "Go installed"
fi

export PATH=$PATH:$GO_BIN

# ── System dependencies ──
log_info "Installing system dependencies..."
if command -v apt-get &>/dev/null; then
  sudo apt-get update -qq
  sudo apt-get install -y -qq curl jq python3 python3-pip git bc dnsutils whois > /dev/null 2>&1
  log_success "System deps installed"
elif command -v dnf &>/dev/null; then
  sudo dnf install -y -q curl jq python3 python3-pip git bc bind-utils whois > /dev/null 2>&1
  log_success "System deps installed"
fi

# ── Go-based tools (ProjectDiscovery ecosystem + others) ──
log_info "Installing Go-based recon tools..."

install_go_tool "subfinder"   "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
install_go_tool "httpx"       "github.com/projectdiscovery/httpx/cmd/httpx@latest"
install_go_tool "nuclei"      "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
install_go_tool "katana"      "github.com/projectdiscovery/katana/cmd/katana@latest"
install_go_tool "dnsx"        "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
install_go_tool "naabu"       "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
install_go_tool "gau"         "github.com/lc/gau/v2/cmd/gau@latest"
install_go_tool "waybackurls" "github.com/tomnomnom/waybackurls@latest"
install_go_tool "anew"        "github.com/tomnomnom/anew@latest"
install_go_tool "unfurl"      "github.com/tomnomnom/unfurl@latest"
install_go_tool "gospider"    "github.com/jaeles-project/gospider@latest"
install_go_tool "ffuf"        "github.com/ffuf/ffuf/v2@latest"
install_go_tool "dalfox"      "github.com/hahwul/dalfox/v2@latest"
install_go_tool "assetfinder" "github.com/tomnomnom/assetfinder@latest"
install_go_tool "gf"          "github.com/tomnomnom/gf@latest"
install_go_tool "crlfuzz"     "github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"

# ── Optional: dnsgen + puredns for subdomain permutation ──
install_go_tool "puredns"     "github.com/d3mondev/puredns/v2@latest"
if ! command -v dnsgen &>/dev/null; then
  log_info "Installing dnsgen (Python)..."
  pip3 install dnsgen --quiet 2>/dev/null && log_success "dnsgen installed" || log_warn "dnsgen install failed"
fi

# ── Ghost's own Python dependencies ──
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
log_info "Installing Ghost Python requirements..."
pip3 install -r "$SCRIPT_DIR/requirements.txt" --quiet 2>/dev/null \
  || pip3 install -r "$SCRIPT_DIR/requirements.txt" --quiet --break-system-packages \
  && log_success "Python requirements installed" || log_warn "pip install failed — see requirements.txt"

# ── Python tools ──
mkdir -p "$TOOLS_DIR"

# LinkFinder
if [[ ! -d "$TOOLS_DIR/LinkFinder" ]]; then
  log_info "Installing LinkFinder..."
  git clone -q https://github.com/GerbenJavado/LinkFinder.git "$TOOLS_DIR/LinkFinder" 2>/dev/null
  cd "$TOOLS_DIR/LinkFinder" && pip3 install -r requirements.txt --quiet 2>/dev/null
  cd - > /dev/null
  log_success "LinkFinder installed"
else
  log_success "LinkFinder already installed"
fi

# SecretFinder
if [[ ! -d "$TOOLS_DIR/SecretFinder" ]]; then
  log_info "Installing SecretFinder..."
  git clone -q https://github.com/m4ll0k/SecretFinder.git "$TOOLS_DIR/SecretFinder" 2>/dev/null
  cd "$TOOLS_DIR/SecretFinder" && pip3 install -r requirements.txt --quiet 2>/dev/null
  cd - > /dev/null
  log_success "SecretFinder installed"
else
  log_success "SecretFinder already installed"
fi

# ── Update nuclei templates ──
log_info "Updating nuclei templates..."
nuclei -ut -silent 2>/dev/null && log_success "Nuclei templates updated" || log_warn "Template update failed"

# ── PATH setup ──
if ! echo "$PATH" | grep -q "$GO_BIN"; then
  echo "export PATH=\$PATH:$GO_BIN" >> ~/.bashrc
  log_info "Added $GO_BIN to PATH in .bashrc"
fi

echo -e "\n${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║${NC}  Installation complete!                                  ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}                                                          ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}  Run: source ~/.bashrc && python3 ghost.py -u <target>   ${GREEN}║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}\n"
