#!/bin/bash
# m7smartssrf - One-Click Installer
# By: Sharlix | Milkyway Intelligence | httpsm7

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${CYAN}"
echo "  ╔══════════════════════════════════════════════╗"
echo "  ║   m7smartssrf Installer                      ║"
echo "  ║   By: Sharlix | Milkyway Intelligence        ║"
echo "  ╚══════════════════════════════════════════════╝"
echo -e "${NC}"

# Check Python3
if ! command -v python3 &>/dev/null; then
    echo -e "${RED}[!] Python3 not found. Install it first.${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Python3 found: $(python3 --version)${NC}"

# Install PyYAML (only external dep)
echo -e "${CYAN}[*] Installing PyYAML...${NC}"
pip3 install pyyaml --break-system-packages -q 2>/dev/null || \
pip3 install pyyaml -q 2>/dev/null || true

# Create directories
mkdir -p logs reports

# Make executable
chmod +x m7smartssrf.py

# Create wrapper in /usr/local/bin
TOOL_DIR="$(cd "$(dirname "$0")" && pwd)"

cat > /tmp/m7smartssrf_wrapper << EOF
#!/bin/bash
cd "$TOOL_DIR"
python3 "$TOOL_DIR/m7smartssrf.py" "\$@"
EOF

if [ -w /usr/local/bin ]; then
    cp /tmp/m7smartssrf_wrapper /usr/local/bin/m7smartssrf
    chmod +x /usr/local/bin/m7smartssrf
    echo -e "${GREEN}[+] Installed to /usr/local/bin/m7smartssrf${NC}"
else
    sudo cp /tmp/m7smartssrf_wrapper /usr/local/bin/m7smartssrf
    sudo chmod +x /usr/local/bin/m7smartssrf
    echo -e "${GREEN}[+] Installed to /usr/local/bin/m7smartssrf (sudo)${NC}"
fi

echo ""
echo -e "${GREEN}[+] Installation complete!${NC}"
echo -e "${YELLOW}[*] Usage:${NC}"
echo -e "    m7smartssrf scan urls.txt"
echo -e "    m7smartssrf scan urls.txt --threads 50 --oob"
echo -e "    m7smartssrf scan urls.txt --mode deep --bypass all"
echo -e "    m7smartssrf --help"
echo ""
echo -e "${RED}[!] Use only on authorized targets. Unauthorized use is illegal.${NC}"
