#!/bin/bash
# KILLER ENGINE V2.0 - VPS Auto Setup Script
# Run this on fresh Linux VPS (Ubuntu/Debian)

set -e

echo "=========================================="
echo "  KILLER ENGINE V2.0 - VPS AUTO SETUP"
echo "=========================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}[!] Please run as root: sudo bash setup_vps.sh${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Updating system...${NC}"
apt update && apt upgrade -y

echo -e "${GREEN}[+] Installing Python 3.10+...${NC}"
apt install -y python3 python3-pip python3-venv git curl wget htop iftop tmux screen

# Check Python version
PYTHON_VERSION=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1,2)
echo -e "${GREEN}[+] Python version: $PYTHON_VERSION${NC}"

if (( $(echo "$PYTHON_VERSION < 3.8" | bc -l) )); then
    echo -e "${RED}[!] Python 3.8+ required. Current: $PYTHON_VERSION${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Creating virtual environment...${NC}"
python3 -m venv venv

echo -e "${GREEN}[+] Activating virtual environment...${NC}"
source venv/bin/activate

echo -e "${GREEN}[+] Installing Python dependencies...${NC}"
pip install --upgrade pip
pip install -r requirements.txt

echo -e "${GREEN}[+] Optimizing system for high performance...${NC}"

# Increase file descriptors
cat >> /etc/security/limits.conf << EOF
* soft nofile 65535
* hard nofile 65535
root soft nofile 65535
root hard nofile 65535
EOF

# TCP tuning
sysctl -w net.ipv4.tcp_tw_reuse=1
sysctl -w net.ipv4.ip_local_port_range="1024 65535"
sysctl -w net.core.somaxconn=65535
sysctl -w net.ipv4.tcp_max_syn_backlog=8192
sysctl -w net.core.netdev_max_backlog=5000

# Make persistent
cat >> /etc/sysctl.conf << EOF
net.ipv4.tcp_tw_reuse=1
net.ipv4.ip_local_port_range=1024 65535
net.core.somaxconn=65535
net.ipv4.tcp_max_syn_backlog=8192
net.core.netdev_max_backlog=5000
EOF

echo -e "${GREEN}[+] Checking premium proxies...${NC}"
if [ -f "proxies/premium_proxy.txt" ]; then
    PROXY_COUNT=$(wc -l < proxies/premium_proxy.txt)
    echo -e "${GREEN}[+] Found $PROXY_COUNT premium proxies${NC}"
else
    echo -e "${YELLOW}[!] Premium proxy file not found: proxies/premium_proxy.txt${NC}"
    echo -e "${YELLOW}[!] Please upload your proxies before running attack${NC}"
fi

echo ""
echo -e "${GREEN}=========================================="
echo -e "  SETUP COMPLETE!"
echo -e "==========================================${NC}"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "1. Upload premium proxies to: proxies/premium_proxy.txt"
echo "2. Activate venv: source venv/bin/activate"
echo "3. Run attack: python3 launch_extreme.py"
echo ""
echo -e "${YELLOW}Run in background:${NC}"
echo "  tmux new -s attack"
echo "  python3 launch_extreme.py"
echo "  Ctrl+B then D to detach"
echo ""
echo -e "${GREEN}[+] System optimized for high-performance attacks!${NC}"
