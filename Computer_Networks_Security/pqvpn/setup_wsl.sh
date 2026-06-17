#!/usr/bin/env bash
# setup_wsl.sh — WSL2 Ubuntu içinde çalıştırın (sudo ile)
# Her iki PC'deki WSL2'de de aynı script çalışacak.
#
# Kullanım:
#   chmod +x setup_wsl.sh
#   sudo bash setup_wsl.sh

set -e

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║   PQ-VPN — WSL2 Ubuntu Kurulum Scripti                  ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

# ── 1. Paket Güncelleme ───────────────────────────────────────────────────────
echo -e "${YELLOW}[1/5] Sistem güncelleniyor...${NC}"
apt-get update -qq
apt-get upgrade -y -qq
echo -e "${GREEN}      ✅ Sistem güncellendi.${NC}"

# ── 2. Gerekli Araçlar ────────────────────────────────────────────────────────
echo -e "${YELLOW}[2/5] Gerekli araçlar kuruluyor (iperf3, wireshark-common, iproute2)...${NC}"
apt-get install -y -qq python3 python3-pip iperf3 iproute2 net-tools tcpdump
echo -e "${GREEN}      ✅ Araçlar kuruldu.${NC}"

# ── 3. Python Kütüphaneleri ───────────────────────────────────────────────────
echo -e "${YELLOW}[3/5] Python kütüphaneleri kuruluyor...${NC}"
pip3 install --quiet --break-system-packages kyber-py cryptography psutil
echo -e "${GREEN}      ✅ kyber-py, cryptography, psutil kuruldu.${NC}"

# ── 4. Kurulum Doğrulama ──────────────────────────────────────────────────────
echo -e "${YELLOW}[4/5] Kurulum doğrulanıyor...${NC}"
python3 -c "from kyber_py.kyber import Kyber512; print('      ✅ kyber-py OK')"
python3 -c "from cryptography.hazmat.primitives.ciphers.aead import AESGCM; print('      ✅ cryptography OK')"
python3 -c "import psutil; print('      ✅ psutil OK')"
python3 -c "import fcntl, struct; print('      ✅ TUN gereksinimleri OK')"

# ── 5. IP Bilgisi ─────────────────────────────────────────────────────────────
echo -e "${YELLOW}[5/5] Ağ bilgisi alınıyor...${NC}"
echo ""
echo -e "${CYAN}══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  Bu WSL2 makinesinin IP adresi:${NC}"
ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v "127.0.0.1"
echo ""
echo -e "${CYAN}  ⚠️  mirrored mod açık ise bu IP = Windows IP'dir${NC}"
echo -e "${CYAN}  ⚠️  Karşı makineden bu IP'ye ping atarak test edin${NC}"
echo -e "${CYAN}══════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${GREEN}  KURULUM TAMAMLANDI!${NC}"
echo ""
echo -e "  Sonraki adım:"
echo -e "  ${YELLOW}Makine A (Sunucu):${NC}"
echo -e "    cd /mnt/c/Users/MUSTAFA/Desktop/CENG\\ FİLES/3.SINIF/bahar/network/pqvpn"
echo -e "    sudo python3 server.py"
echo ""
echo -e "  ${YELLOW}Makine B (İstemci):${NC}"
echo -e "    cd /mnt/c/Users/MUSTAFA/Desktop/CENG\\ FİLES/3.SINIF/bahar/network/pqvpn"
echo -e "    sudo python3 client.py --server-ip <MAKİNE_A_IP>"
echo ""
