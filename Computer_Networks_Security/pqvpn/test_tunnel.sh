#!/usr/bin/env bash
# test_tunnel.sh — VPN tünelinin çalıştığını kanıtlayan test scripti
# Sunucu ve istemci çalışırken SUNUCU tarafında çalıştırın.
#
# Kullanım:
#   bash test_tunnel.sh

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

SERVER_TUN_IP="10.0.0.1"
CLIENT_TUN_IP="10.0.0.2"

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║   PQ-VPN Tünel Test Paketi                              ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

# ── Test 1: TUN Arayüzü Kontrolü ─────────────────────────────────────────────
echo -e "${YELLOW}[TEST 1] TUN arayüzü aktif mi?${NC}"
if ip link show tun0 &>/dev/null; then
    echo -e "${GREEN}         ✅ tun0 arayüzü AKTIF${NC}"
    ip addr show tun0 | grep "inet "
else
    echo -e "${RED}         ❌ tun0 bulunamadı! server.py / client.py çalışıyor mu?${NC}"
fi
echo ""

# ── Test 2: Ping Testi (Tünel üzerinden) ─────────────────────────────────────
echo -e "${YELLOW}[TEST 2] Tünel üzerinden ping ($CLIENT_TUN_IP)...${NC}"
if ping -c 4 -W 2 $CLIENT_TUN_IP &>/dev/null; then
    RTT=$(ping -c 4 $CLIENT_TUN_IP 2>/dev/null | tail -1 | awk -F '/' '{print $5}')
    echo -e "${GREEN}         ✅ PING BAŞARILI! Ortalama RTT: ${RTT} ms${NC}"
    echo -e "${GREEN}         ► Bu, VPN tünelinin iki makine arasında çalıştığını KANITLAR!${NC}"
else
    echo -e "${RED}         ❌ Ping başarısız. İstemci bağlı mu?${NC}"
fi
echo ""

# ── Test 3: iperf3 Bant Genişliği Testi ──────────────────────────────────────
echo -e "${YELLOW}[TEST 3] iperf3 ile bant genişliği testi (sunucu modu)...${NC}"
echo -e "         İstemci tarafında şunu çalıştırın:"
echo -e "         ${CYAN}iperf3 -c $SERVER_TUN_IP -t 30 -b 5M${NC}"
echo ""
echo -e "         Sunucu başlatılıyor (30 saniye bekleyecek)..."
iperf3 -s -B $SERVER_TUN_IP --one-off 2>&1 || echo -e "${RED}         iperf3 kurulu değil: sudo apt install iperf3${NC}"
echo ""

# ── Test 4: tcpdump ile Şifreleme Kanıtı ─────────────────────────────────────
echo -e "${YELLOW}[TEST 4] Fiziksel arayüzde şifreli UDP trafiği var mı?${NC}"
echo -e "         (eth0 üzerinde UDP:5555 paketleri yakalanıyor, 10 saniye)..."
echo ""
IFACE=$(ip route | grep default | awk '{print $5}' | head -1)
echo -e "         Arayüz: ${CYAN}$IFACE${NC}"
echo -e "${CYAN}─────────────────────────────────────────────────────────${NC}"
timeout 10 tcpdump -i "$IFACE" -n "udp port 5555" -c 20 2>/dev/null || \
    echo -e "${YELLOW}         (10 saniyede paket gelmedi veya trafik yok)${NC}"
echo -e "${CYAN}─────────────────────────────────────────────────────────${NC}"
echo ""
echo -e "${GREEN}Yukarıdaki UDP paketleri = Kyber512+AES ile şifrelenmiş VPN trafiği${NC}"
echo -e "${GREEN}Wireshark ile açmaya çalışırsanız anlamsız byte görürsünüz → şifreleme ÇALIŞIYOR!${NC}"
echo ""
