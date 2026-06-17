"""
client.py — PQ-VPN İstemci Tarafı
────────────────────────────────────
Adımlar:
  1. TCP üzerinden sunucuya bağlanır, Public Key alır
  2. Kyber512.encaps(pk) → ciphertext + shared_secret üretir
  3. Ciphertext'i sunucuya gönderir
  4. AES-256-GCM motorunu shared_secret ile başlatır
  5. TUN arayüzünü açar (10.0.0.2/24)
  6. İki yönlü şifreli UDP tüneli çalıştırır + CPU yükünü loglar

Çalıştırma:
  sudo python3 client.py --server-ip <SUNUCU_IP>
"""

import os
import sys
import socket
import threading
import time
import statistics
import argparse

import psutil
from kyber_py.kyber import Kyber512
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

sys.path.insert(0, os.path.dirname(__file__))
from common import (
    create_tun_interface,
    encrypt_packet,
    decrypt_packet,
    HANDSHAKE_PORT,
    TUNNEL_PORT,
    MTU,
)

# ── Yapılandırma ──────────────────────────────────────────────────────────────
TUN_NAME      = "tun0"
TUN_LOCAL_IP  = "10.0.0.2"
TUN_REMOTE_IP = "10.0.0.1"
TUN_NETMASK   = "24"

BANNER = """
╔══════════════════════════════════════════════════════════════════╗
║          POST-QUANTUM SECURE VPN — CLIENT (Makine B)           ║
║    Algoritma: Kyber512 (ML-KEM) + AES-256-GCM                  ║
╚══════════════════════════════════════════════════════════════════╝
"""

# ── Global durum değişkenleri ─────────────────────────────────────────────────
running      = True
cpu_readings = []
packet_count = 0
total_bytes_in  = 0
total_bytes_out = 0


# ═════════════════════════════════════════════════════════════════════════════
# ADIM 1-3: Kyber512 Post-Kuantum El Sıkışması (TCP üzerinden)
# ═════════════════════════════════════════════════════════════════════════════
def perform_kyber_handshake(server_ip: str) -> bytes:
    """
    Sunucuya TCP ile bağlanır, Kyber512 encaps yapar.
    Döndürür: 32-byte shared_secret (AES oturum anahtarı)
    """
    print(f"\n[Handshake] Sunucuya bağlanılıyor: {server_ip}:{HANDSHAKE_PORT} ...")

    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.settimeout(30)
    try:
        conn.connect((server_ip, HANDSHAKE_PORT))
    except ConnectionRefusedError:
        print(f"[HATA] Sunucu bağlantısı reddedildi. Sunucu çalışıyor mu?")
        sys.exit(1)
    except socket.timeout:
        print(f"[HATA] Sunucuya ulaşılamıyor (timeout). IP doğru mu?")
        sys.exit(1)

    print(f"[Handshake] Sunucuya bağlandı ✅")

    # Sunucudan Public Key al
    pk_len = int.from_bytes(conn.recv(4), "big")
    pk = b""
    while len(pk) < pk_len:
        pk += conn.recv(pk_len - len(pk))
    print(f"[Handshake] Sunucunun Public Key'i alındı ({len(pk)} byte).")

    # Kyber Encapsulate: shared_secret + ciphertext üret
    t0 = time.perf_counter()
    shared_secret, ct = Kyber512.encaps(pk)
    encaps_ms = (time.perf_counter() - t0) * 1000
    print(f"[Handshake] Kyber512 encapsulation tamamlandı. ({encaps_ms:.2f} ms)")
    print(f"[Handshake] Ciphertext boyutu: {len(ct)} byte")

    # Ciphertext'i sunucuya gönder
    conn.sendall(len(ct).to_bytes(4, "big"))
    conn.sendall(ct)
    print(f"[Handshake] Kapsül (ciphertext) sunucuya gönderildi.")

    conn.close()
    print(f"[Handshake] ✅ Shared Secret: {shared_secret.hex()[:32]}... (32 byte)")
    print(f"[Handshake] ✅ Encapsulation Süresi: {encaps_ms:.2f} ms")
    return shared_secret


# ═════════════════════════════════════════════════════════════════════════════
# CPU İzleme Thread'i
# ═════════════════════════════════════════════════════════════════════════════
def cpu_monitor_thread():
    global running
    while running:
        cpu_readings.append(psutil.cpu_percent(interval=0.5))


# ═════════════════════════════════════════════════════════════════════════════
# TUN → UDP Yönü (Şifrele ve Gönder)
# ═════════════════════════════════════════════════════════════════════════════
def tun_to_udp(tun_fd: int, aesgcm: AESGCM, udp_sock: socket.socket, server_addr):
    global running, packet_count, total_bytes_out
    while running:
        try:
            packet = os.read(tun_fd, MTU)
            if not packet:
                continue

            payload = encrypt_packet(aesgcm, packet)
            udp_sock.sendto(payload, server_addr)

            packet_count += 1
            total_bytes_out += len(payload)

            overhead = len(payload) - len(packet)
            print(
                f"[→ UDP] #{packet_count:04d} | "
                f"Ham: {len(packet):5d}B | "
                f"Şifreli: {len(payload):5d}B | "
                f"Overhead: {overhead}B | "
                f"CPU: {psutil.cpu_percent():.1f}%"
            )
        except Exception as exc:
            if running:
                print(f"[HATA] tun_to_udp: {exc}")
            break


# ═════════════════════════════════════════════════════════════════════════════
# UDP → TUN Yönü (Deşifre Et ve TUN'a Yaz)
# ═════════════════════════════════════════════════════════════════════════════
def udp_to_tun(tun_fd: int, aesgcm: AESGCM, udp_sock: socket.socket):
    global running, total_bytes_in
    while running:
        try:
            payload, addr = udp_sock.recvfrom(MTU + 64)
            packet = decrypt_packet(aesgcm, payload)
            os.write(tun_fd, packet)
            total_bytes_in += len(packet)
        except Exception as exc:
            if running:
                print(f"[HATA] udp_to_tun: {exc}")
            break


# ═════════════════════════════════════════════════════════════════════════════
# Özet Raporu
# ═════════════════════════════════════════════════════════════════════════════
def print_summary(start_time: float):
    elapsed = time.time() - start_time
    print("\n" + "═" * 65)
    print("  OTURUM ÖZETİ")
    print("═" * 65)
    print(f"  Süre           : {elapsed:.1f} saniye")
    print(f"  Gönderilen Pkt : {packet_count}")
    print(f"  Toplam Çıkış   : {total_bytes_out / 1024:.2f} KB (şifreli)")
    print(f"  Toplam Giriş   : {total_bytes_in / 1024:.2f} KB (çözülmüş)")
    if cpu_readings:
        print(f"  Ort. CPU Yükü  : {statistics.mean(cpu_readings):.1f}%")
        print(f"  Maks. CPU Yükü : {max(cpu_readings):.1f}%")
        print(f"  Min. CPU Yükü  : {min(cpu_readings):.1f}%")

    log_file = os.path.join(os.path.dirname(__file__), "client_cpu_log.csv")
    with open(log_file, "w") as f:
        f.write("sample_no,cpu_percent\n")
        for i, v in enumerate(cpu_readings):
            f.write(f"{i},{v}\n")
    print(f"\n  CPU log dosyası: {log_file}")
    print("═" * 65)


# ═════════════════════════════════════════════════════════════════════════════
# ANA PROGRAM
# ═════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PQ-VPN İstemci")
    parser.add_argument(
        "--server-ip",
        required=True,
        help="Sunucu makinenin IP adresi (örn: 192.168.1.100)",
    )
    args = parser.parse_args()

    print(BANNER)
    print(f"[*] Hedef Sunucu: {args.server_ip}")

    # 1. Kyber512 El Sıkışması
    shared_secret = perform_kyber_handshake(args.server_ip)
    aesgcm = AESGCM(shared_secret)
    print("\n[AES-GCM] Motor Kyber shared secret ile başlatıldı. ✅")

    # 2. TUN Arayüzü
    print(f"\n[TUN] Arayüz oluşturuluyor: {TUN_NAME} ({TUN_LOCAL_IP}/{TUN_NETMASK})")
    tun_fd = create_tun_interface(TUN_NAME)
    os.system(f"ip addr add {TUN_LOCAL_IP}/{TUN_NETMASK} dev {TUN_NAME} 2>/dev/null")
    os.system(f"ip link set dev {TUN_NAME} up")
    print(f"[TUN] {TUN_NAME} → {TUN_LOCAL_IP}/{TUN_NETMASK} aktif. ✅")

    # 3. UDP Soketi
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind(("0.0.0.0", TUNNEL_PORT))
    server_addr = (args.server_ip, TUNNEL_PORT)

    print(f"\n[UDP] Tünel soketi dinleniyor: 0.0.0.0:{TUNNEL_PORT}")
    print(f"[UDP] Paketler → {server_addr} adresine gönderilecek")

    # 4. CPU İzleyici
    threading.Thread(target=cpu_monitor_thread, daemon=True).start()
    print("\n[CPU] İzleme başladı (0.5s aralık).")

    # 5. Tünel Thread'leri
    start_time = time.time()
    t1 = threading.Thread(target=tun_to_udp, args=(tun_fd, aesgcm, udp_sock, server_addr), daemon=True)
    t2 = threading.Thread(target=udp_to_tun, args=(tun_fd, aesgcm, udp_sock), daemon=True)
    t1.start()
    t2.start()

    print("\n" + "═" * 65)
    print(f"  🔒 PQ-VPN Tüneli AKTIF!")
    print(f"  Yerel IP  : {TUN_LOCAL_IP}")
    print(f"  Uzak IP   : {TUN_REMOTE_IP}")
    print(f"  Çıkmak için: Ctrl+C")
    print("═" * 65 + "\n")

    try:
        while True:
            time.sleep(10)
            if cpu_readings:
                avg = statistics.mean(cpu_readings[-20:])
                print(f"[Durum] Paket={packet_count} | CPU_ort={avg:.1f}% | "
                      f"Çıkış={total_bytes_out//1024}KB | Giriş={total_bytes_in//1024}KB")
    except KeyboardInterrupt:
        print("\n\n[!] Ctrl+C alındı. Tünel kapatılıyor...")
        running = False

    # Temizlik
    os.close(tun_fd)
    udp_sock.close()
    os.system(f"ip link set dev {TUN_NAME} down 2>/dev/null")
    os.system(f"ip tuntap del dev {TUN_NAME} mode tun 2>/dev/null")
    print_summary(start_time)
    print("\n[✓] İstemci güvenli şekilde kapatıldı.")
