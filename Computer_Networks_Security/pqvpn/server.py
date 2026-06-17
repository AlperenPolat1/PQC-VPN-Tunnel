"""
server.py — PQ-VPN Sunucu Tarafı
─────────────────────────────────
Adımlar:
  1. Kyber512 anahtar çifti üretir (keygen)
  2. TCP üzerinden istemciye Public Key gönderir
  3. İstemciden gelen kapsülü (ciphertext) kendi sk ile açar → shared_secret
  4. AES-256-GCM motorunu shared_secret ile başlatır
  5. TUN arayüzünü açar (10.0.0.1/24)
  6. İki yönlü şifreli UDP tüneli çalıştırır + CPU yükünü loglar

Çalıştırma:
  sudo python3 server.py
"""

import os
import sys
import socket
import threading
import time
import statistics
import datetime

import psutil
from kyber_py.kyber import Kyber512
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Proje klasörümüzdeki common.py'yi bul
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
TUN_LOCAL_IP  = "10.0.0.1"
TUN_REMOTE_IP = "10.0.0.2"
TUN_NETMASK   = "24"

BANNER = """
╔══════════════════════════════════════════════════════════════════╗
║          POST-QUANTUM SECURE VPN — SERVER (Makine A)           ║
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
def perform_kyber_handshake() -> tuple[bytes, str]:
    """
    TCP soketi üzerinden gerçek Kyber512 el sıkışması yapar.
    Döndürür: (shared_secret, client_physical_ip)
    """
    print("\n[Handshake] TCP sunucusu başlatılıyor...")
    print(f"[Handshake] Kyber512 anahtar çifti üretiliyor...")

    t0 = time.perf_counter()
    pk, sk = Kyber512.keygen()
    keygen_ms = (time.perf_counter() - t0) * 1000
    print(f"[Handshake] Kyber512 keygen tamamlandı. ({keygen_ms:.2f} ms)")
    print(f"[Handshake] Public Key boyutu : {len(pk)} byte")
    print(f"[Handshake] Private Key boyutu: {len(sk)} byte")

    # TCP sunucusu aç ve istemciyi bekle
    srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv_sock.bind(("0.0.0.0", HANDSHAKE_PORT))
    srv_sock.listen(1)
    print(f"[Handshake] İstemci bekleniyor... (port {HANDSHAKE_PORT})")

    conn, addr = srv_sock.accept()
    print(f"[Handshake] İstemci bağlandı: {addr[0]}:{addr[1]}")

    # Public Key'i istemciye gönder
    conn.sendall(len(pk).to_bytes(4, "big"))  # önce boyut (4 byte)
    conn.sendall(pk)
    print(f"[Handshake] Public Key istemciye gönderildi ({len(pk)} byte).")

    # İstemciden kapsülü (ciphertext) al
    ct_len = int.from_bytes(conn.recv(4), "big")
    ct = b""
    while len(ct) < ct_len:
        ct += conn.recv(ct_len - len(ct))
    print(f"[Handshake] Kapsül (ciphertext) alındı ({len(ct)} byte).")

    # Kapsülü özel anahtarla aç → shared_secret
    t1 = time.perf_counter()
    shared_secret = Kyber512.decaps(sk, ct)
    decaps_ms = (time.perf_counter() - t1) * 1000
    print(f"[Handshake] Decapsulation tamamlandı. ({decaps_ms:.2f} ms)")

    client_ip = addr[0]   # ← İstemcinin gerçek fiziksel IP'si (TCP'den öğrenildi)
    conn.close()
    srv_sock.close()

    print(f"[Handshake] ✅ Shared Secret: {shared_secret.hex()[:32]}... (32 byte)")
    print(f"[Handshake] ✅ İstemci Fiziksel IP: {client_ip}")
    print(f"[Handshake] ✅ Toplam Handshake Süresi: {keygen_ms + decaps_ms:.2f} ms")
    return shared_secret, client_ip


# ═════════════════════════════════════════════════════════════════════════════
# CPU İzleme Thread'i
# ═════════════════════════════════════════════════════════════════════════════
def cpu_monitor_thread():
    """Her 0.5 saniyede CPU yüzdesini kayıt eder."""
    global running
    while running:
        cpu_readings.append(psutil.cpu_percent(interval=0.5))


# ═════════════════════════════════════════════════════════════════════════════
# TUN → UDP Yönü (Okuma: şifrele ve gönder)
# ═════════════════════════════════════════════════════════════════════════════
def tun_to_udp(tun_fd: int, aesgcm: AESGCM, udp_sock: socket.socket, client_addr):
    global running, packet_count, total_bytes_out
    while running:
        try:
            packet = os.read(tun_fd, MTU)
            if not packet:
                continue

            payload = encrypt_packet(aesgcm, packet)
            udp_sock.sendto(payload, client_addr)

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
# UDP → TUN Yönü (Alma: deşifre et ve TUN'a yaz)
# ═════════════════════════════════════════════════════════════════════════════
def udp_to_tun(tun_fd: int, aesgcm: AESGCM, udp_sock: socket.socket, client_addr_ref: list):
    """
    UDP'den şifreli paket alır, deşifre edip TUN'a yazar.
    client_addr_ref: [ip, port] — ilk paketten öğrenilir, tun_to_udp ile paylaşılır.
    """
    global running, total_bytes_in
    while running:
        try:
            payload, addr = udp_sock.recvfrom(MTU + 64)
            # İstemcinin UDP adresini dinamik olarak öğren (NAT arkasında da çalışır)
            if client_addr_ref[0] != addr[0]:
                client_addr_ref[0] = addr[0]
                client_addr_ref[1] = addr[1]
                print(f"[UDP] İstemci adresi güncellendi: {addr[0]}:{addr[1]}")
            packet = decrypt_packet(aesgcm, payload)
            os.write(tun_fd, packet)
            total_bytes_in += len(packet)
        except Exception as exc:
            if running:
                print(f"[HATA] udp_to_tun: {exc}")
            break


# ═════════════════════════════════════════════════════════════════════════════
# Özet Raporu Yazdır
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

    # CSV dosyasına kaydet
    log_file = os.path.join(os.path.dirname(__file__), "server_cpu_log.csv")
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
    print(BANNER)

    # 1. Kyber512 El Sıkışması
    shared_secret, client_physical_ip = perform_kyber_handshake()
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
    # İstemcinin gerçek fiziksel IP'si (TUN IP değil!) — TCP handshake'ten öğrenildi
    client_addr_ref = [client_physical_ip, TUNNEL_PORT]
    client_addr = (client_physical_ip, TUNNEL_PORT)

    print(f"\n[UDP] Tünel soketi dinleniyor: 0.0.0.0:{TUNNEL_PORT}")
    print(f"[UDP] İstemci fiziksel adresi: {client_physical_ip}:{TUNNEL_PORT}")

    # 4. CPU İzleyici
    threading.Thread(target=cpu_monitor_thread, daemon=True).start()
    print("\n[CPU] İzleme başladı (0.5s aralık).")

    # 5. Tünel Thread'leri
    start_time = time.time()
    t1 = threading.Thread(target=tun_to_udp, args=(tun_fd, aesgcm, udp_sock, client_addr), daemon=True)
    t2 = threading.Thread(target=udp_to_tun, args=(tun_fd, aesgcm, udp_sock, client_addr_ref), daemon=True)
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
                avg = statistics.mean(cpu_readings[-20:])   # Son 10 sn
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
    print("\n[✓] Sunucu güvenli şekilde kapatıldı.")
