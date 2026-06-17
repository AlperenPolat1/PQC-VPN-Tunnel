"""
classic_server.py — Klasik VPN Sunucu (RSA-2048 + AES-256-GCM)
────────────────────────────────────────────────────────────────
PQ-VPN ile karşılaştırma için:
  - Kyber512  → RSA-2048 (klasik, kuantuma karşı SAVUNMASIZ)
  - El sıkışma süresi, anahtar boyutları ve CPU yükü karşılaştırılacak

Çalıştırma:
  sudo python3 classic_server.py
"""

import os, sys, socket, threading, time, statistics
import psutil

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

sys.path.insert(0, os.path.dirname(__file__))
from common import create_tun_interface, encrypt_packet, decrypt_packet, MTU

HANDSHAKE_PORT = 4445   # Farklı port (PQ-VPN ile çakışmasın)
TUNNEL_PORT    = 5556
TUN_NAME       = "tun1"
TUN_LOCAL_IP   = "10.1.0.1"
TUN_NETMASK    = "24"

BANNER = """
╔══════════════════════════════════════════════════════════════════╗
║       KLASİK VPN — SERVER (RSA-2048 + AES-256-GCM)            ║
║       ⚠️  KUANTUMA KARŞI SAVUNMASIZ (Karşılaştırma Amaçlı)    ║
╚══════════════════════════════════════════════════════════════════╝
"""

running = True
cpu_readings = []
packet_count = 0
total_bytes_out = 0
total_bytes_in  = 0


def perform_rsa_handshake() -> tuple[bytes, str]:
    """RSA-2048 ile anahtar değişimi (klasik yöntem)."""
    print("\n[Handshake] RSA-2048 anahtar çifti üretiliyor...")

    t0 = time.perf_counter()
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key  = private_key.public_key()
    keygen_ms   = (time.perf_counter() - t0) * 1000
    print(f"[Handshake] RSA-2048 keygen tamamlandı. ({keygen_ms:.2f} ms)")

    # Public Key boyutunu göster (DER formatı)
    pub_der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    print(f"[Handshake] RSA Public Key boyutu : {len(pub_der)} byte")
    print(f"[Handshake] RSA Private Key boyutu: 1218 byte (PKCS8 DER)")

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", HANDSHAKE_PORT))
    srv.listen(1)
    print(f"[Handshake] İstemci bekleniyor... (port {HANDSHAKE_PORT})")

    conn, addr = srv.accept()
    client_ip = addr[0]
    print(f"[Handshake] İstemci bağlandı: {addr[0]}:{addr[1]}")

    # Public Key gönder
    conn.sendall(len(pub_der).to_bytes(4, "big"))
    conn.sendall(pub_der)
    print(f"[Handshake] RSA Public Key gönderildi ({len(pub_der)} byte).")

    # İstemcinin RSA ile şifrelenmiş AES session key'i al
    enc_len = int.from_bytes(conn.recv(4), "big")
    enc_session_key = b""
    while len(enc_session_key) < enc_len:
        enc_session_key += conn.recv(enc_len - len(enc_session_key))
    print(f"[Handshake] Şifreli session key alındı ({len(enc_session_key)} byte).")

    # RSA ile şifreyi çöz → AES oturum anahtarı
    t1 = time.perf_counter()
    session_key = private_key.decrypt(
        enc_session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    decrypt_ms = (time.perf_counter() - t1) * 1000
    print(f"[Handshake] RSA Decrypt tamamlandı. ({decrypt_ms:.2f} ms)")

    conn.close()
    srv.close()

    total_ms = keygen_ms + decrypt_ms
    print(f"[Handshake] ✅ Session Key: {session_key.hex()[:32]}... (32 byte)")
    print(f"[Handshake] ✅ İstemci Fiziksel IP: {client_ip}")
    print(f"[Handshake] ✅ Toplam RSA Handshake Süresi: {total_ms:.2f} ms")
    return session_key, client_ip


def cpu_monitor():
    global running
    while running:
        cpu_readings.append(psutil.cpu_percent(interval=0.5))


def tun_to_udp(tun_fd, aesgcm, udp_sock, client_addr):
    global running, packet_count, total_bytes_out
    while running:
        try:
            packet  = os.read(tun_fd, MTU)
            payload = encrypt_packet(aesgcm, packet)
            udp_sock.sendto(payload, client_addr)
            packet_count    += 1
            total_bytes_out += len(payload)
            overhead = len(payload) - len(packet)
            print(f"[→ UDP] #{packet_count:04d} | Ham:{len(packet):5d}B | "
                  f"Şifreli:{len(payload):5d}B | Overhead:{overhead}B | "
                  f"CPU:{psutil.cpu_percent():.1f}%")
        except Exception as e:
            if running: print(f"[HATA] {e}")
            break


def udp_to_tun(tun_fd, aesgcm, udp_sock, client_addr_ref):
    global running, total_bytes_in
    while running:
        try:
            payload, addr = udp_sock.recvfrom(MTU + 64)
            if client_addr_ref[0] != addr[0]:
                client_addr_ref[0] = addr[0]
                print(f"[UDP] Adres güncellendi: {addr[0]}")
            packet = decrypt_packet(aesgcm, payload)
            os.write(tun_fd, packet)
            total_bytes_in += len(packet)
        except Exception as e:
            if running: print(f"[HATA] {e}")
            break


def print_summary(start_time):
    elapsed = time.time() - start_time
    print("\n" + "═"*65)
    print("  KLASİK VPN — OTURUM ÖZETİ")
    print("═"*65)
    print(f"  Süre           : {elapsed:.1f} saniye")
    print(f"  Gönderilen Pkt : {packet_count}")
    print(f"  Toplam Çıkış   : {total_bytes_out/1024:.2f} KB")
    print(f"  Toplam Giriş   : {total_bytes_in/1024:.2f} KB")
    if cpu_readings:
        print(f"  Ort. CPU Yükü  : {statistics.mean(cpu_readings):.1f}%")
        print(f"  Maks. CPU Yükü : {max(cpu_readings):.1f}%")
        print(f"  Min. CPU Yükü  : {min(cpu_readings):.1f}%")
    log = os.path.join(os.path.dirname(__file__), "classic_server_cpu_log.csv")
    with open(log, "w") as f:
        f.write("sample_no,cpu_percent\n")
        for i, v in enumerate(cpu_readings):
            f.write(f"{i},{v}\n")
    print(f"\n  CPU log: {log}")
    print("═"*65)


if __name__ == "__main__":
    print(BANNER)
    session_key, client_ip = perform_rsa_handshake()
    aesgcm = AESGCM(session_key)
    print("\n[AES-GCM] Motor RSA session key ile başlatıldı. ✅")

    tun_fd = create_tun_interface(TUN_NAME)
    os.system(f"ip addr add {TUN_LOCAL_IP}/{TUN_NETMASK} dev {TUN_NAME} 2>/dev/null")
    os.system(f"ip link set dev {TUN_NAME} up")
    print(f"[TUN] {TUN_NAME} → {TUN_LOCAL_IP}/{TUN_NETMASK} aktif. ✅")

    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind(("0.0.0.0", TUNNEL_PORT))
    client_addr     = (client_ip, TUNNEL_PORT)
    client_addr_ref = [client_ip, TUNNEL_PORT]

    threading.Thread(target=cpu_monitor, daemon=True).start()
    start_time = time.time()

    threading.Thread(target=tun_to_udp,
                     args=(tun_fd, aesgcm, udp_sock, client_addr), daemon=True).start()
    threading.Thread(target=udp_to_tun,
                     args=(tun_fd, aesgcm, udp_sock, client_addr_ref), daemon=True).start()

    print("\n" + "═"*65)
    print(f"  ⚠️  KLASİK VPN Tüneli AKTIF (RSA-2048)")
    print(f"  Yerel IP : {TUN_LOCAL_IP}  |  Uzak IP: 10.1.0.2")
    print(f"  Ctrl+C ile çık")
    print("═"*65 + "\n")

    try:
        while True:
            time.sleep(10)
            if cpu_readings:
                avg = statistics.mean(cpu_readings[-20:])
                print(f"[Durum] Pkt={packet_count} | CPU={avg:.1f}% | "
                      f"Çıkış={total_bytes_out//1024}KB | Giriş={total_bytes_in//1024}KB")
    except KeyboardInterrupt:
        print("\n[!] Kapatılıyor...")
        running = False

    os.close(tun_fd)
    udp_sock.close()
    os.system(f"ip link set dev {TUN_NAME} down 2>/dev/null")
    os.system(f"ip tuntap del dev {TUN_NAME} mode tun 2>/dev/null")
    print_summary(start_time)
    print("[✓] Klasik VPN sunucu kapatıldı.")
