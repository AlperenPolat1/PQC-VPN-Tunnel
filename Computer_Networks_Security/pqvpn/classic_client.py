"""
classic_client.py — Klasik VPN İstemci (RSA-2048 + AES-256-GCM)
─────────────────────────────────────────────────────────────────
Çalıştırma:
  sudo python3 classic_client.py --server-ip <SUNUCU_IP>
"""

import os, sys, socket, threading, time, statistics, argparse
import psutil

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.backends import default_backend

sys.path.insert(0, os.path.dirname(__file__))
from common import create_tun_interface, encrypt_packet, decrypt_packet, MTU

HANDSHAKE_PORT = 4445
TUNNEL_PORT    = 5556
TUN_NAME       = "tun1"
TUN_LOCAL_IP   = "10.1.0.2"
TUN_NETMASK    = "24"

BANNER = """
╔══════════════════════════════════════════════════════════════════╗
║       KLASİK VPN — CLIENT (RSA-2048 + AES-256-GCM)            ║
║       ⚠️  KUANTUMA KARŞI SAVUNMASIZ (Karşılaştırma Amaçlı)    ║
╚══════════════════════════════════════════════════════════════════╝
"""

running = True
cpu_readings = []
packet_count = 0
total_bytes_out = 0
total_bytes_in  = 0


def perform_rsa_handshake(server_ip: str) -> bytes:
    """Sunucudan RSA public key al, AES session key üret ve RSA ile şifrele."""
    print(f"\n[Handshake] Sunucuya bağlanılıyor: {server_ip}:{HANDSHAKE_PORT}")
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.settimeout(30)
    conn.connect((server_ip, HANDSHAKE_PORT))
    print("[Handshake] Bağlandı ✅")

    # Sunucunun RSA Public Key'ini al
    pk_len = int.from_bytes(conn.recv(4), "big")
    pub_der = b""
    while len(pub_der) < pk_len:
        pub_der += conn.recv(pk_len - len(pub_der))
    print(f"[Handshake] RSA Public Key alındı ({len(pub_der)} byte).")

    public_key: RSAPublicKey = serialization.load_der_public_key(
        pub_der, backend=default_backend()
    )

    # 32 byte rastgele AES session key üret
    session_key = os.urandom(32)

    # Session key'i sunucunun RSA public key'i ile şifrele
    t0 = time.perf_counter()
    enc_session_key = public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    encaps_ms = (time.perf_counter() - t0) * 1000
    print(f"[Handshake] RSA Encrypt tamamlandı. ({encaps_ms:.2f} ms)")
    print(f"[Handshake] Şifreli session key boyutu: {len(enc_session_key)} byte")

    # Sunucuya gönder
    conn.sendall(len(enc_session_key).to_bytes(4, "big"))
    conn.sendall(enc_session_key)
    print(f"[Handshake] Şifreli session key gönderildi.")

    conn.close()
    print(f"[Handshake] ✅ Session Key: {session_key.hex()[:32]}... (32 byte)")
    print(f"[Handshake] ✅ RSA Encrypt Süresi: {encaps_ms:.2f} ms")
    return session_key


def cpu_monitor():
    global running
    while running:
        cpu_readings.append(psutil.cpu_percent(interval=0.5))


def tun_to_udp(tun_fd, aesgcm, udp_sock, server_addr):
    global running, packet_count, total_bytes_out
    while running:
        try:
            packet  = os.read(tun_fd, MTU)
            payload = encrypt_packet(aesgcm, packet)
            udp_sock.sendto(payload, server_addr)
            packet_count    += 1
            total_bytes_out += len(payload)
            overhead = len(payload) - len(packet)
            print(f"[→ UDP] #{packet_count:04d} | Ham:{len(packet):5d}B | "
                  f"Şifreli:{len(payload):5d}B | Overhead:{overhead}B | "
                  f"CPU:{psutil.cpu_percent():.1f}%")
        except Exception as e:
            if running: print(f"[HATA] {e}")
            break


def udp_to_tun(tun_fd, aesgcm, udp_sock):
    global running, total_bytes_in
    while running:
        try:
            payload, _ = udp_sock.recvfrom(MTU + 64)
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
    if cpu_readings:
        print(f"  Ort. CPU Yükü  : {statistics.mean(cpu_readings):.1f}%")
        print(f"  Maks. CPU Yükü : {max(cpu_readings):.1f}%")
    log = os.path.join(os.path.dirname(__file__), "classic_client_cpu_log.csv")
    with open(log, "w") as f:
        f.write("sample_no,cpu_percent\n")
        for i, v in enumerate(cpu_readings):
            f.write(f"{i},{v}\n")
    print(f"\n  CPU log: {log}")
    print("═"*65)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--server-ip", required=True)
    args = parser.parse_args()

    print(BANNER)
    session_key = perform_rsa_handshake(args.server_ip)
    aesgcm = AESGCM(session_key)
    print("\n[AES-GCM] Motor RSA session key ile başlatıldı. ✅")

    tun_fd = create_tun_interface(TUN_NAME)
    os.system(f"ip addr add {TUN_LOCAL_IP}/{TUN_NETMASK} dev {TUN_NAME} 2>/dev/null")
    os.system(f"ip link set dev {TUN_NAME} up")
    print(f"[TUN] {TUN_NAME} → {TUN_LOCAL_IP}/{TUN_NETMASK} aktif. ✅")

    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind(("0.0.0.0", TUNNEL_PORT))
    server_addr = (args.server_ip, TUNNEL_PORT)

    threading.Thread(target=cpu_monitor, daemon=True).start()
    start_time = time.time()

    threading.Thread(target=tun_to_udp,
                     args=(tun_fd, aesgcm, udp_sock, server_addr), daemon=True).start()
    threading.Thread(target=udp_to_tun,
                     args=(tun_fd, aesgcm, udp_sock), daemon=True).start()

    print("\n" + "═"*65)
    print(f"  ⚠️  KLASİK VPN Tüneli AKTIF (RSA-2048)")
    print(f"  Yerel IP : {TUN_LOCAL_IP}  |  Uzak IP: 10.1.0.1")
    print(f"  Ctrl+C ile çık")
    print("═"*65 + "\n")

    try:
        while True:
            time.sleep(10)
            if cpu_readings:
                avg = statistics.mean(cpu_readings[-20:])
                print(f"[Durum] Pkt={packet_count} | CPU={avg:.1f}%")
    except KeyboardInterrupt:
        print("\n[!] Kapatılıyor...")
        running = False

    os.close(tun_fd)
    udp_sock.close()
    os.system(f"ip link set dev {TUN_NAME} down 2>/dev/null")
    os.system(f"ip tuntap del dev {TUN_NAME} mode tun 2>/dev/null")
    print_summary(start_time)
    print("[✓] Klasik VPN istemci kapatıldı.")
