"""
plain_udp_test.py — Şifresiz UDP Baseline Testi
─────────────────────────────────────────────────
Amaç: PQ-VPN ve Klasik VPN ile karşılaştırmak için
      HİÇBİR şifreleme olmadan UDP paket gönderimindeki
      CPU yükünü ölçmek.

Sunucu (Makine A):
  python3 plain_udp_test.py --mode server

İstemci (Makine B):
  python3 plain_udp_test.py --mode client --server-ip 172.21.195.229
"""

import os, sys, socket, threading, time, statistics, argparse
import psutil

PORT       = 5557
PACKET_SIZE = 1024   # byte — PQ-VPN testindeki iperf paket boyutuna yakın
DURATION    = 60     # saniye

running      = True
cpu_readings = []
recv_count   = 0
send_count   = 0


def cpu_monitor():
    global running
    while running:
        cpu_readings.append(psutil.cpu_percent(interval=0.5))


# ── SUNUCU MODU ────────────────────────────────────────────────────────────────
def run_server():
    global running, recv_count
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", PORT))
    sock.settimeout(2)

    print(f"\n[Sunucu] Şifresiz UDP dinleniyor: 0.0.0.0:{PORT}")
    print(f"[Sunucu] İstemcinin bağlanmasını bekle, sonra Ctrl+C ile durdur.\n")

    threading.Thread(target=cpu_monitor, daemon=True).start()
    start = time.time()

    try:
        while running:
            try:
                data, addr = sock.recvfrom(PACKET_SIZE + 64)
                recv_count += 1
                if recv_count % 100 == 0:
                    elapsed = time.time() - start
                    cpu_now = psutil.cpu_percent()
                    print(f"[←] Alınan: {recv_count:5d} pkt | "
                          f"Ham: {len(data)}B (şifresiz!) | "
                          f"CPU: {cpu_now:.1f}% | Süre: {elapsed:.0f}s")
            except socket.timeout:
                continue
    except KeyboardInterrupt:
        pass

    running = False
    sock.close()
    _print_summary(start, "plain_server_cpu_log.csv")


# ── İSTEMCİ MODU ──────────────────────────────────────────────────────────────
def run_client(server_ip: str):
    global running, send_count
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    payload = os.urandom(PACKET_SIZE)   # Rastgele ham veri (şifresiz!)
    target  = (server_ip, PORT)

    print(f"\n[İstemci] Şifresiz UDP → {server_ip}:{PORT}")
    print(f"[İstemci] Paket boyutu: {PACKET_SIZE} byte | Süre: {DURATION} saniye")
    print(f"[İstemci] Gönderiliyor... (Ctrl+C ile durdur)\n")

    threading.Thread(target=cpu_monitor, daemon=True).start()
    start    = time.time()
    end_time = start + DURATION

    try:
        while time.time() < end_time and running:
            sock.sendto(payload, target)
            send_count += 1
            time.sleep(0.001)   # ~1000 pkt/s ≈ 1 Mbps

            if send_count % 200 == 0:
                elapsed = time.time() - start
                cpu_now = psutil.cpu_percent()
                throughput = (send_count * PACKET_SIZE * 8) / (elapsed * 1_000_000)
                print(f"[→] Gönderilen: {send_count:5d} pkt | "
                      f"{PACKET_SIZE}B HAM (şifresiz!) | "
                      f"CPU: {cpu_now:.1f}% | {throughput:.2f} Mbps")
    except KeyboardInterrupt:
        pass

    running = False
    sock.close()
    _print_summary(start, "plain_client_cpu_log.csv")


# ── ÖZET RAPORU ────────────────────────────────────────────────────────────────
def _print_summary(start_time: float, log_filename: str):
    elapsed = time.time() - start_time
    print("\n" + "═"*60)
    print("  ŞİFRESİZ UDP — OTURUM ÖZETİ")
    print("═"*60)
    print(f"  Süre           : {elapsed:.1f} saniye")
    print(f"  Gönderilen/Alınan: {max(send_count, recv_count)} paket")
    if cpu_readings:
        avg = statistics.mean(cpu_readings)
        mx  = max(cpu_readings)
        mn  = min(cpu_readings)
        print(f"  Ort. CPU Yükü  : {avg:.1f}%")
        print(f"  Maks. CPU Yükü : {mx:.1f}%")
        print(f"  Min. CPU Yükü  : {mn:.1f}%")
        print(f"\n  *** Bu değerleri not alın! ***")
        print(f"  PQ-VPN CPU'su bu değerden yüksekse → şifreleme maliyeti kanıtlanmış!")

        log = os.path.join(os.path.dirname(__file__), log_filename)
        with open(log, "w") as f:
            f.write("sample_no,cpu_percent\n")
            for i, v in enumerate(cpu_readings):
                f.write(f"{i},{v}\n")
        print(f"\n  CPU log: {log}")
    print("═"*60)


# ── ANA PROGRAM ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Şifresiz UDP Baseline Testi")
    parser.add_argument("--mode",      required=True, choices=["server","client"])
    parser.add_argument("--server-ip", help="Sunucu IP (sadece --mode client için)")
    args = parser.parse_args()

    print("╔══════════════════════════════════════════════════════════╗")
    print("║     ŞİFRESİZ UDP BASELINE TESTİ (Karşılaştırma)        ║")
    print("║     Şifreleme YOK — CPU baseline değeri ölçülüyor      ║")
    print("╚══════════════════════════════════════════════════════════╝")

    if args.mode == "server":
        run_server()
    else:
        if not args.server_ip:
            print("[HATA] --server-ip gerekli!")
            sys.exit(1)
        run_client(args.server_ip)
