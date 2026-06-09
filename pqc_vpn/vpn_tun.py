import os
import fcntl
import struct
import socket
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from kyber.kyber import Kyber512  # NIST FIPS 203 ML-KEM Standardı

# Linux kernel ağ arayüzü yapılandırma sabitleri
TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000

def create_tun_interface(tun_name="tun0"):
    tun_fd = os.open("/dev/net/tun", os.O_RDWR)
    ifr = struct.pack('16sH', tun_name.encode('utf-8'), IFF_TUN | IFF_NO_PI)
    fcntl.ioctl(tun_fd, TUNSETIFF, ifr)
    print(f"[{tun_name}] Virtual network interface successfully created!")
    return tun_fd

def pqc_handshake_simulation():
    """
    İki bilgisayarın tünel kurulmadan önce Kyber algoritması ile 
    nasıl ortak bir sır ürettiğini simüle eden El Sıkışma (Handshake) fonksiyonu.
    """
    print("\n--- POST-QUANTUM KEY EXCHANGE (KEM) INITIATED ---")

    # 1. Sunucu anahtar çifti üretir (Server Side)
    print("[Server] Generating Kyber512 Keypair (Public & Secret Keys)...")
    pk, sk = Kyber512.keygen()

    # 2. İstemci, Sunucunun Public Key'ini kullanarak bir sır kapsüller (Client Side)
    print("[Client] Encapsulating Shared Secret using Server's Public Key...")
    client_shared_secret, ciphertext = Kyber512.encaps(pk)


    # 3. Sunucu, şifreli metni kendi Secret Key'i ile açar (Server Side)
    print("[Server] Decapsulating Ciphertext to extract Shared Secret...")
    server_shared_secret = Kyber512.decaps(sk, ciphertext)

    # 4. İki tarafın da aynı sırra sahip olduğunu doğrula
    assert client_shared_secret == server_shared_secret
    print("[*] Handshake Successful! Both sides established a Quantum-Resistant Shared Secret.")

    # Kyber bize 32 byte'lık (256-bit) mükemmel bir AES anahtarı verir
    print(f"[*] Derived AES Key: {server_shared_secret.hex()[:32]}...\n")
    return server_shared_secret

if __name__ == "__main__":
    print("Starting the Post-Quantum Secure VPN Tunnel...")
    # AŞAMA 3: STATİK ANAHTARI SİLİP, DİNAMİK KYBER ANAHTARINI DEVREYE ALIYORUZ
    dynamic_key = pqc_handshake_simulation()
    aesgcm = AESGCM(dynamic_key)

    fd = create_tun_interface()
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    DEST_IP = "127.0.0.1"
    DEST_PORT = 5555
    print(f"Listening for packets... Encrypting with PQC-Derived Key and forwarding via UDP")

    try:
        while True:
            # 1. TUN'dan ham IP paketini oku
            packet = os.read(fd, 2048)

            # 2. Şifreleme için 12-byte rastgele Nonce üret
            nonce = os.urandom(12)

            # 3. Paketi Kyber'in ürettiği yepyeni dinamik anahtarla AES-GCM üzerinden şifrele
            encrypted_packet = aesgcm.encrypt(nonce, packet, None)
            payload = nonce + encrypted_packet

            # 4. Raporlama için Overhead çıktısı
            print(f"[*] Raw Packet: {len(packet)} bytes | Encrypted: {len(payload)} bytes (PQC-Secured)")

            # 5. Şifrelenmiş veriyi UDP üzerinden fırlat
            udp_socket.sendto(payload, (DEST_IP, DEST_PORT))

    except KeyboardInterrupt:
        print("\nClosing the secure tunnel...")
        os.close(fd)
        udp_socket.close()
