import os
import fcntl
import struct
import socket
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Linux kernel ağ arayüzü yapılandırma sabitleri
TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000

# AES-256-GCM için 32-byte (256-bit) statik test anahtarı
# Not: 3. Aşamada bu anahtar, Post-Kuantum (Kyber) algoritmasıyla iki bilgisayar arasında dinamik üretilecek!
STATIC_KEY = b'12345678901234567890123456789012'
aesgcm = AESGCM(STATIC_KEY)

def create_tun_interface(tun_name="tun0"):
    tun_fd = os.open("/dev/net/tun", os.O_RDWR)
    ifr = struct.pack('16sH', tun_name.encode('utf-8'), IFF_TUN | IFF_NO_PI)
    fcntl.ioctl(tun_fd, TUNSETIFF, ifr)
    print(f"[{tun_name}] Virtual network interface successfully created!")
    return tun_fd

if __name__ == "__main__":
    print("Starting the Secure VPN Tunnel...")
    fd = create_tun_interface()
    
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    DEST_IP = "127.0.0.1"
    DEST_PORT = 5555
    
    print(f"Listening for packets... Encrypting and forwarding to {DEST_IP}:{DEST_PORT} via UDP")
    
    try:
        while True:
            # 1. TUN'dan ham IP paketini oku
            packet = os.read(fd, 2048)
            
            # 2. Şifreleme için 12-byte rastgele bir Nonce (Number Used Once) üret
            # Bu, aynı paket iki kez gönderilse bile şifreli halinin farklı görünmesini sağlar
            nonce = os.urandom(12)
            
            # 3. Paketi AES-GCM ile şifrele
            encrypted_packet = aesgcm.encrypt(nonce, packet, None)
            
            # 4. Karşı tarafın şifreyi çözebilmesi için Nonce'u şifreli paketin başına ekle
            payload = nonce + encrypted_packet
            
            # Akademik Rapor için Önemli Çıktı: Veri Yükü (Overhead) Analizi
            print(f"[*] Raw IP Packet: {len(packet)} bytes | Encrypted Payload: {len(payload)} bytes (Overhead: {len(payload) - len(packet)} bytes)")
            
            # 5. Şifrelenmiş yepyeni veriyi UDP üzerinden fırlat
            udp_socket.sendto(payload, (DEST_IP, DEST_PORT))
            
    except KeyboardInterrupt:
        print("\nClosing the secure tunnel...")
        os.close(fd)
        udp_socket.close()
