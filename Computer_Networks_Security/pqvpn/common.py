"""
common.py — PQ-VPN Ortak Yardımcılar
Sunucu ve istemci tarafından paylaşılan sabitler, TUN arayüzü oluşturma
ve AES-GCM şifreleme/deşifreleme yardımcıları.
"""

import os
import fcntl
import struct
import sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ── Ağ Portları ──────────────────────────────────────────────────────────────
HANDSHAKE_PORT = 4444   # TCP: Kyber512 el sıkışması için
TUNNEL_PORT    = 5555   # UDP: Şifreli veri paketi aktarımı için

# ── TUN Arayüzü Linux Sabitleri ───────────────────────────────────────────────
TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_NO_PI = 0x1000

# ── MTU ───────────────────────────────────────────────────────────────────────
MTU = 1500   # Maksimum iletim birimi (byte)


def create_tun_interface(tun_name: str = "tun0") -> int:
    """
    Linux TUN sanal ağ arayüzü oluşturur.
    Gereksinim: root / sudo yetkisi
    Döndürür: Açık dosya tanımlayıcısı (file descriptor)
    """
    try:
        tun_fd = os.open("/dev/net/tun", os.O_RDWR)
        ifr = struct.pack("16sH", tun_name.encode("utf-8"), IFF_TUN | IFF_NO_PI)
        fcntl.ioctl(tun_fd, TUNSETIFF, ifr)
        print(f"  [TUN] '{tun_name}' sanal arayüzü başarıyla açıldı (fd={tun_fd})")
        return tun_fd
    except PermissionError:
        print("[HATA] TUN arayüzü için root yetkisi gerekli. 'sudo python3' ile çalıştırın.")
        sys.exit(1)
    except Exception as exc:
        print(f"[HATA] TUN arayüzü oluşturulamadı: {exc}")
        sys.exit(1)


def encrypt_packet(aesgcm: AESGCM, plaintext: bytes) -> bytes:
    """
    Paketi AES-256-GCM ile şifreler.
    Çıktı formatı: [12 byte nonce] + [şifreli veri + 16 byte GCM etiketi]
    Overhead: 12 (nonce) + 16 (tag) = 28 byte  ← Hocaya kanıtlanacak overhead!
    """
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext


def decrypt_packet(aesgcm: AESGCM, payload: bytes) -> bytes:
    """
    AES-256-GCM ile deşifre eder.
    Giriş formatı: [12 byte nonce] + [şifreli veri + 16 byte GCM etiketi]
    """
    if len(payload) < 29:   # nonce(12) + min_ciphertext(1) + tag(16)
        raise ValueError(f"Payload çok kısa: {len(payload)} byte")
    nonce      = payload[:12]
    ciphertext = payload[12:]
    return aesgcm.decrypt(nonce, ciphertext, None)
