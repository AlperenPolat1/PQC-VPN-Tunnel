<div align="center">

# 🔐 PQC-VPN-Tunnel

### Post-Quantum Cryptography Layer-3 VPN Tunnel
### Kuantum Sonrası Kriptografi ile Katman-3 VPN Tüneli

**CENG3544 – Computer Networks and Security**
Marmara University · Computer Engineering

---

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Security](https://img.shields.io/badge/ML--KEM-Kyber512-6B48FF?style=for-the-badge&logo=shield&logoColor=white)](https://csrc.nist.gov/pubs/fips/203/final)
[![Encryption](https://img.shields.io/badge/AES--256--GCM-Encryption-00B894?style=for-the-badge&logo=lock&logoColor=white)](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)
[![NIST](https://img.shields.io/badge/NIST-FIPS%20203-blue?style=for-the-badge)](https://csrc.nist.gov/pubs/fips/203/final)
[![Platform](https://img.shields.io/badge/WSL2-Ubuntu%2024.04-E95420?style=for-the-badge&logo=ubuntu&logoColor=white)](https://ubuntu.com)

---

**Authors · Yazarlar**

| Name | Email | University |
|------|-------|------------|
| Mustafa Aydın | mustafaa@posta.mu.edu.tr | Mugla Sıtkı Kocman University |
| Alperen Polat | alperenpolat@posta.mu.edu.tr | Mugla Sıtkı Kocman University |

</div>

---

## 🌐 Language / Dil

- [🇺🇸 English](#-english)
- [🇹🇷 Türkçe](#-türkçe)

---

# 🇺🇸 English

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [File Structure](#file-structure)
4. [Requirements](#requirements)
5. [Setup & Installation](#setup--installation)
6. [Running the VPN](#running-the-vpn)
7. [Benchmarks & Results](#benchmarks--results)
8. [Security Analysis](#security-analysis)

---

## Overview

This project implements a **Layer-3 VPN tunnel** that uses **post-quantum cryptography** for key establishment, making it resistant to attacks from future quantum computers.

- **Key Encapsulation:** Kyber512 (ML-KEM, NIST FIPS 203) — lattice-based, quantum-resistant
- **Data Encryption:** AES-256-GCM — authenticated symmetric encryption
- **Transport Layer:** Linux TUN virtual network interfaces + UDP
- **Handshake Layer:** TCP (port 4444) for KEM exchange
- **Platform:** Windows 11 + WSL2 (Ubuntu 24.04, mirrored networking)

> **Why post-quantum?** Shor's algorithm can break RSA and ECC on a quantum computer in polynomial time. The *harvest-now-decrypt-later* threat — recording encrypted traffic today to decrypt it once quantum computers mature — motivates immediate migration.

---

## Architecture

```
┌─────────────────────────────────┐        ┌─────────────────────────────────┐
│         SERVER (Mustafa)        │        │         CLIENT (Alperen)        │
│       172.21.195.229            │        │       172.21.196.43             │
│                                 │        │                                 │
│  1. Kyber512.keygen()           │        │                                 │
│     → pk, sk                   │        │                                 │
│  2. Send pk ──────────────────────────► │                                 │
│                                 │        │  3. Kyber512.encaps(pk)         │
│                                 │        │     → shared_secret, ct         │
│  4. Kyber512.decaps(sk, ct)  ◄────────── │  5. Send ct                     │
│     → shared_secret             │        │                                 │
│                                 │        │                                 │
│  6. AESGCM(shared_secret)       │        │  6. AESGCM(shared_secret)       │
│     TUN: 10.0.0.1/24            │◄──────►│     TUN: 10.0.0.2/24            │
│     UDP port 5555               │        │     UDP port 5555               │
└─────────────────────────────────┘        └─────────────────────────────────┘
                    TCP port 4444 (handshake only)
```

### Data Flow per Packet

```
[IP Packet] → AES-256-GCM Encrypt → [12B Nonce | Ciphertext | 16B GCM Tag] → UDP → Network
```

---

## File Structure

```
PQC-VPN-Tunnel/
├── Computer_Networks_Security/
│   ├── pqvpn/
│   │   ├── common.py               # Shared crypto helpers, TUN management, AES-GCM wrappers
│   │   ├── server.py               # PQ-VPN Server (Kyber512 keygen + UDP tunnel)
│   │   ├── client.py               # PQ-VPN Client (Kyber512 encaps + UDP tunnel)
│   │   ├── classic_server.py       # Classical VPN Server (RSA-2048 for comparison)
│   │   ├── classic_client.py       # Classical VPN Client (RSA-2048 for comparison)
│   │   ├── benchmark.py            # Handshake timing benchmarks (Kyber vs RSA)
│   │   ├── cpu_analysis.py         # Real-time CPU load analysis during tunnel operation
│   │   ├── compare.py              # Side-by-side PQ vs Classic comparison tool
│   │   ├── plain_udp_test.py       # Baseline UDP throughput test (no encryption)
│   │   ├── setup_wsl.sh            # WSL2 TUN interface & routing setup script
│   │   ├── test_tunnel.sh          # End-to-end tunnel connectivity test
│   │   ├── fix_network.ps1         # Windows-side network fix utility
│   │   ├── benchmark_report.txt    # Raw benchmark output
│   │   ├── comparison_report.txt   # PQ vs Classic comparison report
│   │   └── cpu_analysis_report.txt # CPU utilization report
│   └── pqvpn_report.tex            # IEEE-format academic paper (LaTeX source)
└── README.md
```

---

## Requirements

### Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `kyber-py` | ≥ 1.2.0 | Kyber512 (ML-KEM) implementation |
| `cryptography` | ≥ 46.0.5 | AES-256-GCM (via `cryptography.hazmat`) |
| `psutil` | ≥ 5.9.0 | CPU & memory monitoring |

### System Requirements

| Component | Requirement |
|-----------|-------------|
| OS | Windows 11 + WSL2 (Ubuntu 24.04) or native Linux |
| WSL2 Network Mode | `mirrored` (set in `.wslconfig`) |
| Python | 3.10 or higher |
| Privileges | `sudo` (required for TUN interface creation) |
| Ports | TCP 4444 (handshake), UDP 5555 (tunnel data) |

---

## Setup & Installation

### 1. WSL2 Network Configuration

Add to `C:\Users\<YourName>\.wslconfig`:
```ini
[wsl2]
networkingMode=mirrored
```

Restart WSL2:
```powershell
wsl --shutdown
```

### 2. Install Python Dependencies (in WSL2)

```bash
pip install kyber-py cryptography psutil
```

### 3. Configure TUN Interface

```bash
chmod +x pqvpn/setup_wsl.sh
sudo bash pqvpn/setup_wsl.sh
```

This script creates the TUN interface and sets up routing.

---

## Running the VPN

### Post-Quantum VPN (Kyber512 + AES-256-GCM)

**On the Server machine:**
```bash
sudo python3 pqvpn/server.py
```

**On the Client machine:**
```bash
sudo python3 pqvpn/client.py <SERVER_IP>
```

### Classical VPN (RSA-2048 + AES-256-GCM) — Comparison Baseline

**On the Server machine:**
```bash
sudo python3 pqvpn/classic_server.py
```

**On the Client machine:**
```bash
sudo python3 pqvpn/classic_client.py <SERVER_IP>
```

### Run Benchmarks

```bash
python3 pqvpn/benchmark.py
python3 pqvpn/cpu_analysis.py
python3 pqvpn/compare.py
```

---

## Benchmarks & Results

### Handshake Performance

| Operation | Avg (ms) | Min (ms) | Max (ms) |
|-----------|----------|----------|----------|
| Kyber512 keygen | 1.30 | 1.07 | 4.07 |
| **Kyber512 full exchange** | **5.18** | **4.82** | **6.62** |
| RSA-2048 keygen | 35.02 | 8.54 | 102.11 |
| **RSA-2048 full exchange** | **36.19** | **10.94** | **80.58** |

> 🚀 **Kyber512 is ~7x faster** than RSA-2048 in controlled benchmarks, and **16.8x faster** in live two-machine deployment (3.90 ms vs 65.53 ms).

### Cryptographic Object Sizes

| Object | Kyber512 | RSA-2048 |
|--------|----------|----------|
| Public Key | 800 bytes | 294 bytes |
| Private Key | 1,632 bytes | 1,218 bytes |
| Ciphertext / Enc. Session Key | 768 bytes | 256 bytes |
| Shared Secret | 32 bytes | 32 bytes |

> Kyber512's larger public key is a one-time cost sent only during handshake — it has **zero effect** on per-packet performance.

### Packet Overhead (AES-256-GCM)

| Plaintext (B) | Ciphertext (B) | Overhead (B) | Overhead (%) |
|---------------|----------------|--------------|--------------|
| 64 | 92 | 28 | 43.8% |
| 84 | 112 | 28 | 33.3% |
| 256 | 284 | 28 | 10.9% |
| 512 | 540 | 28 | 5.5% |
| 1024 | 1052 | 28 | 2.7% |
| 1500 | 1528 | 28 | 1.9% |

The 28-byte overhead is **constant and mathematical**:

```
Overhead = 12 bytes (GCM nonce) + 16 bytes (GCM authentication tag) = 28 bytes
```

### AES-256-GCM Encryption Throughput

| Packet Size (B) | Avg Latency (ms) | Throughput (MB/s) |
|-----------------|------------------|-------------------|
| 64 | 0.0010 | 64.0 |
| 256 | 0.0010 | 256.0 |
| 512 | 0.0010 | 512.0 |
| 1024 | 0.0010 | 1024.0 |
| 1500 | 0.0010 | 1500.0 |

### CPU Utilization During Tunnel Operation

| Configuration | CPU During Handshake | CPU During Data Transfer (20 Mbps) |
|---------------|---------------------|--------------------------------------|
| PQ-VPN (Kyber512) | ~2% | < 5% |
| Classic VPN (RSA-2048) | ~8% | < 5% |

> Both configurations show **statistically identical CPU usage during data transfer**. The difference is limited to the one-time handshake phase.

---

## Security Analysis

| Attack Scenario | RSA-2048 VPN | PQ-VPN (Kyber512) |
|-----------------|:------------:|:-----------------:|
| Classical brute force | ✅ Secure | ✅ Secure |
| Shor's algorithm (quantum) | ❌ Broken | ✅ Secure |
| Grover's algorithm (quantum) | ⚠️ Weakened | ✅ Secure |
| Man-in-the-Middle | ✅ Secure | ✅ Secure |
| Harvest-now-decrypt-later | ❌ Broken | ✅ Secure |

### Standards Compliance

| Standard | Description | Status |
|----------|-------------|--------|
| NIST FIPS 203 | ML-KEM (Kyber) Key Encapsulation | ✅ Implemented |
| NIST SP 800-38D | AES-GCM Authenticated Encryption | ✅ Implemented |
| RFC 4303 | IP Encapsulating Security Payload concepts | ✅ Aligned |

---

---

# 🇹🇷 Türkçe

## İçindekiler

1. [Genel Bakış](#genel-bakış)
2. [Mimari](#mimari)
3. [Dosya Yapısı](#dosya-yapısı)
4. [Gereksinimler](#gereksinimler)
5. [Kurulum](#kurulum)
6. [VPN'i Çalıştırma](#vpni-çalıştırma)
7. [Benchmark ve Sonuçlar](#benchmark-ve-sonuçlar)
8. [Güvenlik Analizi](#güvenlik-analizi)

---

## Genel Bakış

Bu proje, anahtar oluşturma aşamasında **kuantum sonrası kriptografi** kullanan bir **Katman-3 VPN tüneli** implemente etmektedir. Sistem, gelecekteki kuantum bilgisayar saldırılarına karşı dirençli hale getirilmiştir.

- **Anahtar Kapsülleme:** Kyber512 (ML-KEM, NIST FIPS 203) — kafes tabanlı, kuantum dirençli
- **Veri Şifreleme:** AES-256-GCM — kimlik doğrulamalı simetrik şifreleme
- **Taşıma Katmanı:** Linux TUN sanal ağ arayüzleri + UDP
- **El Sıkışma Katmanı:** TCP (port 4444) — KEM değişimi için
- **Platform:** Windows 11 + WSL2 (Ubuntu 24.04, mirrored networking modu)

> **Neden kuantum sonrası?** Shor algoritması, bir kuantum bilgisayarda RSA ve ECC'yi polinom zamanda kırabilir. *Şimdi topla, sonra şifre çöz* tehdidi — bugün şifreli trafiği kaydedip kuantum bilgisayarlar olgunlaşınca çözme — anlık geçişi zorunlu kılmaktadır.

---

## Mimari

```
┌─────────────────────────────────┐        ┌─────────────────────────────────┐
│      SUNUCU (Mustafa)           │        │      İSTEMCİ (Alperen)          │
│       172.21.195.229            │        │       172.21.196.43             │
│                                 │        │                                 │
│  1. Kyber512.keygen()           │        │                                 │
│     → pk (açık anahtar),        │        │                                 │
│       sk (gizli anahtar)        │        │                                 │
│  2. pk gönder ───────────────────────── ►│                                 │
│                                 │        │  3. Kyber512.encaps(pk)         │
│                                 │        │     → ortak_sır, şifreli_metin  │
│  4. Kyber512.decaps(sk, ct)  ◄────────── │  5. şifreli_metin gönder        │
│     → ortak_sır                 │        │                                 │
│                                 │        │                                 │
│  6. AESGCM(ortak_sır)           │        │  6. AESGCM(ortak_sır)           │
│     TUN: 10.0.0.1/24            │◄──────►│     TUN: 10.0.0.2/24            │
│     UDP port 5555               │        │     UDP port 5555               │
└─────────────────────────────────┘        └─────────────────────────────────┘
              TCP port 4444 (yalnızca el sıkışma)
```

### Paket Başına Veri Akışı

```
[IP Paketi] → AES-256-GCM Şifrele → [12B Nonce | Şifreli Metin | 16B GCM Tag] → UDP → Ağ
```

---

## Dosya Yapısı

```
PQC-VPN-Tunnel/
├── Computer_Networks_Security/
│   ├── pqvpn/
│   │   ├── common.py               # Ortak kripto yardımcıları, TUN yönetimi, AES-GCM sarmalayıcılar
│   │   ├── server.py               # PQ-VPN Sunucusu (Kyber512 keygen + UDP tüneli)
│   │   ├── client.py               # PQ-VPN İstemcisi (Kyber512 encaps + UDP tüneli)
│   │   ├── classic_server.py       # Klasik VPN Sunucusu (karşılaştırma için RSA-2048)
│   │   ├── classic_client.py       # Klasik VPN İstemcisi (karşılaştırma için RSA-2048)
│   │   ├── benchmark.py            # El sıkışma zamanlama benchmarkları (Kyber vs RSA)
│   │   ├── cpu_analysis.py         # Tünel çalışırken gerçek zamanlı CPU yük analizi
│   │   ├── compare.py              # PQ vs Klasik yan yana karşılaştırma aracı
│   │   ├── plain_udp_test.py       # Temel UDP verim testi (şifreleme yok)
│   │   ├── setup_wsl.sh            # WSL2 TUN arayüzü ve yönlendirme kurulum betiği
│   │   ├── test_tunnel.sh          # Uçtan uca tünel bağlantı testi
│   │   ├── fix_network.ps1         # Windows tarafı ağ düzeltme aracı
│   │   ├── benchmark_report.txt    # Ham benchmark çıktısı
│   │   ├── comparison_report.txt   # PQ vs Klasik karşılaştırma raporu
│   │   └── cpu_analysis_report.txt # CPU kullanım raporu
│   └── pqvpn_report.tex            # IEEE formatlı akademik makale (LaTeX kaynağı)
└── README.md
```

---

## Gereksinimler

### Python Kütüphaneleri

| Kütüphane | Sürüm | Amaç |
|-----------|-------|------|
| `kyber-py` | ≥ 1.2.0 | Kyber512 (ML-KEM) implementasyonu |
| `cryptography` | ≥ 46.0.5 | AES-256-GCM (`cryptography.hazmat` üzerinden) |
| `psutil` | ≥ 5.9.0 | CPU ve bellek izleme |

### Sistem Gereksinimleri

| Bileşen | Gereksinim |
|---------|------------|
| İşletim Sistemi | Windows 11 + WSL2 (Ubuntu 24.04) veya doğrudan Linux |
| WSL2 Ağ Modu | `mirrored` (`.wslconfig` dosyasında ayarlanır) |
| Python | 3.10 veya üzeri |
| Yetkiler | `sudo` (TUN arayüzü oluşturmak için gerekli) |
| Portlar | TCP 4444 (el sıkışma), UDP 5555 (tünel verisi) |

---

## Kurulum

### 1. WSL2 Ağ Yapılandırması

`C:\Users\<KullanıcıAdı>\.wslconfig` dosyasına ekleyin:
```ini
[wsl2]
networkingMode=mirrored
```

WSL2'yi yeniden başlatın:
```powershell
wsl --shutdown
```

### 2. Python Bağımlılıklarını Yükleme (WSL2 içinde)

```bash
pip install kyber-py cryptography psutil
```

### 3. TUN Arayüzünü Yapılandırma

```bash
chmod +x pqvpn/setup_wsl.sh
sudo bash pqvpn/setup_wsl.sh
```

Bu betik TUN arayüzünü oluşturur ve yönlendirmeyi ayarlar.

---

## VPN'i Çalıştırma

### Kuantum Sonrası VPN (Kyber512 + AES-256-GCM)

**Sunucu makinesinde:**
```bash
sudo python3 pqvpn/server.py
```

**İstemci makinesinde:**
```bash
sudo python3 pqvpn/client.py <SUNUCU_IP>
```

### Klasik VPN (RSA-2048 + AES-256-GCM) — Karşılaştırma Baz Çizgisi

**Sunucu makinesinde:**
```bash
sudo python3 pqvpn/classic_server.py
```

**İstemci makinesinde:**
```bash
sudo python3 pqvpn/classic_client.py <SUNUCU_IP>
```

### Benchmark Çalıştırma

```bash
python3 pqvpn/benchmark.py
python3 pqvpn/cpu_analysis.py
python3 pqvpn/compare.py
```

---

## Benchmark ve Sonuçlar

### El Sıkışma Performansı

| İşlem | Ortalama (ms) | Min (ms) | Maks (ms) |
|-------|---------------|----------|-----------|
| Kyber512 keygen | 1.30 | 1.07 | 4.07 |
| **Kyber512 tam değişim** | **5.18** | **4.82** | **6.62** |
| RSA-2048 keygen | 35.02 | 8.54 | 102.11 |
| **RSA-2048 tam değişim** | **36.19** | **10.94** | **80.58** |

> 🚀 **Kyber512, RSA-2048'den ~7x daha hızlıdır** (kontrollü benchmark); iki makine arasındaki canlı testte **16.8x daha hızlı** (3.90 ms vs 65.53 ms).

### Kriptografik Nesne Boyutları

| Nesne | Kyber512 | RSA-2048 |
|-------|----------|----------|
| Açık Anahtar | 800 bayt | 294 bayt |
| Gizli Anahtar | 1.632 bayt | 1.218 bayt |
| Şifreli Metin / Şifreli Oturum Anahtarı | 768 bayt | 256 bayt |
| Ortak Sır | 32 bayt | 32 bayt |

> Kyber512'nin daha büyük açık anahtarı yalnızca el sıkışma sırasında bir kez gönderilir — paket başına performansa **sıfır etkisi** vardır.

### Paket Ek Yükü (AES-256-GCM)

| Düz Metin (B) | Şifreli Metin (B) | Ek Yük (B) | Ek Yük (%) |
|---------------|-------------------|------------|------------|
| 64 | 92 | 28 | %43.8 |
| 84 | 112 | 28 | %33.3 |
| 256 | 284 | 28 | %10.9 |
| 512 | 540 | 28 | %5.5 |
| 1024 | 1052 | 28 | %2.7 |
| 1500 | 1528 | 28 | %1.9 |

28 baytlık ek yük **sabit ve matematikseldir**:

```
Ek Yük = 12 bayt (GCM nonce) + 16 bayt (GCM kimlik doğrulama etiketi) = 28 bayt
```

### AES-256-GCM Şifreleme Verimi

| Paket Boyutu (B) | Ortalama Gecikme (ms) | Verim (MB/s) |
|------------------|----------------------|--------------|
| 64 | 0.0010 | 64.0 |
| 256 | 0.0010 | 256.0 |
| 512 | 0.0010 | 512.0 |
| 1024 | 0.0010 | 1024.0 |
| 1500 | 0.0010 | 1500.0 |

### Tünel Çalışırken CPU Kullanımı

| Yapılandırma | El Sıkışma CPU | Veri Aktarımı CPU (20 Mbps) |
|--------------|----------------|------------------------------|
| PQ-VPN (Kyber512) | ~%2 | <%5 |
| Klasik VPN (RSA-2048) | ~%8 | <%5 |

> Her iki yapılandırma da veri aktarımı sırasında **istatistiksel olarak özdeş CPU kullanımı** göstermektedir. Fark yalnızca tek seferlik el sıkışma aşamasıyla sınırlıdır.

---

## Güvenlik Analizi

| Saldırı Senaryosu | RSA-2048 VPN | PQ-VPN (Kyber512) |
|-------------------|:------------:|:-----------------:|
| Klasik kaba kuvvet | ✅ Güvenli | ✅ Güvenli |
| Shor algoritması (kuantum) | ❌ Kırılmış | ✅ Güvenli |
| Grover algoritması (kuantum) | ⚠️ Zayıflamış | ✅ Güvenli |
| Ortadaki Adam Saldırısı | ✅ Güvenli | ✅ Güvenli |
| Şimdi topla, sonra şifre çöz | ❌ Kırılmış | ✅ Güvenli |

### Standart Uyumluluğu

| Standart | Açıklama | Durum |
|----------|----------|-------|
| NIST FIPS 203 | ML-KEM (Kyber) Anahtar Kapsülleme | ✅ Uygulandı |
| NIST SP 800-38D | AES-GCM Kimlik Doğrulamalı Şifreleme | ✅ Uygulandı |
| RFC 4303 | IP Güvenlik Yükü Kavramları | ✅ Uyumlu |

---

<div align="center">

---

### References · Kaynaklar

[NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) · [CRYSTALS-Kyber Spec](https://pq-crystals.org/kyber/) · [Shor 1997](https://doi.org/10.1137/S0097539795293172) · [NIST SP 800-38D](https://doi.org/10.6028/NIST.SP.800-38D)

---

*CENG3544 – Computer Networks and Security · Marmara University · June 2026*

</div>
