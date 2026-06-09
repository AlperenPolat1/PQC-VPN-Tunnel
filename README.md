# PQC-VPN-Tunnel: Custom Post-Quantum VPN Architecture
*(Scroll down for the Turkish version / Türkçe versiyon için aşağı kaydırın)*

This repository contains the proof-of-concept (PoC) implementation for a custom, OS-level Virtual Private Network (VPN) tunnel. Developed as a final research project, this architecture transitions from classical symmetric encryption to Post-Quantum Cryptography (PQC) standards to secure network traffic against future quantum computing threats.

**Developer:** Alperen Polat

---

## English Version: Project Milestones

### Phase 1: Clear-text TUN Interface
* Created a virtual network interface (`tun0`) operating at Layer 3 (IP Layer) using Python's `fcntl` and `struct` modules.
* Implemented low-level OS routing to capture raw IP packets and forward them via standard UDP sockets without wrapper APIs.

### Phase 2: Symmetric Encryption (Data Confidentiality)
* Integrated AES-256-GCM via the `cryptography` library.
* Network Overhead Analysis: Observed exactly 28 bytes of overhead per packet (12-byte Nonce + 16-byte GCM Authentication Tag).

### Phase 3: Post-Quantum Key Exchange (ML-KEM) - [COMPLETED]
* Replaced static AES keys with a dynamic, quantum-resistant key encapsulation mechanism.
* Integrated CRYSTALS-Kyber (NIST FIPS 203 ML-KEM) using a pure Python implementation (`kyber-py`).
* Both ends now successfully establish a 32-byte quantum-resistant shared secret during the handshake, which is then used as the session key for AES-GCM encryption.

## How to Run (For Testing)

1. **Start the Secure Tunnel (Server/Client Handshake):**
```bash
sudo ./vpn_env/bin/python3 vpn_tun.py
sudo ip addr add 10.0.0.1/24 dev tun0
sudo ip link set dev tun0 up
ping 10.0.0.1
Observe the real-time encryption process and overhead calculation in the main terminal logs.
```

-----TR-------
Türkçe Versiyon: Proje Aşamaları
Bu depo, işletim sistemi seviyesinde (OS-level) çalışan özel bir Sanal Özel Ağ (VPN) tünelinin kavram kanıtı (PoC) uygulamasını içermektedir. Bir araştırma projesi olarak geliştirilen bu mimari, ağ trafiğini gelecekteki kuantum bilgisayar tehditlerine karşı korumak amacıyla klasik şifreleme yöntemlerinden Post-Kuantum Kriptografi (PQC) standartlarına geçiş yapmaktadır.

Aşama 1: Şifresiz TUN Arayüzü
Python'ın fcntl modülleri kullanılarak Katman 3'te (IP Katmanı) çalışan sanal bir ağ arayüzü (tun0) oluşturuldu.

İşletim sistemi seviyesinde yönlendirme yapılarak, ham IP paketleri yakalandı ve UDP soketleri üzerinden iletildi.

Aşama 2: Simetrik Şifreleme (Veri Gizliliği)
cryptography kütüphanesi kullanılarak sisteme AES-256-GCM entegre edildi.

Ağ Yükü (Overhead) Analizi: Her paket başına tam olarak 28 byte şifreleme yükü (12-byte Nonce + 16-byte GCM Doğrulama Etiketi) eklendiği gözlemlendi ve loglandı.

Aşama 3: Post-Kuantum Anahtar Değişimi (ML-KEM) - [TAMAMLANDI]
Statik AES anahtarları, dinamik ve kuantum-dirençli bir anahtar kapsülleme mekanizmasıyla (KEM) değiştirildi.

Saf Python uyarlaması kullanılarak sisteme CRYSTALS-Kyber (NIST FIPS 203 ML-KEM) standardı entegre edildi.

Bağlantı anında (handshake), tünelin iki ucu da kuantum saldırılarına dayanıklı 32-byte'lık ortak bir sır (shared secret) üretir ve bu sırrı AES-GCM oturum anahtarı olarak kullanır.

Nasıl Çalıştırılır (Test İçin)
Güvenli Tüneli Başlatın (Kuantum El Sıkışma):
sudo ./vpn_env/bin/python3 vpn_tun.py
sudo ip addr add 10.0.0.1/24 dev tun0
sudo ip link set dev tun0 up
ping 10.0.0.1
Şifrelenen paketlerin akışını ve overhead boyutlarını ana terminal ekranından anlık olarak izleyebilirsiniz.

