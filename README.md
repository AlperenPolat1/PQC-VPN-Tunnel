 PQC-VPN-Tunnel: Custom Post-Quantum VPN Architecture

This repository contains the proof-of-concept (PoC) implementation for a custom, OS-level Virtual Private Network (VPN) tunnel. Developed as a final research project for the **Computer Networks Security** course,
this project aims to transition from classical symmetric encryption to Post-Quantum Cryptography (PQC) standards to secure network traffic against future quantum computing threats.

Current Progress: Phase 2 Completed

We are building this VPN architecture from scratch, directly interacting with the Linux kernel network stack. We do not use wrapper APIs for the core routing; instead, we manipulate raw IP packets.

 Phase 1: Clear-text TUN Interface
* Successfully created a virtual network interface (`tun0`) operating at Layer 3 (IP Layer) using Python's `fcntl` and `struct` modules.
* Implemented low-level OS routing to capture raw IP packets and forward them via standard UDP sockets with **0% packet loss**.

 Phase 2: Symmetric Encryption (Data Confidentiality)
* Integrated **AES-256-GCM** via the Python `cryptography` library.
* Replaced the clear-text UDP forwarding with an encrypted payload mechanism.
* **Network Overhead Analysis:** We observed and logged the exact cryptographic overhead. The AES-GCM implementation adds exactly **28 bytes** of overhead per packet (consisting of a 12-byte Nonce and
*  a 16-byte GCM Authentication Tag).

 Next Steps: Phase 3 (Post-Quantum Integration)
Our upcoming milestone is to replace the static AES key with a dynamic, quantum-resistant key exchange mechanism.
* **Dynamic Key Exchange:** Implement **CRYSTALS-Kyber (ML-KEM)** using the `liboqs-python` library for a secure handshake protocol between two endpoints.
* **Latency & Performance Benchmarking:** Analyze the handshake latency and packet overhead of our PQC-VPN, and prepare an academic comparison against standard protocols (like OpenVPN/WireGuard).

 How to Run (For Testing)

1. **Prerequisites:** Ensure you are on a Linux environment (Ubuntu/WSL) and have the necessary libraries installed.
```bash
sudo apt update
sudo apt install python3-cryptography
