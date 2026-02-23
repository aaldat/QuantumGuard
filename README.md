# QuantumGuard: PQC-Aware Vulnerability Scanner

A command-line auditing tool designed to evaluate the **Quantum Readiness** of network endpoints. This tool actively probes servers for Post-Quantum Cryptography (PQC) support based on the finalized NIST FIPS 203 standards. 

**QuantumGuard** utilizes **Active Protocol Exploitation**:
1. Uses `scapy` to craft a raw, byte-level TLS 1.3 `ClientHello`.
2. Advertises support for NIST-standardized PQC NamedGroups (e.g., `0x11ec` for ML-KEM-768).
3. Intentionally provides only a classical key share (X25519) in the payload.
4. Analyzes the response to see if the server explicitly issues a `HelloRetryRequest` (HRR) demanding a Post-Quantum Key Share, providing definitive cryptographic proof of Crypto-Agility.

To handle strict CDNs and fragmented records (like Cloudflare or Akamai), QuantumGuard implements a highly resilient dual-parsing architecture:
* **Standard Dissection:** Uses `scapy` for clean TLS layer parsing and TLS Alert catching (e.g., catching Alert 70 for Protocol Downgrades).
* **Deep Byte Inspection (DBI):** A fallback mechanism that scans the raw binary stream for HRR Magic Bytes and Extension `51` (Key Share) IDs if proprietary CDN extensions break standard parsers.

The scanner grades endpoints based on their vulnerability to specific quantum and classical threat models:

| Grade | Scenario | Threat Model | Verdict |
| :--- | :--- | :--- | :--- |
| **A / A+** | Server negotiates Hybrid Key Exchange (`0x11ec`, `0x11ed`). | Quantum-Safe | **PASS:** Prepared for Y2Q (Year to Quantum). |
| **B** | Server enforces TLS 1.3 but falls back to Classical (`0x001d`). | **Store-Now-Decrypt-Later (SNDL)** | **WARNING:** Secure today, but intercepted traffic can be decrypted by future CRQCs. |
| **F** | Server rejects TLS 1.3 (Alert 70) or fails handshake (Alert 40). | Classical Protocol Downgrade | **CRITICAL:** Vulnerable to current classical attacks and future quantum impersonation. |

## Installation
```bash
# Install dependencies (Scapy, Cryptography, Rich, Typer)
pip install -r requirements.txt
```

## Usage
```bash
python main.py <domain_or_IP_address>
```
