"""
Post-Quantum Cryptography (PQC) TLS 1.3 Identifiers & OID Registries.
"""

# Active Probing: Hex IDs used in the 'Supported Groups' extension of ClientHello
PQC_GROUPS = {
    0x11ec: {"name": "X25519_MLKEM768", "status": "Quantum-Ready (NIST Standard)", "grade": "A"},
    0x11ed: {"name": "SecP384r1_MLKEM1024", "status": "Quantum-Ready (High Security)", "grade": "A+"},
    0x001d: {"name": "X25519", "status": "Vulnerable (Classical)", "grade": "B"},
    0x0017: {"name": "SecP256r1", "status": "Vulnerable (Classical)", "grade": "B"}
}

# Passive Probing: Certificate OID Registries (Sourced from canonical registries)
PQC_SIGNATURE_OIDS = {
    "2.16.840.1.101.3.4.3.17": "ML-DSA-44",  # NIST standardized Dilithium
    "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
    "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
    "1.3.9999.3.1": "Falcon-512",
    "1.3.9999.6.4.1": "SPHINCS+-SHA256-128f",
}

PQC_KEM_OIDS = {
    "2.16.840.1.101.3.4.4.1": "ML-KEM-512",  # NIST standardized Kyber
    "2.16.840.1.101.3.4.4.2": "ML-KEM-768",
    "2.16.840.1.101.3.4.4.3": "ML-KEM-1024",
    "1.3.9999.99.1": "X25519-Kyber512",
}

def get_group_info(group_id):
    return PQC_GROUPS.get(group_id, {
        "name": f"Unknown (0x{group_id:04x})",
        "status": "Untrusted/Unknown",
        "grade": "F"
    })
