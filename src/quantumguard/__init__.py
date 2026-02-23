"""
QuantumGuard: PQC-Aware Vulnerability Scanner
An active auditing tool for Post-Quantum Cryptography (PQC) readiness in TLS 1.3 handshakes.

Developed for the Master's in Cybersecurity Engineering at Politecnico di Torino.
"""

__version__ = "0.1.0"
__author__ = "Alessio Flamini"

from .scanner import analyze_tls_handshake
from .tls_utils import (
    get_group_info, 
    PQC_GROUPS, 
    PQC_SIGNATURE_OIDS, 
    PQC_KEM_OIDS
)

__all__ = [
    "analyze_tls_handshake",
    "get_group_info",
    "PQC_GROUPS",
    "PQC_SIGNATURE_OIDS",
    "PQC_KEM_OIDS"
]