"""
Module 2: Quantum Key Distribution (QKD) Simulation Layer

This module provides quantum-grade key distribution simulation using Qiskit.
Implements BB84, E91, and BBM92 protocols for secure key generation.

Components:
- BB84 Protocol (Bennett-Brassard 1984)
- E91 Protocol (Ekert 1991)
- BBM92 Protocol (Bennett-Brassard-Mermin 1992)
- Key distillation and privacy amplification
- Integration with PQC-TLS sessions

Compliance: ISO/SAE 21434, Quantum-safe key management
"""

__version__ = "1.0.0"
__author__ = "LTTS Quantum Security Team"

from .bb84 import BB84Protocol, BB84KeyPair
from .e91 import E91Protocol, E91KeyPair
from .qkd_manager import QKDManager, QKDSession
from .privacy_amplification import PrivacyAmplifier
from .utils import QuantumChannel, measure_qber

__all__ = [
    "BB84Protocol",
    "BB84KeyPair",
    "E91Protocol",
    "E91KeyPair",
    "QKDManager",
    "QKDSession",
    "PrivacyAmplifier",
    "QuantumChannel",
    "measure_qber",
]
