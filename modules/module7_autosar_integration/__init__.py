"""
Module 7: AUTOSAR Adaptive Integration Module

Integrates PQC with AUTOSAR Adaptive Platform.

Features:
- AUTOSAR Crypto Stack integration
- HSM/TPM 2.0 support
- Real-time performance optimization
- ASIL-D compliance validation

Standards: AUTOSAR Adaptive Platform, ISO 26262
"""

__version__ = "1.0.0"

from .autosar_crypto import AUTOSARCryptoStack
from .hsm_integration import HSMIntegration

__all__ = ["AUTOSARCryptoStack", "HSMIntegration"]
