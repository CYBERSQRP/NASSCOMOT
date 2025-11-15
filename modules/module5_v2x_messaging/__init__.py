"""
Module 5: V2X Quantum-Secure Messaging Module

Quantum-safe V2X communication for:
- Vehicle-to-Vehicle (V2V)
- Vehicle-to-Infrastructure (V2I)
- Vehicle-to-Pedestrian (V2P)
- Vehicle-to-Network (V2N)

Protocols:
- DSRC/ITS-G5 with PQC signatures
- 5G C-V2X with PQ-TLS
- OTA updates for RSUs

Compliance: UNECE R155, IEEE 1609.2, ETSI ITS
"""

__version__ = "1.0.0"

from .v2x_crypto import V2XCryptoManager
from .dsrc_security import SecureDSRC
from .cv2x_security import SecureCV2X

__all__ = ["V2XCryptoManager", "SecureDSRC", "SecureCV2X"]
