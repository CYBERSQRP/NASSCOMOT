"""
Module 4: In-Vehicle Secure Communication Module

PQC-secured ECU-to-ECU communication across automotive networks:
- CAN, CAN-FD
- Automotive Ethernet
- SOME/IP-SD
- FlexRay

Components:
- PQC key exchange for ECU pairs
- Encrypted message frames
- VLAN-based network segmentation
- Legacy ECU fallback support

Compliance: ISO/SAE 21434, AUTOSAR Adaptive Platform
"""

__version__ = "1.0.0"

from .ecu_crypto import ECUCryptoManager
from .can_security import (
    SecureCANBus,
    CANSecureFrame,
    CANSecurityLevel,
    setup_ecu_can_network,
)
from .someip_security import SecureSOMEIP
from .ethernet_security import AutomotiveEthernetSecurity

__all__ = [
    "ECUCryptoManager",
    "SecureCANBus",
    "CANSecureFrame",
    "CANSecurityLevel",
    "setup_ecu_can_network",
    "SecureSOMEIP",
    "AutomotiveEthernetSecurity",
]
