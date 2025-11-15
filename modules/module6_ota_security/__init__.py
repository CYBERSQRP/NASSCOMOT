"""
Module 6: OTA Update Security & Telemetry Protection

Secure firmware updates and telemetry transmission using PQC.

Features:
- PQC-signed firmware packages
- Secure OTA distribution
- Anti-rollback protection
- PQ-TLS tunnels to cloud
- Encrypted telemetry

Compliance: ISO 21434 Section 5, UNECE R156
"""

__version__ = "1.0.0"

from .firmware_signer import FirmwareSigner
from .ota_manager import OTAManager
from .telemetry_security import TelemetrySecurity

__all__ = ["FirmwareSigner", "OTAManager", "TelemetrySecurity"]
