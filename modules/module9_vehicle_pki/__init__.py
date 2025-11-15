"""
Module 9: Quantum-Safe Vehicle PKI (Optional)

PQC-based Public Key Infrastructure for vehicles.

Features:
- PQC certificates for ECUs
- VIN-based identity management
- Certificate lifecycle management
- Revocation handling

Standards: X.509 with PQC extensions, UNECE R155
"""

__version__ = "1.0.0"

from .pqc_certificates import PQCCertificateAuthority
from .vin_identity import VINIdentityManager

__all__ = ["PQCCertificateAuthority", "VINIdentityManager"]
