"""PQC Certificate Authority"""

import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from modules.module1_pqc_layer import MLDSA65
import time

class PQCCertificateAuthority:
    """Certificate Authority using PQC signatures."""
    
    def __init__(self, ca_name: str):
        self.ca_name = ca_name
        self.dsa = MLDSA65()
        self.ca_keypair = self.dsa.generate_keypair()
        print(f"CA initialized: {ca_name}")
    
    def issue_certificate(self, subject: str, public_key: bytes) -> dict:
        """Issue PQC certificate."""
        cert_data = {
            "subject": subject,
            "issuer": self.ca_name,
            "public_key": public_key,
            "not_before": time.time(),
            "not_after": time.time() + (365 * 24 * 3600),  # 1 year
            "serial": os.urandom(16).hex()
        }
        
        # Sign certificate
        cert_bytes = str(cert_data).encode()
        signature = self.dsa.sign(self.ca_keypair.secret_key, cert_bytes)
        cert_data["signature"] = signature.to_bytes()
        
        print(f"Issued certificate for: {subject}")
        return cert_data
    
    def verify_certificate(self, cert: dict) -> bool:
        """Verify certificate signature."""
        cert_copy = cert.copy()
        signature = cert_copy.pop("signature")
        cert_bytes = str(cert_copy).encode()
        
        from modules.module1_pqc_layer.mldsa import MLDSASignatureData
        sig_data = MLDSASignatureData(signature, "ML-DSA-65", 0.0)
        return self.dsa.verify(self.ca_keypair.public_key, cert_bytes, sig_data)
