"""Firmware Signing with PQC"""

import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from modules.module1_pqc_layer import MLDSA65
import hashlib

class FirmwareSigner:
    """Sign firmware packages with PQC."""
    
    def __init__(self):
        self.dsa = MLDSA65()
        self.signing_keypair = self.dsa.generate_keypair()
    
    def sign_firmware(self, firmware_data: bytes, version: str, ecu_id: str) -> dict:
        """Sign firmware package."""
        # Calculate hash
        fw_hash = hashlib.sha3_256(firmware_data).digest()
        
        # Create manifest
        manifest = f"FIRMWARE|{ecu_id}|{version}|{fw_hash.hex()}".encode()
        
        # Sign
        signature = self.dsa.sign(self.signing_keypair.secret_key, manifest)
        
        return {
            "firmware": firmware_data,
            "version": version,
            "ecu_id": ecu_id,
            "hash": fw_hash,
            "signature": signature.to_bytes(),
            "public_key": self.signing_keypair.public_key
        }
    
    def verify_firmware(self, package: dict) -> bool:
        """Verify firmware signature."""
        manifest = f"FIRMWARE|{package['ecu_id']}|{package['version']}|{package['hash'].hex()}".encode()
        from modules.module1_pqc_layer.mldsa import MLDSASignatureData
        sig_data = MLDSASignatureData(package['signature'], "ML-DSA-65", 0.0)
        return self.dsa.verify(package['public_key'], manifest, sig_data)
