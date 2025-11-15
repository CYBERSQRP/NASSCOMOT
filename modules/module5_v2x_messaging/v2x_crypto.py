"""V2X Cryptographic Operations"""

import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from modules.module1_pqc_layer import MLDSA44, MLKEM768

class V2XCryptoManager:
    """Manages V2X cryptographic operations."""
    
    def __init__(self, vehicle_id: str):
        self.vehicle_id = vehicle_id
        self.dsa = MLDSA44()  # Level 2 for performance
        self.kem = MLKEM768()
        
        # Generate keys
        self.signing_keypair = self.dsa.generate_keypair()
        print(f"V2X crypto initialized for vehicle: {vehicle_id}")
    
    def sign_v2x_message(self, message: bytes) -> bytes:
        """Sign V2X message."""
        signature = self.dsa.sign(self.signing_keypair.secret_key, message)
        return signature.to_bytes()
    
    def verify_v2x_message(self, message: bytes, signature: bytes, sender_pk: bytes) -> bool:
        """Verify V2X message signature."""
        from modules.module1_pqc_layer.mldsa import MLDSASignatureData
        sig_data = MLDSASignatureData(signature, "ML-DSA-44", 0.0)
        return self.dsa.verify(sender_pk, message, sig_data)
