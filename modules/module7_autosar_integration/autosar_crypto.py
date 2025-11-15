"""AUTOSAR Crypto Stack Integration"""

import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from modules.module1_pqc_layer import MLKEM768, MLDSA65

class AUTOSARCryptoStack:
    """
    AUTOSAR Adaptive Crypto Stack with PQC.
    
    Provides standardized crypto interface for AUTOSAR applications.
    """
    
    def __init__(self):
        self.kem = MLKEM768()
        self.dsa = MLDSA65()
        print("AUTOSAR Crypto Stack initialized with PQC support")
    
    def crypto_key_exchange(self, peer_public_key: bytes) -> bytes:
        """AUTOSAR key exchange using ML-KEM."""
        ciphertext, shared_secret = self.kem.encapsulate(peer_public_key)
        return shared_secret
    
    def crypto_signature_generate(self, data: bytes, private_key: bytes) -> bytes:
        """Generate signature using ML-DSA."""
        signature = self.dsa.sign(private_key, data)
        return signature.to_bytes()
    
    def crypto_signature_verify(self, data: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify signature."""
        from modules.module1_pqc_layer.mldsa import MLDSASignatureData
        sig_data = MLDSASignatureData(signature, "ML-DSA-65", 0.0)
        return self.dsa.verify(public_key, data, sig_data)
