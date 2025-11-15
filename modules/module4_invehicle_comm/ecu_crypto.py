"""
ECU Cryptographic Manager

Manages cryptographic operations for ECU secure communication.
Integrates PQC algorithms for ECU-to-ECU encryption and authentication.
"""

import time
from typing import Dict, Optional, Tuple
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from modules.module1_pqc_layer import MLKEM768, MLDSA65


class ECUCryptoManager:
    """
    Manages cryptographic keys and sessions for ECUs.
    
    Features:
    - PQC key generation for ECUs
    - Session key establishment
    - Message encryption/authentication
    """
    
    def __init__(self, ecu_id: str):
        """Initialize ECU crypto manager."""
        self.ecu_id = ecu_id
        self.kem = MLKEM768()
        self.dsa = MLDSA65()
        
        # Generate ECU long-term keys
        self.signing_keypair = self.dsa.generate_keypair()
        self.kem_keypair = self.kem.generate_keypair()
        
        # Active sessions
        self.sessions: Dict[str, bytes] = {}
        
        print(f"ECU {ecu_id} initialized with PQC keys")
    
    def establish_session(self, peer_ecu_id: str, peer_public_key: bytes) -> bytes:
        """
        Establish secure session with another ECU.
        
        Args:
            peer_ecu_id: Peer ECU identifier
            peer_public_key: Peer's ML-KEM public key
        
        Returns:
            Session key
        """
        # Perform key encapsulation
        ciphertext, shared_secret = self.kem.encapsulate(peer_public_key)
        
        # Store session
        self.sessions[peer_ecu_id] = shared_secret
        
        print(f"ECU {self.ecu_id} established session with {peer_ecu_id}")
        
        return shared_secret
    
    def encrypt_message(self, peer_ecu_id: str, plaintext: bytes) -> bytes:
        """Encrypt message for peer ECU."""
        if peer_ecu_id not in self.sessions:
            raise ValueError(f"No session with {peer_ecu_id}")
        
        session_key = self.sessions[peer_ecu_id]
        
        # Simplified encryption (in production use AES-GCM)
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        import os
        
        nonce = os.urandom(12)
        aesgcm = AESGCM(session_key[:32])
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        
        return nonce + ciphertext
    
    def sign_message(self, message: bytes) -> bytes:
        """Sign message with ECU's signing key."""
        signature = self.dsa.sign(self.signing_keypair.secret_key, message)
        return signature.to_bytes()
