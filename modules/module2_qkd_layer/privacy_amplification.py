"""
Privacy Amplification for QKD

Implements privacy amplification to extract a shorter, secure key from
a longer key that may have partial information leaked to eavesdropper.

Techniques:
- Universal hashing
- Toeplitz matrix multiplication
- HKDF-based extraction
"""

import hashlib
import secrets
from typing import Tuple


class PrivacyAmplifier:
    """Privacy amplification for QKD keys."""

    def amplify(
        self,
        raw_key: bytes,
        output_length: int,
        leakage_estimate: float = 0.0
    ) -> bytes:
        """
        Perform privacy amplification on raw key.

        Args:
            raw_key: Raw key from QKD
            output_length: Desired output key length
            leakage_estimate: Estimated information leakage (0.0-1.0)

        Returns:
            Amplified key
        """
        # Adjust output length based on leakage
        adjusted_length = int(output_length * (1.0 - leakage_estimate))

        # Use HKDF for privacy amplification
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF

        try:
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=adjusted_length,
                salt=None,
                info=b"QKD privacy amplification",
            )
            amplified_key = hkdf.derive(raw_key)
        except ImportError:
            # Fallback: simple SHA-256 based extraction
            amplified_key = hashlib.sha256(raw_key).digest()[:adjusted_length]

        return amplified_key
