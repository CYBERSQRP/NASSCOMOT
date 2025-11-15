"""
Secure Random Number Generator

High-level interface for cryptographically secure random generation.
Integrates hardware RNG, entropy pool, and FIPS validation.
"""

from .entropy_pool import get_global_pool
from .fips_tests import FIPSEntropyTester


class SecureRandom:
    """
    Cryptographically secure random number generator.

    Provides validated, high-quality randomness for automotive crypto.
    """

    def __init__(self, validate_fips: bool = True):
        """
        Initialize secure random generator.

        Args:
            validate_fips: Enable FIPS validation of output
        """
        self.pool = get_global_pool()
        self.validate_fips = validate_fips

    def get_bytes(self, num_bytes: int) -> bytes:
        """
        Get cryptographically secure random bytes.

        Args:
            num_bytes: Number of bytes to generate

        Returns:
            Random bytes
        """
        data = self.pool.get_bytes(num_bytes)

        if self.validate_fips and num_bytes >= 20:
            if not FIPSEntropyTester.validate(data):
                # Re-generate if validation fails
                print("WARNING: FIPS validation failed, regenerating...")
                data = self.pool.get_bytes(num_bytes)

        return data

    def get_int(self, min_val: int, max_val: int) -> int:
        """Get random integer in range [min_val, max_val]."""
        import secrets
        return secrets.randbelow(max_val - min_val + 1) + min_val

    def get_float(self) -> float:
        """Get random float in range [0.0, 1.0)."""
        import secrets
        return secrets.randbelow(2**53) / (2**53)
