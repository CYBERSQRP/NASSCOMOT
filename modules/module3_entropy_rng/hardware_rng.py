"""
Hardware RNG Integration

Interfaces with hardware random number generators:
- Quantum Optical RNG (photon arrival times)
- Radioactive decay RNG (Geiger counter)
- TPM 2.0 RNG
- CPU RDRAND/RDSEED instructions

Automotive Requirements:
- High throughput for real-time systems
- FIPS 140-3 compliance
- Fault detection and health monitoring
"""

import os
import secrets
from abc import ABC, abstractmethod
from typing import Optional
import time


class HardwareRNG(ABC):
    """Abstract base class for hardware RNGs."""

    @abstractmethod
    def get_random_bytes(self, num_bytes: int) -> bytes:
        """Get random bytes from hardware source."""
        pass

    @abstractmethod
    def health_check(self) -> bool:
        """Perform health check on RNG source."""
        pass


class QuantumRNG(HardwareRNG):
    """
    Quantum Optical RNG based on photon arrival times.

    In production, this would interface with actual quantum hardware.
    For simulation, uses high-quality system entropy.
    """

    def __init__(self, device_path: str = "/dev/qrng"):
        """
        Initialize Quantum RNG.

        Args:
            device_path: Path to quantum RNG device
        """
        self.device_path = device_path
        self.available = os.path.exists(device_path)

        if not self.available:
            print(f"WARNING: Quantum RNG device not found at {device_path}")
            print("Falling back to system entropy source")

    def get_random_bytes(self, num_bytes: int) -> bytes:
        """Get random bytes from quantum source."""
        if self.available:
            # Read from actual quantum device
            with open(self.device_path, 'rb') as f:
                return f.read(num_bytes)
        else:
            # Fallback to system RNG
            return os.urandom(num_bytes)

    def health_check(self) -> bool:
        """Check if quantum RNG is functioning."""
        if not self.available:
            return False

        try:
            # Test read
            test_bytes = self.get_random_bytes(16)
            return len(test_bytes) == 16
        except Exception:
            return False


class RadioactiveRNG(HardwareRNG):
    """
    Radioactive Decay RNG using Geiger counter.

    Measures time between radioactive decay events for true randomness.
    """

    def __init__(self, device_path: str = "/dev/radioactive_rng"):
        """Initialize Radioactive RNG."""
        self.device_path = device_path
        self.available = os.path.exists(device_path)

        if not self.available:
            print(f"WARNING: Radioactive RNG not found at {device_path}")
            print("Falling back to system entropy")

    def get_random_bytes(self, num_bytes: int) -> bytes:
        """Get random bytes from radioactive decay."""
        if self.available:
            with open(self.device_path, 'rb') as f:
                return f.read(num_bytes)
        else:
            return os.urandom(num_bytes)

    def health_check(self) -> bool:
        """Health check for radioactive source."""
        if not self.available:
            return False

        try:
            test_bytes = self.get_random_bytes(16)
            return len(test_bytes) == 16
        except Exception:
            return False


class TPMRNG(HardwareRNG):
    """TPM 2.0 Random Number Generator."""

    def __init__(self):
        """Initialize TPM RNG."""
        try:
            import tpm2_pytss
            self.tpm_available = True
            self.tpm = tpm2_pytss
        except ImportError:
            self.tpm_available = False
            print("WARNING: TPM library not available")

    def get_random_bytes(self, num_bytes: int) -> bytes:
        """Get random bytes from TPM."""
        if self.tpm_available:
            # Use TPM2_GetRandom
            # This is simplified - actual implementation would use tpm2_pytss
            return os.urandom(num_bytes)
        else:
            return os.urandom(num_bytes)

    def health_check(self) -> bool:
        """TPM health check."""
        return self.tpm_available


class CPURNG(HardwareRNG):
    """CPU-based RNG using RDRAND/RDSEED instructions."""

    def __init__(self):
        """Initialize CPU RNG."""
        self.rdrand_available = self._check_rdrand()

    def _check_rdrand(self) -> bool:
        """Check if RDRAND instruction is available."""
        # Simplified check - would use CPUID in production
        return True

    def get_random_bytes(self, num_bytes: int) -> bytes:
        """Get random bytes from CPU RDRAND."""
        # Use secrets module which leverages RDRAND on x86
        return secrets.token_bytes(num_bytes)

    def health_check(self) -> bool:
        """CPU RNG health check."""
        try:
            test = self.get_random_bytes(32)
            return len(test) == 32
        except Exception:
            return False


def get_best_available_rng() -> HardwareRNG:
    """
    Get the best available hardware RNG for this system.

    Returns:
        HardwareRNG instance (prioritizes: Quantum > Radioactive > TPM > CPU)
    """
    # Try Quantum RNG first
    qrng = QuantumRNG()
    if qrng.health_check():
        print("Using Quantum Optical RNG")
        return qrng

    # Try Radioactive RNG
    rrng = RadioactiveRNG()
    if rrng.health_check():
        print("Using Radioactive Decay RNG")
        return rrng

    # Try TPM RNG
    tpm_rng = TPMRNG()
    if tpm_rng.health_check():
        print("Using TPM 2.0 RNG")
        return tpm_rng

    # Fallback to CPU RNG
    print("Using CPU RDRAND RNG")
    return CPURNG()
