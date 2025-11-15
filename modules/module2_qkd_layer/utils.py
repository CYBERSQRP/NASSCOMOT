"""
QKD Utility Functions

Helper functions for QKD simulation and analysis.
"""

from typing import List
import secrets


class QuantumChannel:
    """Simulates a quantum channel with optional noise."""

    def __init__(self, error_rate: float = 0.05):
        """
        Initialize quantum channel.

        Args:
            error_rate: Bit error rate (0.0 - 1.0)
        """
        self.error_rate = error_rate

    def transmit(self, qubit_state: int) -> int:
        """
        Transmit a qubit through the channel.

        Args:
            qubit_state: Input qubit state (0 or 1)

        Returns:
            Output qubit state (may be flipped due to noise)
        """
        if secrets.randbelow(1000) < int(self.error_rate * 1000):
            return 1 - qubit_state  # Bit flip
        return qubit_state


def measure_qber(alice_bits: List[int], bob_bits: List[int]) -> float:
    """
    Measure Quantum Bit Error Rate.

    Args:
        alice_bits: Alice's bit string
        bob_bits: Bob's bit string

    Returns:
        QBER (0.0 - 1.0)
    """
    if len(alice_bits) != len(bob_bits):
        raise ValueError("Bit strings must have equal length")

    if len(alice_bits) == 0:
        return 0.0

    errors = sum(1 for a, b in zip(alice_bits, bob_bits) if a != b)
    return errors / len(alice_bits)
