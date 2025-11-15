"""
FIPS 140-3 Entropy Testing

Implements statistical tests for validating RNG quality.
Based on NIST SP 800-90B and FIPS 140-3 requirements.
"""

from collections import Counter
import math


class FIPSEntropyTester:
    """FIPS 140-3 entropy validation tests."""

    @staticmethod
    def frequency_test(data: bytes) -> bool:
        """
        Frequency (monobit) test.

        Tests if the number of ones and zeros is approximately equal.
        """
        bits = bin(int.from_bytes(data, 'big'))[2:].zfill(len(data) * 8)
        ones = bits.count('1')
        zeros = bits.count('0')

        # Chi-square test
        expected = len(bits) / 2
        chi_square = ((ones - expected) ** 2 + (zeros - expected) ** 2) / expected

        # Critical value for 1 degree of freedom at 0.01 significance
        return chi_square < 6.635

    @staticmethod
    def runs_test(data: bytes) -> bool:
        """
        Runs test.

        Tests for oscillation between ones and zeros.
        """
        bits = bin(int.from_bytes(data, 'big'))[2:].zfill(len(data) * 8)

        runs = 1
        for i in range(1, len(bits)):
            if bits[i] != bits[i - 1]:
                runs += 1

        n = len(bits)
        ones = bits.count('1')
        proportion = ones / n

        # Expected runs
        expected_runs = 2 * n * proportion * (1 - proportion) + 1

        # Standard deviation
        std_dev = 2 * math.sqrt(2 * n * proportion * (1 - proportion))

        # Check if runs is within acceptable range
        return abs(runs - expected_runs) < 3 * std_dev

    @staticmethod
    def validate(data: bytes) -> bool:
        """
        Run all FIPS validation tests.

        Args:
            data: Random data to test

        Returns:
            True if all tests pass
        """
        if len(data) < 20:  # Need minimum data
            return False

        return (
            FIPSEntropyTester.frequency_test(data) and
            FIPSEntropyTester.runs_test(data)
        )
