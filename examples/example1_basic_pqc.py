#!/usr/bin/env python3
"""
Example 1: Basic PQC Operations

Demonstrates basic post-quantum cryptography operations:
- Key generation
- Key encapsulation (ML-KEM)
- Digital signatures (ML-DSA)
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from modules.module1_pqc_layer import MLKEM768, MLDSA65


def example_key_exchange():
    """Example: ML-KEM key exchange."""
    print("=" * 60)
    print("Example: ML-KEM Key Exchange")
    print("=" * 60)

    # Initialize ML-KEM
    kem = MLKEM768()

    # Alice generates keypair
    print("\n1. Alice generates ML-KEM-768 keypair...")
    alice_keypair = kem.generate_keypair()
    print(f"   Public key size: {len(alice_keypair.public_key)} bytes")
    print(f"   Secret key size: {len(alice_keypair.secret_key)} bytes")

    # Bob encapsulates to Alice's public key
    print("\n2. Bob encapsulates shared secret...")
    ciphertext, bob_shared_secret = kem.encapsulate(alice_keypair.public_key)
    print(f"   Ciphertext size: {len(ciphertext)} bytes")
    print(f"   Shared secret size: {len(bob_shared_secret)} bytes")

    # Alice decapsulates
    print("\n3. Alice decapsulates to recover shared secret...")
    alice_shared_secret = kem.decapsulate(alice_keypair.secret_key, ciphertext)

    # Verify both parties have same shared secret
    if alice_shared_secret == bob_shared_secret:
        print("   ✓ SUCCESS: Both parties have identical shared secret!")
    else:
        print("   ✗ FAILED: Shared secrets don't match!")

    return alice_shared_secret == bob_shared_secret


def example_digital_signature():
    """Example: ML-DSA digital signature."""
    print("\n" + "=" * 60)
    print("Example: ML-DSA Digital Signature")
    print("=" * 60)

    # Initialize ML-DSA
    dsa = MLDSA65()

    # Generate signing keypair
    print("\n1. Generating ML-DSA-65 signing keypair...")
    keypair = dsa.generate_keypair()
    print(f"   Public key size: {len(keypair.public_key)} bytes")
    print(f"   Secret key size: {len(keypair.secret_key)} bytes")

    # Sign a message
    message = b"ECU Firmware v1.2.3 - Critical Safety Update"
    print(f"\n2. Signing message: {message.decode()}")
    signature = dsa.sign(keypair.secret_key, message)
    print(f"   Signature size: {len(signature)} bytes")

    # Verify signature
    print("\n3. Verifying signature...")
    is_valid = dsa.verify(keypair.public_key, message, signature)

    if is_valid:
        print("   ✓ SUCCESS: Signature is valid!")
    else:
        print("   ✗ FAILED: Signature verification failed!")

    # Try tampering
    print("\n4. Testing tampering detection...")
    tampered_message = b"ECU Firmware v1.2.3 - MALICIOUS UPDATE"
    is_valid_tampered = dsa.verify(keypair.public_key, tampered_message, signature)

    if not is_valid_tampered:
        print("   ✓ SUCCESS: Tampering detected!")
    else:
        print("   ✗ FAILED: Tampering not detected!")

    return is_valid and not is_valid_tampered


def main():
    """Run all examples."""
    print("\n" + "=" * 60)
    print("NASSCOMOT - PQC Examples")
    print("=" * 60)

    success_count = 0
    total_count = 2

    # Run examples
    if example_key_exchange():
        success_count += 1

    if example_digital_signature():
        success_count += 1

    # Summary
    print("\n" + "=" * 60)
    print(f"Results: {success_count}/{total_count} examples passed")
    print("=" * 60)

    return success_count == total_count


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
