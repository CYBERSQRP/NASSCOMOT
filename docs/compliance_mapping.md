# Compliance Mapping

## ISO/SAE 21434 - Cybersecurity Engineering

### Section 9.3: Cryptography

| Requirement | NASSCOMOT Implementation | Module | Status |
|-------------|-------------------------|--------|--------|
| 9.3.1 - Cryptographic key management | QKD Manager, Entropy Pool, Key lifecycle | Module 2, 3 | ✓ Implemented |
| 9.3.2 - Random number generation | Hardware RNG, FIPS validation | Module 3 | ✓ Implemented |
| 9.3.3 - Cryptographic algorithms | ML-KEM, ML-DSA, SLH-DSA (NIST PQC) | Module 1 | ✓ Implemented |
| 9.3.4 - Key derivation | HKDF-based key derivation | Module 1 | ✓ Implemented |
| 9.3.5 - Digital signatures | ML-DSA for firmware, messages | Module 1, 5, 6 | ✓ Implemented |

### Section 5: Secure Software Updates

| Requirement | NASSCOMOT Implementation | Module | Status |
|-------------|-------------------------|--------|--------|
| 5.1 - Software identification | Version tracking, manifest | Module 6 | ✓ Implemented |
| 5.2 - Software integrity | ML-DSA signatures, hash verification | Module 6 | ✓ Implemented |
| 5.3 - Software authenticity | PQC certificate validation | Module 6, 9 | ✓ Implemented |
| 5.4 - Secure communication channels | PQ-TLS for OTA | Module 1, 6 | ✓ Implemented |
| 5.5 - Anti-rollback protection | Version verification | Module 6 | ✓ Implemented |

## UNECE R155 - Cyber Security and Management System

### Annex 5 - Cyber Security Requirements

| Requirement | NASSCOMOT Implementation | Module | Status |
|-------------|-------------------------|--------|--------|
| A5-3.1 - Vehicle communication security | PQC for V2X, ECU-to-ECU | Module 4, 5 | ✓ Implemented |
| A5-3.2 - Secure software updates | ML-DSA signed firmware | Module 6 | ✓ Implemented |
| A5-3.3 - Vehicle data protection | Encrypted telemetry | Module 6 | ✓ Implemented |
| A5-3.4 - Cryptographic protection | NIST PQC algorithms | Module 1 | ✓ Implemented |

### Table A5/2 - Mitigation Measures

| Threat | Mitigation | NASSCOMOT Implementation | Module |
|--------|-----------|-------------------------|--------|
| T3 - Manipulation of vehicle communication | PQC signatures, encryption | ML-DSA, ML-KEM | 1, 4, 5 |
| T5 - Manipulation of software/firmware | Signed updates, integrity checks | ML-DSA signing | 6 |
| T6 - Back-end server vulnerabilities | PQ-TLS, mutual authentication | Hybrid TLS | 1, 6 |

## UNECE R156 - Software Update Management System

| Requirement | NASSCOMOT Implementation | Module | Status |
|-------------|-------------------------|--------|--------|
| 7.2.1 - Software identification | Version tracking | Module 6 | ✓ Implemented |
| 7.2.2 - Software authenticity | ML-DSA signatures | Module 6 | ✓ Implemented |
| 7.2.3 - Software integrity | Hash verification | Module 6 | ✓ Implemented |
| 7.2.4 - Secure update process | PQ-TLS channels | Module 1, 6 | ✓ Implemented |

## NIST FIPS Standards

### FIPS 203 - ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)

| Parameter Set | Security Level | NASSCOMOT Implementation | Use Case |
|--------------|---------------|-------------------------|----------|
| ML-KEM-512 | NIST Level 1 | MLKEM512 class | Constrained ECUs |
| ML-KEM-768 | NIST Level 3 | MLKEM768 class (recommended) | General automotive use |
| ML-KEM-1024 | NIST Level 5 | MLKEM1024 class | Critical safety systems |

### FIPS 204 - ML-DSA (Module-Lattice-Based Digital Signature Algorithm)

| Parameter Set | Security Level | NASSCOMOT Implementation | Use Case |
|--------------|---------------|-------------------------|----------|
| ML-DSA-44 | NIST Level 2 | MLDSA44 class | V2X real-time signing |
| ML-DSA-65 | NIST Level 3 | MLDSA65 class (recommended) | Firmware signing |
| ML-DSA-87 | NIST Level 5 | MLDSA87 class | Long-term signatures |

### FIPS 205 - SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)

| Parameter Set | Security Level | NASSCOMOT Implementation | Use Case |
|--------------|---------------|-------------------------|----------|
| SLH-DSA-128s | NIST Level 1 | SLHDSA128s class | Conservative choice |
| SLH-DSA-192s | NIST Level 3 | SLHDSA192s class | CA signatures |
| SLH-DSA-256s | NIST Level 5 | SLHDSA256s class | Root CA |

### FIPS 140-3 - Cryptographic Module Validation

| Requirement | NASSCOMOT Implementation | Module | Status |
|-------------|-------------------------|--------|--------|
| Cryptographic module specification | Documented interfaces | All modules | ✓ Documented |
| Approved algorithms | NIST FIPS 203/204/205 | Module 1 | ✓ Implemented |
| Random number generation | FIPS-validated RNG | Module 3 | ✓ Implemented |
| Key management | Secure key lifecycle | Module 2, 3 | ✓ Implemented |
| Self-tests | Continuous tests | Module 3 | ✓ Implemented |

## AUTOSAR Adaptive Platform

### Cryptography Service Interfaces

| AUTOSAR Interface | NASSCOMOT Implementation | Module |
|------------------|-------------------------|--------|
| CryptoKeyManagement | QKD Manager, HSM integration | Module 2, 7 |
| CryptoKeyExchange | ML-KEM implementation | Module 1, 7 |
| CryptoSignature | ML-DSA implementation | Module 1, 7 |
| CryptoEncrypt | AES-GCM with PQC key exchange | Module 4, 7 |
| SecureOTA | Signed firmware updates | Module 6, 7 |

## IEEE 1609.2 - V2X Security

| Requirement | NASSCOMOT Implementation | Module | Status |
|-------------|-------------------------|--------|--------|
| Message authentication | ML-DSA signatures | Module 5 | ✓ Implemented |
| Certificate management | PQC certificates | Module 9 | ✓ Implemented |
| Secure message format | PQC signature appending | Module 5 | ✓ Implemented |

## Quantum Risk Assessment

### Algorithm Migration Path

| Current Algorithm | Quantum Vulnerability | NASSCOMOT Replacement | Timeline |
|------------------|----------------------|---------------------|----------|
| RSA-2048 | HIGH (Shor's algorithm) | ML-KEM-768 | Immediate |
| ECDSA-P256 | HIGH (Shor's algorithm) | ML-DSA-65 | Immediate |
| AES-128 | MEDIUM (Grover's algorithm) | AES-256 | Near-term |
| SHA-256 | LOW (collision resistance) | SHA3-256 | Future-proof |

### Quantum Computing Timeline Assumptions

- **2030**: Small-scale quantum computers (50-100 qubits)
- **2035**: Medium-scale quantum computers capable of breaking RSA-2048
- **2040+**: Large-scale quantum computers

**NASSCOMOT Strategy**: Deploy PQC now to protect against "harvest now, decrypt later" attacks.

## Compliance Summary

### Fully Compliant

✓ ISO/SAE 21434 - Cryptography (Section 9.3)
✓ ISO/SAE 21434 - Secure Updates (Section 5)
✓ UNECE R155 - Cyber Security
✓ UNECE R156 - Software Updates
✓ NIST FIPS 203 - ML-KEM
✓ NIST FIPS 204 - ML-DSA
✓ NIST FIPS 205 - SLH-DSA

### Partially Compliant (Implementation Dependent)

⚠ FIPS 140-3 - Full validation requires certified testing lab
⚠ AUTOSAR Adaptive - Requires integration with OEM platform
⚠ IEEE 1609.2 - Requires V2X infrastructure support

### Recommended Next Steps

1. **FIPS 140-3 Certification**: Submit modules 1 & 3 for CMVP validation
2. **AUTOSAR Integration**: Complete integration testing with OEM platforms
3. **V2X Field Testing**: Deploy in test vehicles with V2X infrastructure
4. **ISO 26262 ASIL**: Conduct safety analysis for safety-critical ECUs

## Audit Trail

| Date | Standard | Version | Assessor | Result |
|------|---------|---------|----------|--------|
| 2025-11-15 | ISO/SAE 21434 | 2021 | Internal | Compliant |
| 2025-11-15 | NIST FIPS 203/204/205 | Draft | Internal | Compliant |
| TBD | FIPS 140-3 | 2019 | CMVP Lab | Pending |
