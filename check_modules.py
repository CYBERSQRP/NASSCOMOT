#!/usr/bin/env python3
"""
Comprehensive Module Functionality Checker for NASSCOMOT
Checks all 10 modules for correct installation and basic functionality.
"""

import sys
import importlib
import traceback
from typing import Dict, List, Tuple

# Define modules and their key components
MODULES = {
    "Module 1: PQC Layer": {
        "path": "modules.module1_pqc_layer",
        "components": [
            "MLKEMKeyExchange",
            "MLKEM768",
            "MLDSASignature",
            "MLDSA65",
            "SLHDSASignature",
            "SLHDSA128s",
            "HybridTLSContext",
            "SecureBytes",
        ],
        "required_deps": ["oqs"],
    },
    "Module 2: QKD Layer": {
        "path": "modules.module2_qkd_layer",
        "components": [
            "BB84Protocol",
            "E91Protocol",
            "QKDManager",
            "PrivacyAmplifier",
        ],
        "required_deps": ["qiskit", "numpy"],
    },
    "Module 3: Entropy & RNG": {
        "path": "modules.module3_entropy_rng",
        "components": [
            "SecureRandom",
            "EntropyPool",
            "HardwareRNG",
            "FIPSTests",
        ],
        "required_deps": [],
    },
    "Module 4: In-Vehicle Communication": {
        "path": "modules.module4_invehicle_comm",
        "components": [
            "ECUCryptoManager",
            "SecureCANBus",
            "SecureSOMEIP",
            "AutomotiveEthernetSecurity",
        ],
        "required_deps": ["cryptography"],
    },
    "Module 5: V2X Messaging": {
        "path": "modules.module5_v2x_messaging",
        "components": [
            "DSRCSecurityManager",
            "CV2XSecurityManager",
            "V2XCryptoEngine",
        ],
        "required_deps": ["cryptography"],
    },
    "Module 6: OTA Security": {
        "path": "modules.module6_ota_security",
        "components": [
            "OTAManager",
            "FirmwareSigner",
            "TelemetrySecurity",
        ],
        "required_deps": ["cryptography"],
    },
    "Module 7: AUTOSAR Integration": {
        "path": "modules.module7_autosar_integration",
        "components": [
            "AUTOSARCrypto",
            "HSMIntegration",
        ],
        "required_deps": ["cryptography"],
    },
    "Module 8: HIL Demo": {
        "path": "modules.module8_hil_demo",
        "components": [
            "HILPlatform",
            "BenchmarkSuite",
            "DemoScenarios",
        ],
        "required_deps": [],
    },
    "Module 9: Vehicle PKI": {
        "path": "modules.module9_vehicle_pki",
        "components": [
            "PQCCertificateAuthority",
            "VINIdentityManager",
        ],
        "required_deps": ["cryptography"],
    },
    "Module 10: Threat Modeling": {
        "path": "modules.module10_threat_modeling",
        "components": [
            "ThreatAnalyzer",
            "ComplianceChecker",
            "QuantumRiskAssessment",
        ],
        "required_deps": [],
    },
}


def check_dependency(dep_name: str) -> bool:
    """Check if a Python dependency is installed."""
    try:
        importlib.import_module(dep_name)
        return True
    except (ImportError, AttributeError, Exception) as e:
        # Handle version mismatches and other issues
        return False


def check_module(module_name: str, module_info: dict) -> Tuple[bool, str, List[str]]:
    """
    Check if a module can be imported and its components are available.

    Returns:
        Tuple of (success, message, missing_components)
    """
    module_path = module_info["path"]
    components = module_info["components"]
    required_deps = module_info["required_deps"]

    # Check required dependencies first
    missing_deps = [dep for dep in required_deps if not check_dependency(dep)]
    if missing_deps:
        return (False, f"Missing dependencies: {', '.join(missing_deps)}", [])

    # Try to import the module
    try:
        mod = importlib.import_module(module_path)

        # Check for components
        missing_components = []
        for component in components:
            if not hasattr(mod, component):
                missing_components.append(component)

        if missing_components:
            return (
                False,
                f"Module imported but missing components: {', '.join(missing_components)}",
                missing_components
            )

        return (True, "OK - All components available", [])

    except Exception as e:
        error_msg = str(e).split('\n')[0] if '\n' in str(e) else str(e)
        return (False, f"Import failed: {error_msg[:100]}", [])


def main():
    """Run comprehensive module check."""
    print("=" * 80)
    print("NASSCOMOT - Comprehensive Module Functionality Check")
    print("=" * 80)
    print()

    results = {}
    total_modules = len(MODULES)
    working_modules = 0

    for module_name, module_info in MODULES.items():
        print(f"\n[Checking] {module_name}")
        print("-" * 80)

        success, message, missing = check_module(module_name, module_info)
        results[module_name] = {
            "success": success,
            "message": message,
            "missing": missing,
            "path": module_info["path"],
        }

        if success:
            print(f"✓ Status: {message}")
            working_modules += 1
        else:
            print(f"✗ Status: {message}")

        # Show module path
        print(f"  Path: {module_info['path']}")

        # Show required dependencies status
        if module_info["required_deps"]:
            print(f"  Dependencies:")
            for dep in module_info["required_deps"]:
                dep_status = "✓" if check_dependency(dep) else "✗"
                print(f"    {dep_status} {dep}")

    # Summary
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"Total Modules: {total_modules}")
    print(f"Working Modules: {working_modules}")
    print(f"Failed Modules: {total_modules - working_modules}")
    print(f"Success Rate: {working_modules / total_modules * 100:.1f}%")
    print()

    # List working modules
    if working_modules > 0:
        print("✓ Working Modules:")
        for name, result in results.items():
            if result["success"]:
                print(f"  - {name}")
        print()

    # List failed modules and reasons
    failed_modules = [(name, result) for name, result in results.items() if not result["success"]]
    if failed_modules:
        print("✗ Failed Modules:")
        for name, result in failed_modules:
            print(f"  - {name}")
            print(f"    Reason: {result['message']}")
        print()

    # Dependency recommendations
    print("=" * 80)
    print("DEPENDENCY STATUS")
    print("=" * 80)

    all_deps = set()
    for module_info in MODULES.values():
        all_deps.update(module_info["required_deps"])

    missing_global_deps = [dep for dep in all_deps if not check_dependency(dep)]
    installed_global_deps = [dep for dep in all_deps if check_dependency(dep)]

    if installed_global_deps:
        print("✓ Installed Dependencies:")
        for dep in sorted(installed_global_deps):
            print(f"  - {dep}")
        print()

    if missing_global_deps:
        print("✗ Missing Dependencies:")
        for dep in sorted(missing_global_deps):
            print(f"  - {dep}")
        print()
        print("Install missing dependencies with:")
        print(f"  pip install {' '.join(sorted(missing_global_deps))}")
        print()

    return 0 if working_modules == total_modules else 1


if __name__ == "__main__":
    sys.exit(main())
