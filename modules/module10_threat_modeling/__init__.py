"""
Module 10: Automotive Threat Modeling & Compliance (Optional)

Tools for threat modeling and compliance validation.

Features:
- ISO/SAE 21434 compliance checking
- UNECE R155/R156 validation
- Quantum risk assessment
- STRIDE/DREAD analysis

Standards: ISO/SAE 21434, UNECE R155/R156
"""

__version__ = "1.0.0"

from .compliance_checker import ComplianceChecker
from .quantum_risk import QuantumRiskAssessment
from .threat_analysis import ThreatAnalyzer

__all__ = ["ComplianceChecker", "QuantumRiskAssessment", "ThreatAnalyzer"]
