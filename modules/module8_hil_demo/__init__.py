"""
Module 8: Hardware-in-Loop (HIL) Demonstration & Benchmarking

Provides HIL deployment and benchmarking for automotive platforms:
- NVIDIA Orin AGX
- dSPACE platforms
- NXP S32 platforms

Features:
- Performance benchmarking
- Latency measurement
- Security KPI dashboard
- Full ECU↔Gateway↔V2X demo

Standards: ISO 26262, Automotive SPICE
"""

__version__ = "1.0.0"

from .benchmark import PQCBenchmark
from .hil_platform import HILPlatform
from .demo_scenarios import DemoScenarios

__all__ = ["PQCBenchmark", "HILPlatform", "DemoScenarios"]
