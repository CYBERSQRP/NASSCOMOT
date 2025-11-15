#!/usr/bin/env python3
"""
NASSCOMOT - Quantum-Safe Cryptography for Automotive Systems
Setup configuration for package installation
"""

from setuptools import setup, find_packages, Extension
import os
import sys

# Read the README file
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Read requirements
with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [
        line.strip() for line in fh
        if line.strip() and not line.startswith("#")
    ]

# Version
VERSION = "1.0.0"

# C/C++ extensions for performance-critical components
extensions = []

# Optional: Add C extensions for PQC algorithms if needed
if "--with-native-extensions" in sys.argv:
    sys.argv.remove("--with-native-extensions")

    # Example: Native ML-KEM implementation
    extensions.append(
        Extension(
            "nasscomot.native.mlkem",
            sources=["modules/module1_pqc_layer/native/mlkem.c"],
            include_dirs=["modules/module1_pqc_layer/native/include"],
            extra_compile_args=["-O3", "-march=native", "-std=c11"],
        )
    )

setup(
    name="nasscomot",
    version=VERSION,
    author="LTTS Quantum Security Team",
    author_email="quantum-security@ltts.com",
    description="Quantum-Safe Cryptography for Automotive Systems",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/CYBERSQRP/NASSCOMOT",
    packages=find_packages(exclude=["tests", "benchmarks", "docs", "examples"]),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Embedded Systems",
        "License :: Other/Proprietary License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: POSIX :: Linux",
        "Environment :: Console",
    ],
    python_requires=">=3.9,<3.13",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.4.3",
            "pytest-cov>=4.1.0",
            "black>=23.12.0",
            "mypy>=1.7.0",
            "pylint>=3.0.3",
        ],
        "docs": [
            "sphinx>=7.2.6",
            "sphinx-rtd-theme>=2.0.0",
            "sphinx-autodoc-typehints>=1.25.0",
        ],
        "benchmark": [
            "pytest-benchmark>=4.0.0",
            "memory-profiler>=0.61.0",
            "py-spy>=0.3.14",
        ],
    },
    ext_modules=extensions,
    entry_points={
        "console_scripts": [
            "nasscomot=modules.cli:main",
            "nasscomot-benchmark=benchmarks.cli:main",
            "nasscomot-validate=compliance.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "nasscomot": [
            "*.yaml",
            "*.json",
            "*.pem",
            "configs/*.yaml",
        ],
    },
    zip_safe=False,
    project_urls={
        "Bug Reports": "https://github.com/CYBERSQRP/NASSCOMOT/issues",
        "Source": "https://github.com/CYBERSQRP/NASSCOMOT",
        "Documentation": "https://nasscomot.readthedocs.io/",
    },
    keywords=[
        "post-quantum cryptography",
        "PQC",
        "automotive security",
        "V2X",
        "AUTOSAR",
        "quantum-safe",
        "ML-KEM",
        "ML-DSA",
        "Kyber",
        "Dilithium",
        "ISO 21434",
        "UNECE R155",
    ],
)
