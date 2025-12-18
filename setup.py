#!/usr/bin/env python3
"""
HAWKSHOT Setup Script
Install with: pip install -e .
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="hawkshot",
    version="4.0.0",
    author="nuxyel",
    author_email="",
    description="A fast multi-purpose reconnaissance tool for DNS enumeration and web scanning",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/nuxyel/hawkshot",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Internet :: Name Service (DNS)",
        "Topic :: Internet :: WWW/HTTP",
    ],
    python_requires=">=3.8",
    install_requires=[
        "dnspython>=2.4.0,<3.0.0",
        "requests>=2.28.0,<3.0.0",
        "colorama>=0.4.6,<1.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "flake8>=6.0.0",
            "black>=23.0.0",
            "mypy>=1.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "hawkshot=hawkshot.cli:main",
        ],
    },
    keywords="security pentesting reconnaissance dns enumeration web scanner",
    project_urls={
        "Bug Reports": "https://github.com/nuxyel/hawkshot/issues",
        "Source": "https://github.com/nuxyel/hawkshot",
    },
)
