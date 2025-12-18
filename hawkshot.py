#!/usr/bin/env python3
"""
HAWKSHOT v4.0 - A Multi-purpose Recon Tool
DNS Subdomain Enumeration | Web Directory Scanning | VHost Enumeration | Tech Detection

This is the legacy single-file entry point. For the full modular package, use:
  python -m hawkshot
  
Or install via pip:
  pip install -e .
  hawkshot --help

Author: r3n4n
License: MIT
"""

# For backward compatibility, import and run the CLI
from hawkshot.cli import main

if __name__ == "__main__":
    main()
