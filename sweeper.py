#!/usr/bin/env python3
# sweeper.py — entry point
"""sweeper — multi-stage recon and scanning framework.

Usage:
    python3 sweeper.py -t targets.txt                 # opens the menu
    python3 sweeper.py -t targets.txt -l mid --no-menu
"""
import sys

from sweeper.app import main

if __name__ == "__main__":
    sys.exit(main())
