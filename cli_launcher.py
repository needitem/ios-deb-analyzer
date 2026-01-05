#!/usr/bin/env python3
"""Launcher script for iOS Deb Analyzer CLI."""

import sys
import os

# Add the package directory to path
if getattr(sys, 'frozen', False):
    base_path = sys._MEIPASS
else:
    base_path = os.path.dirname(os.path.abspath(__file__))

sys.path.insert(0, base_path)

from ios_deb_analyzer.cli import main

if __name__ == '__main__':
    main()
