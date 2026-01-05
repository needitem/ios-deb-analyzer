#!/usr/bin/env python3
"""Launcher script for iOS Deb Analyzer GUI."""

import sys
import os

# Add the package directory to path
if getattr(sys, 'frozen', False):
    # Running as compiled
    base_path = sys._MEIPASS
else:
    base_path = os.path.dirname(os.path.abspath(__file__))

sys.path.insert(0, base_path)

# Now import and run
from ios_deb_analyzer.gui import main

if __name__ == '__main__':
    main()
