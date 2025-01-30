# run_analyzer.py
"""
Entry point script for COM Security Analyzer
"""
import sys
import os

# Add the package directory to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from com_security_analyzer.main import main

if __name__ == "__main__":
    main()