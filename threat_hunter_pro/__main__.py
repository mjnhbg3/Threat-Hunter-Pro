"""
Main entry point for running threat_hunter_pro as a module.

This allows the package to be executed with:
    python -m threat_hunter_pro

This will start the main application using the main.py module.
"""

from .main import main

if __name__ == "__main__":
    main()