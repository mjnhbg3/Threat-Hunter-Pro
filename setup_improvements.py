#!/usr/bin/env python3
"""
Setup script for Wazuh Threat Hunter Pro improvements.

This script installs the new dependencies and downloads the required spaCy model
for Named Entity Recognition functionality.
"""

import subprocess
import sys
import logging

def run_command(command, description):
    """Run a command and handle errors."""
    print(f"🔧 {description}...")
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        print(f"[SUCCESS] {description} completed successfully")
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] {description} failed: {e}")
        print(f"Error output: {e.stderr}")
        return None

def main():
    """Main setup function."""
    print("Setting up Wazuh Threat Hunter Pro AI improvements...")
    print()
    
    # Install requirements
    success = True
    
    if run_command("pip install -r requirements.txt", "Installing Python dependencies") is None:
        success = False
    
    # Download spaCy model
    if run_command("python -m spacy download en_core_web_sm", "Downloading spaCy English model") is None:
        success = False
    
    if success:
        print()
        print("Setup completed successfully!")
        print()
        print("New AI-powered features available:")
        print("  • Named Entity Recognition (NER) for IPs, hostnames, usernames")  
        print("  • Hybrid search combining semantic similarity + keyword matching")
        print("  • Entity boosting in embeddings for better retrieval")
        print("  • Enhanced chat with entity-aware analysis")
        print("  • Improved script generation with entity targeting")
        print("  • Fixed UI z-index issues for fullscreen modals")
        print("  • Added chat status indicators and clear buttons")
        print("  • Increased token limits for longer AI responses")
        print()
        print("To start the application:")
        print("  python main.py")
        print()
    else:
        print()
        print("Setup completed with some errors.")
        print("Please resolve the issues above before running the application.")
        sys.exit(1)

if __name__ == "__main__":
    main()