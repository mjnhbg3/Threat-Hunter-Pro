#!/usr/bin/env python3
"""
Test script to verify application startup with sample environment variables.
"""

import os
import subprocess
import sys

def test_startup():
    """Test application startup with sample environment variables."""
    print("Setting test environment variables...")
    
    # Set test environment variables
    os.environ['GEMINI_API_KEY'] = 'test_key_here'
    os.environ['BASIC_AUTH_USER'] = 'admin'
    os.environ['BASIC_AUTH_PASS'] = 'password'
    
    print("Environment variables set:")
    print(f"  GEMINI_API_KEY: {os.environ.get('GEMINI_API_KEY', 'NOT SET')}")
    print(f"  BASIC_AUTH_USER: {os.environ.get('BASIC_AUTH_USER', 'NOT SET')}")
    print(f"  BASIC_AUTH_PASS: {os.environ.get('BASIC_AUTH_PASS', 'NOT SET')}")
    print()
    
    print("Starting application...")
    print("-" * 50)
    
    # Import and run the application
    try:
        from run_app import main
        main()
    except KeyboardInterrupt:
        print("\nApplication interrupted by user")
        return True
    except Exception as e:
        print(f"Application failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_startup()
    if success:
        print("[OK] Application test completed successfully")
    else:
        print("[ERROR] Application test failed")
        sys.exit(1)