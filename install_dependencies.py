#!/usr/bin/env python3
"""
Install dependencies for Wazuh Threat Hunter Pro.

This script handles the complete installation of all required dependencies
and provides clear feedback on the installation process.
"""

import subprocess
import sys
import os

def run_command(command, description):
    """Run a command and handle errors."""
    print(f"[INFO] {description}...")
    try:
        # Use shell=True and capture output for better Windows compatibility
        result = subprocess.run(
            command, 
            shell=True, 
            check=True, 
            capture_output=True, 
            text=True,
            timeout=600  # 10 minute timeout
        )
        print(f"[SUCCESS] {description} completed")
        if result.stdout.strip():
            print(f"Output: {result.stdout.strip()[:200]}...")
        return True
    except subprocess.TimeoutExpired:
        print(f"[ERROR] {description} timed out after 10 minutes")
        return False
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] {description} failed with exit code {e.returncode}")
        if e.stderr:
            print(f"Error details: {e.stderr.strip()}")
        return False
    except Exception as e:
        print(f"[ERROR] {description} failed: {e}")
        return False

def check_python_version():
    """Check if Python version is compatible."""
    version = sys.version_info
    print(f"[INFO] Python version: {version.major}.{version.minor}.{version.micro}")
    
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print("[ERROR] Python 3.8 or higher is required")
        return False
    
    print("[SUCCESS] Python version is compatible")
    return True

def check_pip():
    """Check if pip is available."""
    try:
        result = subprocess.run([sys.executable, "-m", "pip", "--version"], 
                              capture_output=True, text=True, check=True)
        print(f"[SUCCESS] pip is available: {result.stdout.strip()}")
        return True
    except:
        print("[ERROR] pip is not available")
        return False

def install_requirements():
    """Install all requirements from requirements.txt."""
    if not os.path.exists("requirements.txt"):
        print("[ERROR] requirements.txt not found")
        return False
    
    # Upgrade pip first
    if not run_command(f"{sys.executable} -m pip install --upgrade pip", 
                      "Upgrading pip"):
        print("[WARNING] pip upgrade failed, continuing anyway...")
    
    # Install requirements
    return run_command(f"{sys.executable} -m pip install -r requirements.txt", 
                      "Installing Python packages from requirements.txt")

def download_spacy_model():
    """Download the spaCy English model."""
    return run_command(f"{sys.executable} -m spacy download en_core_web_sm", 
                      "Downloading spaCy English model")

def test_imports():
    """Test that all critical modules can be imported."""
    print("[INFO] Testing critical imports...")
    
    critical_modules = [
        ("fastapi", "FastAPI web framework"),
        ("uvicorn", "ASGI server"),
        ("sentence_transformers", "Sentence embeddings"),
        ("numpy", "Numerical computing"),
        ("httpx", "HTTP client"),
        ("google.generativeai", "Google Gemini API")
    ]
    
    all_good = True
    for module, description in critical_modules:
        try:
            __import__(module)
            print(f"  [OK] {module} - {description}")
        except ImportError as e:
            print(f"  [FAIL] {module} - {description}: {e}")
            all_good = False
    
    # Test optional modules
    optional_modules = [
        ("spacy", "Named Entity Recognition"),
        ("bm25s", "BM25 search"),
        ("sklearn", "Machine learning utilities")
    ]
    
    print("[INFO] Testing optional imports...")
    for module, description in optional_modules:
        try:
            __import__(module)
            print(f"  [OK] {module} - {description}")
        except ImportError:
            print(f"  [OPTIONAL] {module} - {description} (will use fallback)")
    
    return all_good

def main():
    """Main installation function."""
    print("=" * 60)
    print("Wazuh Threat Hunter Pro - Dependency Installation")
    print("=" * 60)
    print()
    
    # Check prerequisites
    if not check_python_version():
        sys.exit(1)
    
    if not check_pip():
        sys.exit(1)
    
    print()
    print("Installing dependencies...")
    print("-" * 40)
    
    # Install requirements
    if not install_requirements():
        print("\n[ERROR] Failed to install requirements")
        print("Please check your internet connection and try again")
        print("You can also try manually: pip install -r requirements.txt")
        sys.exit(1)
    
    print()
    print("Installing optional components...")
    print("-" * 40)
    
    # Download spaCy model (optional)
    if not download_spacy_model():
        print("[WARNING] spaCy model download failed - NER will use regex fallback")
    
    print()
    print("Testing installation...")
    print("-" * 40)
    
    # Test imports
    if not test_imports():
        print("\n[WARNING] Some critical modules failed to import")
        print("The application may not work correctly")
    else:
        print("\n[SUCCESS] All critical modules imported successfully!")
    
    print()
    print("=" * 60)
    print("Installation Summary")
    print("=" * 60)
    print()
    print("The Wazuh Threat Hunter Pro dependencies have been installed.")
    print()
    print("To start the application:")
    print("  python main.py")
    print()
    print("To access the web interface:")
    print("  http://localhost:8000")
    print()
    print("Note: Make sure to set your environment variables:")
    print("  - GEMINI_API_KEY (required)")
    print("  - BASIC_AUTH_USER (required)")
    print("  - BASIC_AUTH_PASS (required)")
    print()

if __name__ == "__main__":
    main()