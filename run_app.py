#!/usr/bin/env python3
"""
Simple launcher for Threat Hunter Pro that handles import issues.

This script can be run directly and will properly initialize the application
without relative import issues.
"""

import os
import sys
import logging
import threading
import time

# Add current directory to Python path to allow direct imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def main():
    """Start the Threat Hunter Pro application."""
    
    # Set up logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    print("Starting Wazuh Threat Hunter Pro (Gemini Edition)")
    print("=" * 60)
    
    try:
        # Import modules - try both relative and direct imports
        try:
            # Try direct imports first
            import config
            import state  
            from app import app
        except ImportError:
            # Fall back to relative imports if direct imports fail
            import config, state
            from app import app
        
        # Check environment variables
        if not config.GEMINI_API_KEYS:
            print("CRITICAL ERROR: No GEMINI_API_KEY environment variables are set.")
            print("Please set at least one of the following environment variables:")
            print("  GEMINI_API_KEY='your_api_key_here'")
            print("  GEMINI_API_KEY_2='your_second_api_key_here'")
            print("  GEMINI_API_KEY_3='your_third_api_key_here'")
            print()
            print("Get your API key from: https://aistudio.google.com/apikey")
            return False
            
        if not config.BASIC_AUTH_USER or not config.BASIC_AUTH_PASS:
            print("CRITICAL ERROR: Authentication credentials not set.")
            print("Please set the following environment variables:")
            print("  BASIC_AUTH_USER='your_username'")
            print("  BASIC_AUTH_PASS='your_password'")
            return False
        
        # Create database directory
        os.makedirs(config.DB_DIR, exist_ok=True)
        
        # Print startup information
        print(f"[OK] Dashboard will be available at: http://localhost:8000")
        print(f"[OK] Username: {config.BASIC_AUTH_USER}")
        print(f"[OK] Password: [hidden]")
        print(f"[OK] Loaded {len(config.GEMINI_API_KEYS)} Gemini API key(s)")
        print(f"[OK] Metrics available at: http://localhost:8000/metrics")
        print("=" * 60)
        
        # Initialize vector database
        print("Initializing vector database...")
        try:
            from vector_db import initialize_vector_db
            initialize_vector_db()
            print("[OK] Vector database initialized")
        except Exception as e:
            logging.error(f"Vector database initialization failed: {e}")
            print("[WARNING] Vector database initialization failed - some features may not work")
        
        # Start background worker
        print("Starting background worker...")
        try:
            from worker import background_worker
            worker_thread = threading.Thread(
                target=background_worker, 
                daemon=True, 
                name="ThreatHunterWorker"
            )
            worker_thread.start()
            print("[OK] Background worker started")
        except Exception as e:
            logging.error(f"Background worker failed to start: {e}")
            print("[WARNING] Background worker failed - manual analysis only")
        
        # Start FastAPI server
        print("Starting web server...")
        print("Press Ctrl+C to stop the server")
        print("=" * 60)
        
        import uvicorn
        uvicorn.run(app, host="0.0.0.0", port=8000)
        
    except KeyboardInterrupt:
        print("\nShutting down...")
        return True
    except Exception as e:
        print(f"CRITICAL ERROR: {e}")
        logging.error(f"Application startup failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = main()
    if not success:
        sys.exit(1)