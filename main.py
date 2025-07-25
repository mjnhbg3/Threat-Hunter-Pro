"""
Application entry point for Threat Hunter.

This script performs environment validation, starts the background
worker thread and launches the FastAPI server using Uvicorn. It
reproduces the startup logic from the original monolithic script
while leveraging the refactored modules.
"""

from __future__ import annotations

import os
import threading
import time
import logging

import uvicorn

from .config import GEMINI_API_KEYS, BASIC_AUTH_USER, BASIC_AUTH_PASS, DB_DIR
from . import state
from .worker import background_worker
from .app import app


def start_backup_worker() -> threading.Thread | None:
    """Start a backup worker thread if the lifespan event fails."""
    try:
        worker_thread = threading.Thread(target=background_worker, daemon=True, name="BackupThreatHunterWorker")
        worker_thread.start()
        logging.info(f"Backup worker thread started. Alive: {worker_thread.is_alive()}")
        return worker_thread
    except Exception as e:
        logging.error(f"Failed to start backup worker: {e}")
        return None


def delayed_backup_start() -> None:
    """Wait for a few seconds and check if any worker thread is running, else start one."""
    time.sleep(5)
    threat_hunter_threads = [t for t in threading.enumerate() if 'ThreatHunter' in t.name]
    if not threat_hunter_threads:
        logging.warning("No ThreatHunter worker threads found. Starting backup worker...")
        start_backup_worker()
    else:
        logging.info(f"Found {len(threat_hunter_threads)} ThreatHunter threads: {[t.name for t in threat_hunter_threads]}")


def main() -> None:
    """Check environment, start worker and run Uvicorn."""
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    if not GEMINI_API_KEYS:
        print("="*80)
        print("!!! CRITICAL ERROR: No GEMINI_API_KEY environment variables are set. !!!")
        print("!!! The application cannot start without at least one.                  !!!")
        print("!!! Please set one or more of the following:                           !!!")
        print("!!! export GEMINI_API_KEY='your_api_key_here'                          !!!")
        print("!!! export GEMINI_API_KEY_2='your_second_api_key_here'                 !!!")
        print("!!! export GEMINI_API_KEY_3='your_third_api_key_here'                  !!!")
        print("="*80)
        return
    if not BASIC_AUTH_USER or not BASIC_AUTH_PASS:
        print("="*80)
        print("!!! CRITICAL ERROR: Authentication credentials not set.                 !!!")
        print("!!! Please set the following environment variables:                     !!!")
        print("!!! export BASIC_AUTH_USER='your_username'                              !!!")
        print("!!! export BASIC_AUTH_PASS='your_password'                              !!!")
        print("="*80)
        return
    os.makedirs(DB_DIR, exist_ok=True)
    print("--- Starting Wazuh Threat Hunter Pro (Gemini Edition) ---")
    print(f"Dashboard will be available at: http://0.0.0.0:8000")
    print(f"Username: {BASIC_AUTH_USER}")
    print(f"Password: [hidden]")
    print(f"Loaded {len(GEMINI_API_KEYS)} Gemini API keys")
    print(f"Metrics available at: http://0.0.0.0:8000/metrics")
    print("---------------------------------------------------------")
    # Start delayed backup check thread
    backup_thread = threading.Thread(target=delayed_backup_start, daemon=True, name="BackupChecker")
    backup_thread.start()
    # Start Uvicorn server
    uvicorn.run(app, host="0.0.0.0", port=8000)


if __name__ == "__main__":
    main()