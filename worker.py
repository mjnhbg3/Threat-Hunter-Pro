"""
Background worker for the Threat Hunter application.

This module defines a function that runs in a separate thread and
continually processes new logs, updates the vector database, runs AI
analyses and refreshes the dashboard data. It closely follows the
behaviour of the monolithic script's background worker.
"""

from __future__ import annotations

import threading
import time
import asyncio
import logging
from datetime import datetime

from . import state
from .vector_db import initialize_vector_db, save_vector_db
from .persistence import (
    load_dashboard_data,
    save_dashboard_data,
    load_settings,
    load_ignored_issues,
)
from .log_processing import process_logs, update_dashboard_metrics
from .ai_logic import analyze_context_with_ner_enhancement


def background_worker() -> None:
    """
    Entry point for the background worker thread. Sets up the vector
    database, loads persisted state and then runs an infinite loop
    processing logs and performing AI analyses at intervals defined
    by the current settings.
    """
    try:
        logging.info("Background worker starting...")
        state.set_app_status("Starting up...")
        # Create a dedicated event loop for asynchronous operations
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(initialize_vector_db())
        state.set_app_status("Loading dashboard data...")
        loop.run_until_complete(load_dashboard_data())
        state.set_app_status("Loading settings...")
        load_settings()
        state.set_app_status("Loading ignored issues...")
        load_ignored_issues()
        state.set_app_status("Ready")
        cycle_count = 0
        while True:
            cycle_count += 1
            cycle_start = time.time()
            try:
                state.set_app_status("Processing logs...")
                new_logs = loop.run_until_complete(process_logs())
                update_dashboard_metrics(new_logs)
                if new_logs:
                    state.set_app_status("AI analyzing logs...")
                    loop.run_until_complete(analyze_context_with_ner_enhancement(new_logs))
                state.dashboard_data["last_run"] = datetime.now().isoformat()
                state.set_app_status("Saving data...")
                loop.run_until_complete(save_dashboard_data())
                state.set_app_status("Idle")
            except Exception as e:
                logging.error(f"Error in background worker cycle {cycle_count}: {e}", exc_info=True)
                state.dashboard_data["summary"] = f"Worker Error: {e}"
                state.set_app_status(f"Error: {str(e)[:50]}")
                loop.run_until_complete(save_dashboard_data())
            cycle_time = time.time() - cycle_start
            loop.run_until_complete(state.metrics.set_cycle_time(cycle_time))
            logging.info(f"=== Worker cycle {cycle_count} finished in {cycle_time:.2f}s ===")
            time.sleep(state.settings.get("processing_interval", 600))
    except Exception as e:
        logging.error(f"Fatal error in background worker: {e}", exc_info=True)
        state.set_app_status("Fatal error - worker crashed")