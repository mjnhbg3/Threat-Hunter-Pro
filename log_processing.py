"""
Log processing utilities for Threat Hunter.

This module provides functions to read the Wazuh alerts log file,
detect new entries since the last processing run, and add them to
the vector database. It handles log rotation, deduplication and
updates dashboard metrics such as log trends and rule distribution.
"""

from __future__ import annotations

import os
import json
import logging
from datetime import datetime
from typing import List, Dict, Any

from . import state
from .config import LOG_FILE, LOG_POSITION_FILE
from .vector_db import add_to_vector_db, save_vector_db
from .persistence import save_dashboard_data


def get_log_position() -> int:
    """Return the last processed byte offset within the log file."""
    if not os.path.exists(LOG_POSITION_FILE):
        logging.info(f"No log position file found at {LOG_POSITION_FILE}, starting from 0")
        return 0
    try:
        with open(LOG_POSITION_FILE, 'r') as f:
            pos = int(f.read().strip())
        logging.info(f"Read log position: {pos}")
        return pos
    except (ValueError, FileNotFoundError) as e:
        logging.warning(f"Error reading log position file: {e}, defaulting to 0")
        return 0


def set_log_position(position: int) -> None:
    """Persist the byte offset of the last processed log line."""
    try:
        with open(LOG_POSITION_FILE, 'w') as f:
            f.write(str(position))
        logging.info(f"Set log position to: {position}")
    except Exception as e:
        logging.error(f"Failed to set log position: {e}")


async def process_logs() -> List[Dict[str, Any]]:
    """
    Read new log entries from the Wazuh alerts file, deduplicate and
    vectorise them. Returns the list of new logs processed in this
    cycle. Updates state.dashboard_data with metrics and persists
    changes to disk.
    """
    logging.info(f"Processing logs from: {LOG_FILE}")
    # Ensure the directory exists
    log_dir = os.path.dirname(LOG_FILE)
    if not os.path.exists(LOG_FILE):
        logging.warning(f"Log file not found at {LOG_FILE}. Skipping processing.")
        return []
    
    logs_to_process: List[Dict[str, Any]] = []
    current_position = 0
    is_initial_run = state.vector_db.ntotal == 0 if state.vector_db else True
    last_position = get_log_position()
    try:
        file_size = os.path.getsize(LOG_FILE)
    except OSError as e:
        logging.error(f"Failed to get file size: {e}")
        return []
    
    # Handle log rotation
    if last_position > file_size:
        logging.info("Log file appears to have been rotated. Resetting position to 0.")
        last_position = 0
    
    if is_initial_run:
        logging.info(f"First run detected. Performing initial scan of the last {state.settings['initial_scan_count']} logs from {LOG_FILE}.")
        try:
            with open(LOG_FILE, 'r', errors='ignore') as f:
                if file_size > 1024 * 1024:
                    f.seek(max(0, file_size - 1024 * 1024))
                    lines = f.readlines()
                    log_lines = lines[-state.settings['initial_scan_count']:]
                else:
                    log_lines = list(f)[-state.settings['initial_scan_count']:]
                current_position = file_size
            for line in log_lines:
                try:
                    logs_to_process.append(json.loads(line.strip()))
                except json.JSONDecodeError:
                    continue
            logging.info(f"Initial scan collected {len(logs_to_process)} logs")
        except Exception as e:
            logging.error(f"Error during initial scan: {e}")
            return []
    else:
        logging.info(f"Checking for new logs since last file position: {last_position}")
        try:
            with open(LOG_FILE, 'r', errors='ignore') as f:
                f.seek(last_position)
                log_count = 0
                while log_count < state.settings['log_batch_size']:
                    line = f.readline()
                    if not line:
                        break
                    try:
                        logs_to_process.append(json.loads(line.strip()))
                        log_count += 1
                    except json.JSONDecodeError:
                        continue
                current_position = f.tell()
            logging.info(f"Found {len(logs_to_process)} new logs since last position")
        except Exception as e:
            logging.error(f"Error reading logs: {e}")
            return []
    
    set_log_position(current_position)
    
    if logs_to_process:
        logging.info(f"Processing {len(logs_to_process)} logs for vector storage...")
        await add_to_vector_db(logs_to_process)
        save_vector_db()
    else:
        logging.info("No new logs found in this cycle.")
    
    state.dashboard_data["stats"]["new_logs"] = len(logs_to_process)
    state.dashboard_data["stats"]["total_logs"] = state.vector_db.ntotal if state.vector_db else 0
    await save_dashboard_data()
    return logs_to_process


def update_dashboard_metrics(logs: List[Dict[str, Any]]) -> None:
    """Update log trend and rule distribution metrics based on new logs."""
    now = datetime.now()
    trend = state.dashboard_data.get("log_trend", [])
    current_minute = now.strftime("%H:%M")
    if trend and trend[-1]["time"] == current_minute:
        trend[-1]["count"] += len(logs)
    else:
        trend.append({"time": current_minute, "count": len(logs)})
    state.dashboard_data["log_trend"] = trend[-60:]
    
    # Update rule distribution
    dist = state.dashboard_data.get("rule_distribution", {})
    for log in logs:
        rule_desc = log.get("rule", {}).get("description", "Unknown Rule")
        dist[rule_desc] = dist.get(rule_desc, 0) + 1
    state.dashboard_data["rule_distribution"] = dist