"""
Persistence helpers for Threat Hunter.

This module contains asynchronous and synchronous functions for
loading and saving the dashboard data, settings and the ignored
issue list to disk. Functions here are called by the worker and
API endpoints to ensure that state survives application restarts.
"""

from __future__ import annotations

import json
import os
import logging
from typing import Dict, Any

import aiofiles

import state
from config import (
    DASHBOARD_DATA_FILE,
    SETTINGS_FILE,
    IGNORED_ISSUES_FILE,
    DEFAULT_SETTINGS,
)

__all__ = [
    'load_dashboard_data', 'save_dashboard_data',
    'load_settings', 'save_settings',
    'load_ignored_issues', 'save_ignored_issues'
]


async def load_dashboard_data() -> None:
    """Load persisted dashboard data from disk into state.dashboard_data."""
    if os.path.exists(DASHBOARD_DATA_FILE):
        try:
            async with aiofiles.open(DASHBOARD_DATA_FILE, 'r') as f:
                loaded = json.loads(await f.read())
                state.dashboard_data.update(loaded)
            logging.info("Loaded dashboard data from file.")
        except Exception as e:
            logging.error(f"Failed to load dashboard data: {e}")


async def save_dashboard_data() -> None:
    """Persist the current dashboard data to disk."""
    try:
        async with state.vector_lock:
            async with aiofiles.open(DASHBOARD_DATA_FILE, 'w') as f:
                await f.write(json.dumps(state.dashboard_data))
        logging.info("Saved dashboard data to file.")
    except Exception as e:
        logging.error(f"Failed to save dashboard data: {e}")


def load_settings() -> None:
    """Load settings from disk and merge them into state.settings."""
    if os.path.exists(SETTINGS_FILE):
        try:
            with open(SETTINGS_FILE, 'r') as f:
                loaded = json.load(f)
                # Only update keys that exist in DEFAULT_SETTINGS to avoid
                # persisting arbitrary values.
                settings_to_update = {k: v for k, v in loaded.items() if k in DEFAULT_SETTINGS}
                
                # Migration: Update old 5-minute interval (300s) to new 10-minute interval (600s)
                migrated = False
                if settings_to_update.get("processing_interval") == 300:
                    logging.info("Migrating processing_interval from 5 minutes to 10 minutes")
                    settings_to_update["processing_interval"] = 600
                    migrated = True
                
                state.settings.update(settings_to_update)
                
                # Save migrated settings back to disk
                if migrated:
                    save_settings()
            logging.info("Loaded settings from file.")
        except Exception as e:
            logging.error(f"Failed to load settings: {e}")


def save_settings() -> None:
    """Persist the current settings to disk."""
    try:
        with open(SETTINGS_FILE, 'w') as f:
            json.dump(state.settings, f)
        logging.info("Saved settings to file.")
    except Exception as e:
        logging.error(f"Failed to save settings: {e}")


def load_ignored_issues() -> None:
    """Load the list of ignored issues from disk into state.ignored_issue_ids."""
    if os.path.exists(IGNORED_ISSUES_FILE):
        try:
            with open(IGNORED_ISSUES_FILE, 'r') as f:
                state.ignored_issue_ids = set(json.load(f))
            logging.info(f"Loaded {len(state.ignored_issue_ids)} ignored issues from file.")
        except Exception as e:
            logging.error(f"Failed to load ignored issues: {e}")


def save_ignored_issues() -> None:
    """Save the current list of ignored issues to disk."""
    try:
        with open(IGNORED_ISSUES_FILE, 'w') as f:
            json.dump(list(state.ignored_issue_ids), f)
        logging.info(f"Saved {len(state.ignored_issue_ids)} ignored issues to file.")
    except Exception as e:
        logging.error(f"Failed to save ignored issues: {e}")