# Threat Hunter Pro (Gemini Edition)
#
# This package contains a refactored implementation of the monolithic
# Wazuh Threat Hunter Pro script provided by the user. The code has
# been modularised to improve readability, maintainability and ease of
# distribution. Each module encapsulates a specific area of
# functionality while preserving the original behaviour.

# The main entry point for running the application is in
# ``threat_hunter/main.py``. Refer to that module if you wish to
# start the FastAPI server using Uvicorn as in the original script.

# Modules included in this package:
#
# - config.py        : Configuration constants and environment handling
# - html_template.py : Contains the HTML/JS/CSS for the dashboard UI
# - models.py        : Pydantic models for API payloads
# - token_bucket.py  : Simple token bucket implementation for rate limiting
# - metrics.py       : Prometheus-style metrics collector
# - state.py         : Global state container and helpers
# - persistence.py   : Functions for loading and saving persistent data
# - vector_db.py     : Vector database management and search functions
# - log_processing.py: Log file reading, deduplication and vectorisation
# - ai_logic.py      : AI interaction logic (Gemini API calls and analysis)
# - worker.py        : Background worker to process logs and run analyses
# - app.py           : FastAPI application with all API routes
# - main.py          : Program entry point, starts the server and worker

# Nothing is executed on import of this package; see ``main.py`` for
# application startup.