"""
Configuration settings for TelemetryLab Detection Engineering Playground.
"""
import os
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.getenv("TELEMETRY_DB_PATH", BASE_DIR / "telemetry.db"))
SCHEMA_FILE = BASE_DIR / "schema" / "schema.sql"
RULES_DIR = BASE_DIR / "rules"
RULES_MANIFEST = RULES_DIR / "rules_manifest.json"
SAMPLE_DATA_DIR = BASE_DIR / "sample_data"
WEB_DIR = BASE_DIR / "web"

# Server Settings
DEFAULT_HOST = os.getenv("TELEMETRY_HOST", "127.0.0.1")
DEFAULT_PORT = int(os.getenv("TELEMETRY_PORT", "8888"))

# SQLite Performance Pragma Settings
SQLITE_PRAGMAS = [
    "PRAGMA journal_mode = WAL;",       # Write-Ahead Logging for high concurrency & speed
    "PRAGMA synchronous = NORMAL;",     # Balanced safety and high throughput
    "PRAGMA foreign_keys = ON;",
    "PRAGMA busy_timeout = 5000;",      # 5s retry on locks
]
