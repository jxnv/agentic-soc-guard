#!/usr/bin/env python3
"""
TelemetryLab - Detection Engineering & Telemetry Playground
Main Application Entrypoint.

Usage:
    python3 app.py                 # Starts Web UI on http://127.0.0.1:8888
    python3 app.py --port 9000     # Custom port
    python3 app.py --no-browser    # Do not auto-open browser
    python3 app.py --cli [args]    # Delegate to CLI
"""
import sys
import webbrowser
import argparse
import threading
import time

import config
from core.database import init_database, get_tables
from core.generator import generate_telemetry
from core.detection_engine import sync_rules_to_db
from server import run_server


def auto_bootstrap():
    """Ensures database is initialized and seeded on first run."""
    if not config.DB_PATH.exists() or len(get_tables()) == 0:
        print("[*] First run detected: Initializing database schema...")
        init_database()
        sync_rules_to_db()
        print("[*] Generating starter telemetry (300 events + attack scenarios)...")
        generate_telemetry(num_benign=300, inject_attacks=True)
        print("[+] Ready!\n")


def main():
    parser = argparse.ArgumentParser(description="TelemetryLab: SQLite Detection Engineering Playground")
    parser.add_argument("--host", default=config.DEFAULT_HOST, help="Server bind host")
    parser.add_argument("--port", type=int, default=config.DEFAULT_PORT, help="Server port (default: 8888)")
    parser.add_argument("--no-browser", action="store_true", help="Do not automatically launch web browser")
    parser.add_argument("--cli", nargs=argparse.REMAINDER, help="Pass arguments directly to CLI")

    args = parser.parse_args()

    # Delegate to CLI if --cli is passed
    if args.cli is not None:
        import cli
        sys.argv = ["cli.py"] + args.cli
        cli.main()
        return

    # Bootstrap DB if needed
    auto_bootstrap()

    url = f"http://{args.host}:{args.port}"

    # Auto-open browser in background
    if not args.no_browser:
        def open_tab():
            time.sleep(1.0)
            webbrowser.open(url)
        threading.Thread(target=open_tab, daemon=True).start()

    # Launch server
    run_server(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
