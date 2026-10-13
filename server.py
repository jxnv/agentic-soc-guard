"""
Lightweight Web Server and REST API for TelemetryLab.
Runs on Python standard library (http.server) with zero external pip dependencies.
Provides REST endpoints for SQL execution, rule testing, mass schema renaming,
data ingestion, and live telemetry streaming.
"""
import http.server
import socketserver
import json
import urllib.parse
from pathlib import Path
from typing import Dict, Any

import config
from core.database import (
    get_tables, get_table_schema, execute_query, export_dump, init_database
)
from core.generator import generate_telemetry
from core.schema_manager import (
    rename_column, rename_table, mass_rename_columns,
    mass_rename_by_pattern, apply_preset_normalization
)
from core.detection_engine import (
    sync_rules_to_db, get_all_rules, get_rule_by_id, run_rule,
    run_all_rules, tune_rule_benchmark, get_mitre_coverage
)
from core.ingest import (
    ingest_csv, ingest_json, start_stream_simulator,
    stop_stream_simulator, get_simulator_status
)


class TelemetryLabHandler(http.server.SimpleHTTPRequestHandler):
    """Custom request handler with REST API routing and static file delivery."""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(config.WEB_DIR), **kwargs)

    def _send_json(self, data: Any, status_code: int = 200):
        body = json.dumps(data, default=str).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self) -> Dict[str, Any]:
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length > 0:
                raw_data = self.rfile.read(content_length).decode("utf-8")
                return json.loads(raw_data)
        except Exception:
            pass
        return {}

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        # REST API Routes
        if path == "/api/tables":
            tables = get_tables()
            self._send_json({"success": True, "tables": tables})
            return

        elif path == "/api/rules":
            sync_rules_to_db()
            rules = get_all_rules()
            self._send_json({"success": True, "rules": rules})
            return

        elif path == "/api/mitre":
            sync_rules_to_db()
            cov = get_mitre_coverage()
            self._send_json({"success": True, "data": cov})
            return

        elif path == "/api/stream/status":
            status = get_simulator_status()
            self._send_json({"success": True, "status": status})
            return

        elif path == "/api/export/dump":
            dump_res = export_dump(config.BASE_DIR / "seed.sql")
            self._send_json({"success": True, "dump": dump_res})
            return

        elif path == "/api/guard/spans":
            spans_path = config.BASE_DIR / "sample_data" / "otel_spans.json"
            if spans_path.exists():
                with open(spans_path, "r", encoding="utf-8") as f:
                    spans = json.load(f)
                self._send_json({"success": True, "count": len(spans), "spans": spans})
            else:
                self._send_json({"success": True, "count": 0, "spans": []})
            return

        elif path == "/api/triage/alerts":
            alerts_path = config.BASE_DIR / "sample_data" / "raw_alerts.json"
            if alerts_path.exists():
                with open(alerts_path, "r", encoding="utf-8") as f:
                    alerts = json.load(f)
                self._send_json({"success": True, "count": len(alerts), "alerts": alerts})
            else:
                self._send_json({"success": True, "count": 0, "alerts": []})
            return

        # Serve static assets (HTML/CSS/JS)
        super().do_GET()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        payload = self._read_json_body()

        if path == "/api/query":
            sql = payload.get("sql", "").strip()
            limit = payload.get("limit", 1000)
            if not sql:
                self._send_json({"success": False, "error": "Query cannot be empty"}, status_code=400)
                return
            res = execute_query(sql, max_rows=limit)
            self._send_json(res)
            return

        elif path == "/api/rules/run":
            rule_id = payload.get("rule_id")
            apply_tune = payload.get("apply_tuning", False)
            if rule_id:
                res = run_rule(rule_id, record_alerts=True, apply_tuning=apply_tune)
            else:
                res = run_all_rules(record_alerts=True)
            self._send_json(res)
            return

        elif path == "/api/rules/benchmark":
            rule_id = payload.get("rule_id")
            if not rule_id:
                self._send_json({"success": False, "error": "rule_id required"}, status_code=400)
                return
            res = tune_rule_benchmark(rule_id)
            self._send_json(res)
            return

        elif path == "/api/schema/rename-column":
            table = payload.get("table")
            old_col = payload.get("old_col")
            new_col = payload.get("new_col")
            if not (table and old_col and new_col):
                self._send_json({"success": False, "error": "table, old_col, and new_col required"}, status_code=400)
                return
            res = rename_column(table, old_col, new_col)
            self._send_json(res)
            return

        elif path == "/api/schema/rename-table":
            old_table = payload.get("old_table")
            new_table = payload.get("new_table")
            if not (old_table and new_table):
                self._send_json({"success": False, "error": "old_table and new_table required"}, status_code=400)
                return
            res = rename_table(old_table, new_table)
            self._send_json(res)
            return

        elif path == "/api/schema/pattern":
            pattern = payload.get("pattern", "")
            replacement = payload.get("replacement", "")
            scope = payload.get("scope", "column")
            dry_run = payload.get("dry_run", True)
            res = mass_rename_by_pattern(pattern, replacement, target_scope=scope, dry_run=dry_run)
            self._send_json(res)
            return

        elif path == "/api/schema/preset":
            preset = payload.get("preset", "ECS")
            dry_run = payload.get("dry_run", True)
            res = apply_preset_normalization(preset, dry_run=dry_run)
            self._send_json(res)
            return

        elif path == "/api/generator/seed":
            count = payload.get("count", 300)
            inject_attacks = payload.get("inject_attacks", True)
            res = generate_telemetry(num_benign=count, inject_attacks=inject_attacks)
            self._send_json(res)
            return

        elif path == "/api/stream/toggle":
            action = payload.get("action", "toggle")
            status = get_simulator_status()
            if action == "start" or (action == "toggle" and not status["running"]):
                res = start_stream_simulator(interval_sec=payload.get("interval", 3.0))
            else:
                res = stop_stream_simulator()
            self._send_json(res)
            return

        elif path == "/api/ingest/raw":
            data_type = payload.get("type", "csv")
            content = payload.get("content", "")
            target_table = payload.get("table", "imported_events")
            
            if not content.strip():
                self._send_json({"success": False, "error": "Content cannot be empty"}, status_code=400)
                return
                
            temp_path = config.BASE_DIR / f"temp_upload_{data_type}.tmp"
            try:
                with open(temp_path, "w", encoding="utf-8") as f:
                    f.write(content)
                    
                if data_type == "csv":
                    res = ingest_csv(temp_path, target_table)
                else:
                    res = ingest_json(temp_path, target_table)
            finally:
                if temp_path.exists():
                    temp_path.unlink()
                    
            self._send_json(res)
            return

        elif path == "/api/db/reset":
            init_database(force=True)
            sync_rules_to_db()
            self._send_json({"success": True, "message": "Database reset to clean schema"})
            return

        elif path == "/api/guard/simulate":
            from telemetry_guard.mock_agent_stream import generate_mock_telemetry_stream
            spans = generate_mock_telemetry_stream()
            self._send_json({"success": True, "spans_generated": len(spans)})
            return

        elif path == "/api/guard/detect":
            from telemetry_guard.mcp_tool_abuse_detector import MCPAgentDetector
            spans_path = config.BASE_DIR / "sample_data" / "otel_spans.json"
            if not spans_path.exists():
                from telemetry_guard.mock_agent_stream import generate_mock_telemetry_stream
                generate_mock_telemetry_stream()
            with open(spans_path, "r", encoding="utf-8") as f:
                spans = json.load(f)
            detector = MCPAgentDetector()
            alerts = detector.evaluate_span_stream(spans)
            saved = detector.save_alerts_to_sqlite(alerts)
            self._send_json({
                "success": True,
                "alerts_count": len(alerts),
                "persisted_count": saved,
                "alerts": [a.to_dict() for a in alerts]
            })
            return

        elif path == "/api/triage/run":
            from autonomous_triage.triage_agent import TriageEngine, find_alert
            alert_id = payload.get("alert_id")
            raw_alert = payload.get("alert")
            raw_alerts_path = config.BASE_DIR / "sample_data" / "raw_alerts.json"

            if not raw_alert and alert_id:
                raw_alert = find_alert(alert_id, raw_alerts_path)

            if not raw_alert:
                self._send_json({"success": False, "error": "Alert not found or provided"}, status_code=400)
                return

            engine = TriageEngine()
            brief = engine.triage_alert(raw_alert)
            self._send_json({
                "success": True,
                "alert_id": brief.alert_id,
                "verdict": brief.verdict.model_dump(),
                "iocs": brief.iocs.model_dump(),
                "baseline": brief.baseline.model_dump(),
                "enrichment": brief.enrichment.model_dump(),
                "ads_markdown": brief.ads_markdown_brief
            })
            return

        self._send_json({"error": "Endpoint not found"}, status_code=404)


def run_server(host: str = config.DEFAULT_HOST, port: int = config.DEFAULT_PORT):
    """Starts the HTTP server on specified host and port."""
    server_address = (host, port)
    
    # Allow port reuse immediately
    socketserver.TCPServer.allow_reuse_address = True
    
    with socketserver.TCPServer(server_address, TelemetryLabHandler) as httpd:
        print("=" * 70)
        print("TELEMETRYLAB: DETECTION ENGINEERING PLAYGROUND")
        print("=" * 70)
        print(f"[*] Local UI & Code Editor: http://{host}:{port}")
        print(f"[*] SQLite Database File:  {config.DB_PATH}")
        print(f"[*] Built-in UDF Functions: REGEXP(), ENTROPY(), IP_IN_CIDR()")
        print("=" * 70)
        print("[!] Press Ctrl+C to stop server.\n")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Shutting down TelemetryLab server.")


if __name__ == "__main__":
    run_server()
