"""
Baseline Store: SQLite query interface for investigating normal enterprise
activity, host behaviors, and process baselines in telemetry.db.
"""
from __future__ import annotations

import sqlite3
import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

import config
from core.database import get_connection


class BaselineStore:
    """
    Connects to the enterprise telemetry database (telemetry.db) to extract
    historical process frequencies, identity patterns, and network baselines.
    """

    KNOWN_SERVICE_ACCOUNTS = {
        "system_deployer",
        "svc_backup",
        "svc_scanner",
        "svc-ansible",
        "system",
        "nt authority\\system",
        "deploy_bot",
    }

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or config.DB_PATH
        self._ensure_triage_table()

    def _get_conn(self) -> sqlite3.Connection:
        """Returns SQLite connection with security UDFs registered."""
        return get_connection(self.db_path)

    def _ensure_triage_table(self) -> None:
        """Creates the autonomous triage audit table if not present."""
        try:
            conn = self._get_conn()
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS autonomous_triage_log (
                    triage_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_id TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    confidence_score REAL NOT NULL,
                    root_cause_analysis TEXT NOT NULL,
                    mitre_mapping TEXT NOT NULL,
                    immediate_containment_action TEXT,
                    analyst_notes TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
            conn.close()
        except Exception:
            pass

    def count_command_occurrences(self, command_line: str, user_name: Optional[str] = None) -> int:
        """
        Calculates how many times this command (or similar) has executed
        in the historical telemetry baseline.
        """
        if not command_line:
            return 0

        conn = self._get_conn()
        cursor = conn.cursor()
        cmd_clean = command_line.strip()

        try:
            if user_name:
                cursor.execute(
                    """
                    SELECT COUNT(*) FROM endpoint_process
                    WHERE (command_line = ? OR command_line LIKE ?)
                      AND LOWER(user_name) = LOWER(?)
                    """,
                    (cmd_clean, f"%{cmd_clean[:40]}%", user_name.strip())
                )
            else:
                cursor.execute(
                    """
                    SELECT COUNT(*) FROM endpoint_process
                    WHERE command_line = ? OR command_line LIKE ?
                    """,
                    (cmd_clean, f"%{cmd_clean[:40]}%")
                )
            row = cursor.fetchone()
            count = row[0] if row else 0
        except Exception:
            count = 0
        finally:
            conn.close()

        return count

    def get_user_activity_summary(self, user_name: str) -> Dict[str, Any]:
        """
        Retrieves user behavior profile: distinct processes, hosts, and logon status.
        """
        conn = self._get_conn()
        cursor = conn.cursor()
        user_norm = user_name.strip().lower()

        summary: Dict[str, Any] = {
            "user_name": user_name,
            "is_known_service_account": user_norm in self.KNOWN_SERVICE_ACCOUNTS,
            "total_process_events": 0,
            "top_processes": [],
            "distinct_hosts": [],
            "failed_logins_count": 0,
        }

        try:
            # Process history
            cursor.execute(
                """
                SELECT process_name, COUNT(*) as cnt 
                FROM endpoint_process 
                WHERE LOWER(user_name) = ?
                GROUP BY process_name 
                ORDER BY cnt DESC LIMIT 5
                """,
                (user_norm,)
            )
            summary["top_processes"] = [f"{r[0]} ({r[1]}x)" for r in cursor.fetchall()]

            # Distinct hosts
            cursor.execute(
                "SELECT DISTINCT host_name FROM endpoint_process WHERE LOWER(user_name) = ?",
                (user_norm,)
            )
            summary["distinct_hosts"] = [r[0] for r in cursor.fetchall()]

            # Auth failures
            cursor.execute(
                "SELECT COUNT(*) FROM identity_auth WHERE LOWER(user_name) = ? AND auth_status = 'FAILURE'",
                (user_norm,)
            )
            row = cursor.fetchone()
            summary["failed_logins_count"] = row[0] if row else 0
        except Exception:
            pass
        finally:
            conn.close()

        return summary

    def check_ip_reputation_baseline(self, ip_str: str) -> Dict[str, Any]:
        """
        Checks if an IP has historical internal network traffic or authentication logs.
        """
        conn = self._get_conn()
        cursor = conn.cursor()
        ip_clean = ip_str.strip()

        stats = {
            "ip": ip_clean,
            "historical_network_flows": 0,
            "historical_auth_events": 0,
        }

        try:
            cursor.execute(
                "SELECT COUNT(*) FROM network_flow WHERE src_ip = ? OR dst_ip = ?",
                (ip_clean, ip_clean)
            )
            row = cursor.fetchone()
            stats["historical_network_flows"] = row[0] if row else 0

            cursor.execute(
                "SELECT COUNT(*) FROM identity_auth WHERE src_ip = ?",
                (ip_clean,)
            )
            row = cursor.fetchone()
            stats["historical_auth_events"] = row[0] if row else 0
        except Exception:
            pass
        finally:
            conn.close()

        return stats

    def get_alert_by_id(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """
        Fetches an alert record from detection_alerts by rule_id or alert_id.
        """
        conn = self._get_conn()
        cursor = conn.cursor()
        record = None

        try:
            cursor.execute(
                """
                SELECT alert_id, run_id, rule_id, rule_name, severity, alert_time,
                       entity_host, entity_user, context_json
                FROM detection_alerts
                WHERE rule_id = ? OR CAST(alert_id AS TEXT) = ?
                ORDER BY alert_id DESC LIMIT 1
                """,
                (alert_id, alert_id)
            )
            row = cursor.fetchone()
            if row:
                ctx = {}
                if row["context_json"]:
                    try:
                        ctx = json.loads(row["context_json"])
                    except Exception:
                        ctx = {"raw": row["context_json"]}
                record = {
                    "alert_id": str(row["rule_id"]),
                    "db_alert_id": row["alert_id"],
                    "rule_name": row["rule_name"],
                    "severity": row["severity"],
                    "timestamp": row["alert_time"],
                    "host": row["entity_host"],
                    "user": row["entity_user"],
                    "context": ctx,
                }
        except Exception:
            pass
        finally:
            conn.close()

        return record

    def record_triage_verdict(self, verdict_dict: Dict[str, Any]) -> bool:
        """
        Persists autonomous triage verdict into autonomous_triage_log table.
        """
        try:
            conn = self._get_conn()
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO autonomous_triage_log
                (alert_id, verdict, confidence_score, root_cause_analysis, mitre_mapping,
                 immediate_containment_action, analyst_notes)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    verdict_dict.get("alert_id", "ALT-UNKNOWN"),
                    verdict_dict.get("verdict", "SUSPICIOUS_FURTHER_INVESTIGATION"),
                    verdict_dict.get("confidence_score", 0.5),
                    verdict_dict.get("root_cause_analysis", ""),
                    json.dumps(verdict_dict.get("mitre_mapping", [])),
                    verdict_dict.get("immediate_containment_action"),
                    verdict_dict.get("analyst_investigation_notes", ""),
                )
            )
            conn.commit()
            conn.close()
            return True
        except Exception:
            return False
