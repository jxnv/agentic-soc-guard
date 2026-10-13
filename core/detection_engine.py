"""
Detection Engineering Engine and Rule Evaluation Runner for TelemetryLab.
Executes SQL detection rules against local telemetry, assesses lifecycle stages,
evaluates rule tuning exclusions, and generates MITRE ATT&CK coverage analytics.
"""
import json
import uuid
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional

import config
from core.database import get_connection, execute_query


def sync_rules_to_db(db_path: Optional[Path] = None) -> int:
    """
    Syncs detection rules from rules_manifest.json into SQLite detection_rules table.
    """
    if not config.RULES_MANIFEST.exists():
        return 0
        
    with open(config.RULES_MANIFEST, "r", encoding="utf-8") as f:
        rules = json.load(f)
        
    conn = get_connection(db_path)
    cursor = conn.cursor()
    
    count = 0
    for r in rules:
        cursor.execute("""
            INSERT INTO detection_rules (
                rule_id, name, severity, mitre_attack_id, mitre_tactic,
                mitre_technique, description, sql_query, threshold,
                lifecycle_stage, status, tune_exclusions
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(rule_id) DO UPDATE SET
                name=excluded.name,
                severity=excluded.severity,
                mitre_attack_id=excluded.mitre_attack_id,
                mitre_tactic=excluded.mitre_tactic,
                mitre_technique=excluded.mitre_technique,
                description=excluded.description,
                sql_query=excluded.sql_query,
                lifecycle_stage=excluded.lifecycle_stage,
                tune_exclusions=excluded.tune_exclusions;
        """, (
            r["rule_id"], r["name"], r["severity"], r.get("mitre_attack_id"),
            r.get("mitre_tactic"), r.get("mitre_technique"), r.get("description"),
            r["sql_query"], r.get("threshold", 1), r.get("lifecycle_stage", "Active"),
            r.get("status", "ENABLED"), r.get("tune_exclusions", "")
        ))
        count += 1
        
    conn.commit()
    conn.close()
    return count


def get_all_rules(db_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Fetches all rules from detection_rules table."""
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM detection_rules ORDER BY rule_id ASC;")
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    
    if not rows and config.RULES_MANIFEST.exists():
        sync_rules_to_db(db_path)
        return get_all_rules(db_path)
        
    return rows


def get_rule_by_id(rule_id: str, db_path: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    """Fetches a specific detection rule by ID."""
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM detection_rules WHERE rule_id = ?;", (rule_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def run_rule(
    rule_id: str,
    record_alerts: bool = True,
    apply_tuning: bool = False,
    run_id: Optional[str] = None,
    db_path: Optional[Path] = None
) -> Dict[str, Any]:
    """
    Executes a specific detection rule against the database.
    Optionally applies tune_exclusions filters and logs matches into detection_alerts.
    """
    rule = get_rule_by_id(rule_id, db_path)
    if not rule:
        return {"success": False, "error": f"Rule not found: {rule_id}"}
        
    sql = rule["sql_query"].strip()
    if apply_tuning and rule.get("tune_exclusions"):
        # If tuning exclusion is present and starts with AND, append it before semicolon if present
        clean_sql = sql.rstrip(";").strip()
        sql = f"{clean_sql} {rule['tune_exclusions']};"
        
    query_result = execute_query(sql, db_path=db_path)
    if not query_result["success"]:
        return {
            "success": False,
            "rule_id": rule_id,
            "rule_name": rule["name"],
            "error": query_result.get("error"),
            "execution_time_ms": query_result.get("execution_time_ms")
        }
        
    matches = query_result.get("rows", [])
    alerts_recorded = 0
    actual_run_id = run_id or f"run_{uuid.uuid4().hex[:8]}"
    
    if record_alerts and matches:
        conn = get_connection(db_path)
        cursor = conn.cursor()
        now = datetime.now(timezone.utc).isoformat()
        
        for m in matches:
            # Extract common entity fields if available
            entity_host = m.get("host_name") or m.get("device_name") or m.get("src_ip")
            entity_user = m.get("user_name") or m.get("actor") or m.get("targeted_users")
            record_id = m.get("id")
            
            cursor.execute("""
                INSERT INTO detection_alerts (
                    run_id, rule_id, rule_name, severity, alert_time,
                    matched_record_id, entity_host, entity_user, context_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                actual_run_id, rule["rule_id"], rule["name"], rule["severity"],
                now, record_id, entity_host, entity_user, json.dumps(m)
            ))
            alerts_recorded += 1
            
        conn.commit()
        conn.close()
        
    return {
        "success": True,
        "run_id": actual_run_id,
        "rule_id": rule_id,
        "rule_name": rule["name"],
        "severity": rule["severity"],
        "mitre_attack_id": rule.get("mitre_attack_id"),
        "mitre_tactic": rule.get("mitre_tactic"),
        "alert_count": len(matches),
        "execution_time_ms": query_result.get("execution_time_ms"),
        "matches": matches,
        "tuning_applied": apply_tuning
    }


def run_all_rules(record_alerts: bool = True, db_path: Optional[Path] = None) -> Dict[str, Any]:
    """
    Executes all enabled detection rules in the catalog.
    Returns comprehensive batch test summary.
    """
    rules = get_all_rules(db_path)
    run_id = f"batch_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:4]}"
    
    results = []
    total_alerts = 0
    total_time_ms = 0.0
    
    for r in rules:
        if r.get("status") == "DISABLED":
            continue
        res = run_rule(r["rule_id"], record_alerts=record_alerts, run_id=run_id, db_path=db_path)
        results.append(res)
        if res.get("success"):
            total_alerts += res.get("alert_count", 0)
            total_time_ms += res.get("execution_time_ms", 0.0)
            
    return {
        "run_id": run_id,
        "total_rules_evaluated": len(results),
        "total_alerts_produced": total_alerts,
        "total_execution_time_ms": round(total_time_ms, 2),
        "rule_results": results
    }


def tune_rule_benchmark(rule_id: str, db_path: Optional[Path] = None) -> Dict[str, Any]:
    """
    Benchmarks rule noise reduction before and after tuning exclusions.
    Calculates False Positive suppression metrics.
    """
    rule = get_rule_by_id(rule_id, db_path)
    if not rule:
        return {"success": False, "error": f"Rule not found: {rule_id}"}
        
    raw_res = run_rule(rule_id, record_alerts=False, apply_tuning=False, db_path=db_path)
    tuned_res = run_rule(rule_id, record_alerts=False, apply_tuning=True, db_path=db_path)
    
    raw_count = raw_res.get("alert_count", 0)
    tuned_count = tuned_res.get("alert_count", 0)
    suppressed = max(0, raw_count - tuned_count)
    suppression_pct = round((suppressed / raw_count * 100), 1) if raw_count > 0 else 0.0
    
    return {
        "rule_id": rule_id,
        "rule_name": rule["name"],
        "raw_alert_count": raw_count,
        "tuned_alert_count": tuned_count,
        "alerts_suppressed": suppressed,
        "noise_reduction_percentage": suppression_pct,
        "tune_exclusions": rule.get("tune_exclusions", "")
    }


def get_mitre_coverage(db_path: Optional[Path] = None) -> Dict[str, Any]:
    """
    Generates MITRE ATT&CK coverage breakdown across tactics and techniques.
    """
    rules = get_all_rules(db_path)
    
    tactic_map: Dict[str, List[Dict[str, Any]]] = {}
    for r in rules:
        tactic = r.get("mitre_tactic") or "Unknown"
        if tactic not in tactic_map:
            tactic_map[tactic] = []
        tactic_map[tactic].append({
            "rule_id": r["rule_id"],
            "name": r["name"],
            "technique_id": r.get("mitre_attack_id"),
            "technique_name": r.get("mitre_technique"),
            "severity": r["severity"],
            "lifecycle_stage": r.get("lifecycle_stage")
        })
        
    return {
        "total_rules": len(rules),
        "tactics_covered": len(tactic_map),
        "coverage": tactic_map
    }
