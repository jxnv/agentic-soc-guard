"""
Data Ingestion and Live Stream Simulator for TelemetryLab.
Allows importing external CSV, JSON, and JSONL data into SQLite tables,
and simulates live telemetry streams for real-time detection testing.
"""
import csv
import json
import time
import threading
from pathlib import Path
from typing import Dict, Any, List, Optional

from core.database import get_connection, get_tables
from core.generator import generate_telemetry


def _infer_sql_type(value: Any) -> str:
    """Infers SQLite column type from a string or python value."""
    if value is None or value == "":
        return "TEXT"
    val_str = str(value).strip()
    if val_str.isdigit() or (val_str.startswith("-") and val_str[1:].isdigit()):
        return "INTEGER"
    try:
        float(val_str)
        return "REAL"
    except ValueError:
        pass
    return "TEXT"


def ingest_csv(
    file_path: Path,
    table_name: str,
    create_if_missing: bool = True,
    db_path: Optional[Path] = None
) -> Dict[str, Any]:
    """
    Ingests a CSV file into a SQLite table.
    If table does not exist and create_if_missing=True, automatically creates schema.
    """
    csv_path = Path(file_path)
    if not csv_path.exists():
        return {"success": False, "error": f"File not found: {csv_path}"}
        
    conn = get_connection(db_path)
    cursor = conn.cursor()
    
    with open(csv_path, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        fieldnames = [fn.strip() for fn in (reader.fieldnames or [])]
        if not fieldnames:
            conn.close()
            return {"success": False, "error": "CSV contains no header row"}
            
        rows = list(reader)
        
    if not rows:
        conn.close()
        return {"success": True, "rows_inserted": 0, "table": table_name}
        
    # Check if table exists
    existing_tables = [t["name"] for t in get_tables(db_path)]
    if table_name not in existing_tables:
        if not create_if_missing:
            conn.close()
            return {"success": False, "error": f"Table '{table_name}' does not exist"}
            
        # Infer types from first non-empty values
        col_defs = ["id INTEGER PRIMARY KEY AUTOINCREMENT"]
        for col in fieldnames:
            sample_val = next((r[col] for r in rows if r.get(col)), None)
            col_type = _infer_sql_type(sample_val)
            col_defs.append(f'"{col}" {col_type}')
            
        create_sql = f'CREATE TABLE "{table_name}" ({", ".join(col_defs)});'
        cursor.execute(create_sql)
        
    # Insert rows
    quoted_cols = [f'"{col}"' for col in fieldnames]
    placeholders = ", ".join(["?"] * len(fieldnames))
    insert_sql = f'INSERT INTO "{table_name}" ({", ".join(quoted_cols)}) VALUES ({placeholders});'
    
    data_tuples = [
        tuple(row.get(col, None) for col in fieldnames)
        for row in rows
    ]
    
    cursor.executemany(insert_sql, data_tuples)
    conn.commit()
    conn.close()
    
    return {
        "success": True,
        "table": table_name,
        "rows_inserted": len(rows),
        "columns": fieldnames
    }


def ingest_json(
    file_path: Path,
    table_name: str,
    create_if_missing: bool = True,
    db_path: Optional[Path] = None
) -> Dict[str, Any]:
    """
    Ingests standard JSON array or line-delimited JSON (JSONL/NDJSON) into a SQLite table.
    """
    json_path = Path(file_path)
    if not json_path.exists():
        return {"success": False, "error": f"File not found: {json_path}"}
        
    rows = []
    with open(json_path, "r", encoding="utf-8") as f:
        content = f.read().strip()
        if content.startswith("["):
            try:
                rows = json.loads(content)
            except Exception as e:
                return {"success": False, "error": f"Invalid JSON array: {e}"}
        else:
            # Assume JSON Lines
            for line_no, line in enumerate(content.splitlines(), start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except Exception as e:
                    return {"success": False, "error": f"Invalid JSON at line {line_no}: {e}"}
                    
    if not rows:
        return {"success": True, "rows_inserted": 0, "table": table_name}
        
    # Get all distinct keys
    fieldnames = list({k for row in rows for k in row.keys()})
    
    conn = get_connection(db_path)
    cursor = conn.cursor()
    
    existing_tables = [t["name"] for t in get_tables(db_path)]
    if table_name not in existing_tables:
        if not create_if_missing:
            conn.close()
            return {"success": False, "error": f"Table '{table_name}' does not exist"}
            
        col_defs = ["id INTEGER PRIMARY KEY AUTOINCREMENT"]
        for col in fieldnames:
            sample_val = next((r.get(col) for r in rows if r.get(col) is not None), None)
            col_type = _infer_sql_type(sample_val)
            col_defs.append(f'"{col}" {col_type}')
            
        cursor.execute(f'CREATE TABLE "{table_name}" ({", ".join(col_defs)});')
        
    quoted_cols = [f'"{col}"' for col in fieldnames]
    placeholders = ", ".join(["?"] * len(fieldnames))
    insert_sql = f'INSERT INTO "{table_name}" ({", ".join(quoted_cols)}) VALUES ({placeholders});'
    
    data_tuples = [
        tuple(
            json.dumps(row[col]) if isinstance(row.get(col), (dict, list)) else row.get(col)
            for col in fieldnames
        )
        for row in rows
    ]
    
    cursor.executemany(insert_sql, data_tuples)
    conn.commit()
    conn.close()
    
    return {
        "success": True,
        "table": table_name,
        "rows_inserted": len(rows),
        "columns": fieldnames
    }


def stream_event(
    table_name: str,
    record: Dict[str, Any],
    db_path: Optional[Path] = None
) -> Dict[str, Any]:
    """
    Inserts a single event into a table (simulating real-time ingest pipeline or webhook).
    """
    conn = get_connection(db_path)
    cursor = conn.cursor()
    
    keys = list(record.keys())
    quoted_keys = [f'"{k}"' for k in keys]
    placeholders = ", ".join(["?"] * len(keys))
    values = tuple(
        json.dumps(record[k]) if isinstance(record[k], (dict, list)) else record[k]
        for k in keys
    )
    
    try:
        sql = f'INSERT INTO "{table_name}" ({", ".join(quoted_keys)}) VALUES ({placeholders});'
        cursor.execute(sql, values)
        event_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return {"success": True, "table": table_name, "id": event_id}
    except Exception as e:
        conn.close()
        return {"success": False, "error": str(e)}


# Global stream simulator state
_simulator_thread: Optional[threading.Thread] = None
_simulator_stop_event = threading.Event()
_simulator_status = {"running": False, "events_produced": 0, "interval_sec": 3}


def start_stream_simulator(interval_sec: float = 3.0, db_path: Optional[Path] = None) -> Dict[str, Any]:
    """Starts background simulated telemetry event streaming into SQLite."""
    global _simulator_thread, _simulator_stop_event, _simulator_status
    
    if _simulator_thread and _simulator_thread.is_alive():
        return {"status": "already_running", "stats": _simulator_status}
        
    _simulator_stop_event.clear()
    _simulator_status["running"] = True
    _simulator_status["interval_sec"] = interval_sec
    
    def _worker():
        while not _simulator_stop_event.is_set():
            try:
                generate_telemetry(num_benign=3, inject_attacks=False, days_back=0, db_path=db_path)
                _simulator_status["events_produced"] += 10
            except Exception:
                pass
            _simulator_stop_event.wait(interval_sec)
        _simulator_status["running"] = False
        
    _simulator_thread = threading.Thread(target=_worker, daemon=True)
    _simulator_thread.start()
    return {"status": "started", "interval_sec": interval_sec}


def stop_stream_simulator() -> Dict[str, Any]:
    """Stops the live telemetry streaming simulator."""
    global _simulator_stop_event, _simulator_status
    _simulator_stop_event.set()
    _simulator_status["running"] = False
    return {"status": "stopped", "stats": _simulator_status}


def get_simulator_status() -> Dict[str, Any]:
    """Returns current live stream simulator status."""
    return _simulator_status
