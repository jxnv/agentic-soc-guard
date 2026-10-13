"""
Mass Schema Transformation and Normalization Engine for TelemetryLab.
Enables detection engineers to mass-update table names, column names,
apply regex transformations, and standardize schemas against ECS and OCSF presets.
"""
import re
import datetime
from typing import Dict, Any, List, Optional
from pathlib import Path

from core.database import get_connection, get_tables, get_table_schema


# Built-in Security Schema Normalization Presets
PRESET_MAPPINGS = {
    "ECS": {
        # Elastic Common Schema conventions (using valid SQL identifiers)
        "endpoint_process": {
            "command_line": "process_command_line",
            "parent_command_line": "process_parent_command_line",
            "parent_process_name": "process_parent_name",
            "parent_process_id": "process_parent_pid",
            "process_id": "process_pid",
            "process_hash_sha256": "process_hash_sha256"
        },
        "network_flow": {
            "src_ip": "source_ip",
            "src_port": "source_port",
            "dest_ip": "destination_ip",
            "dest_port": "destination_port",
            "bytes_sent": "source_bytes",
            "bytes_recv": "destination_bytes"
        },
        "network_http": {
            "src_ip": "source_ip",
            "dest_ip": "destination_ip",
            "uri": "url_path",
            "user_agent": "user_agent_original"
        },
        "endpoint_network": {
            "src_ip": "source_ip",
            "src_port": "source_port",
            "dest_ip": "destination_ip",
            "dest_port": "destination_port"
        }
    },
    "OCSF": {
        # Open Cybersecurity Schema Framework conventions
        "endpoint_process": {
            "host_name": "device_name",
            "user_name": "actor_user_name",
            "command_line": "process_cmd_line",
            "parent_process_name": "parent_process_name",
            "process_id": "process_pid"
        },
        "network_flow": {
            "src_ip": "src_endpoint_ip",
            "src_port": "src_endpoint_port",
            "dest_ip": "dst_endpoint_ip",
            "dest_port": "dst_endpoint_port"
        },
        "identity_auth": {
            "user_name": "actor_user_name",
            "src_ip": "src_endpoint_ip",
            "auth_status": "status_id",
            "failure_reason": "status_detail"
        }
    }
}


def rename_column(table_name: str, old_column: str, new_column: str, db_path: Optional[Path] = None) -> Dict[str, Any]:
    """Renames a single column in a table."""
    conn = get_connection(db_path)
    cursor = conn.cursor()
    
    try:
        sql = f'ALTER TABLE "{table_name}" RENAME COLUMN "{old_column}" TO "{new_column}";'
        cursor.execute(sql)
        
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        cursor.execute("""
            INSERT INTO schema_audit_log (timestamp, operation_type, target_table, old_value, new_value, status)
            VALUES (?, 'RENAME_COLUMN', ?, ?, ?, 'SUCCESS');
        """, (now, table_name, old_column, new_column))
        
        conn.commit()
        conn.close()
        return {"success": True, "table": table_name, "old_column": old_column, "new_column": new_column}
    except Exception as e:
        conn.close()
        return {"success": False, "error": str(e), "table": table_name, "old_column": old_column, "new_column": new_column}


def rename_table(old_table_name: str, new_table_name: str, db_path: Optional[Path] = None) -> Dict[str, Any]:
    """Renames a table in the database."""
    conn = get_connection(db_path)
    cursor = conn.cursor()
    
    try:
        sql = f'ALTER TABLE "{old_table_name}" RENAME TO "{new_table_name}";'
        cursor.execute(sql)
        
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        cursor.execute("""
            INSERT INTO schema_audit_log (timestamp, operation_type, target_table, old_value, new_value, status)
            VALUES (?, 'RENAME_TABLE', ?, ?, ?, 'SUCCESS');
        """, (now, new_table_name, old_table_name, new_table_name))
        
        conn.commit()
        conn.close()
        return {"success": True, "old_table": old_table_name, "new_table": new_table_name}
    except Exception as e:
        conn.close()
        return {"success": False, "error": str(e), "old_table": old_table_name, "new_table": new_table_name}


def mass_rename_columns(
    table_name: str,
    column_mapping: Dict[str, str],
    dry_run: bool = False,
    db_path: Optional[Path] = None
) -> Dict[str, Any]:
    """
    Mass renames columns in a specific table given a dictionary of {old_name: new_name}.
    Returns plan if dry_run=True, otherwise applies changes.
    """
    current_columns = [col["name"] for col in get_table_schema(table_name, db_path)]
    valid_changes = {}
    skipped = {}
    
    for old_col, new_col in column_mapping.items():
        if old_col in current_columns and old_col != new_col:
            valid_changes[old_col] = new_col
        else:
            skipped[old_col] = "Column not found or name unchanged"
            
    plan = {
        "table": table_name,
        "planned_renames": valid_changes,
        "skipped": skipped,
        "dry_run": dry_run
    }
    
    if dry_run or not valid_changes:
        return plan
        
    conn = get_connection(db_path)
    cursor = conn.cursor()
    applied = []
    failed = []
    
    try:
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        for old_col, new_col in valid_changes.items():
            try:
                cursor.execute(f'ALTER TABLE "{table_name}" RENAME COLUMN "{old_col}" TO "{new_col}";')
                cursor.execute("""
                    INSERT INTO schema_audit_log (timestamp, operation_type, target_table, old_value, new_value, status)
                    VALUES (?, 'RENAME_COLUMN', ?, ?, ?, 'SUCCESS');
                """, (now, table_name, old_col, new_col))
                applied.append({"old": old_col, "new": new_col})
            except Exception as e:
                failed.append({"old": old_col, "new": new_col, "error": str(e)})
                
        conn.commit()
    except Exception as e:
        conn.rollback()
        conn.close()
        return {"success": False, "error": str(e), "applied": applied, "failed": failed}
        
    conn.close()
    return {
        "success": True,
        "table": table_name,
        "applied": applied,
        "failed": failed
    }


def mass_rename_by_pattern(
    pattern: str,
    replacement: str,
    tables: Optional[List[str]] = None,
    target_scope: str = "column", # "column" or "table"
    dry_run: bool = False,
    db_path: Optional[Path] = None
) -> Dict[str, Any]:
    """
    Mass-renames columns or tables using regex pattern substitution.
    Example:
      pattern=r"^dest_", replacement="dst_", target_scope="column"
    """
    all_tables = get_tables(db_path)
    table_names = [t["name"] for t in all_tables]
    selected_tables = [t for t in table_names if tables is None or t in tables]
    
    proposals = []
    
    if target_scope == "table":
        for tbl in selected_tables:
            new_tbl_name = re.sub(pattern, replacement, tbl)
            if new_tbl_name != tbl:
                proposals.append({
                    "scope": "table",
                    "table": tbl,
                    "old_name": tbl,
                    "new_name": new_tbl_name
                })
        if dry_run:
            return {"dry_run": True, "scope": "table", "proposals": proposals}
            
        applied = []
        for prop in proposals:
            res = rename_table(prop["old_name"], prop["new_name"], db_path)
            applied.append(res)
        return {"success": True, "applied": applied}
        
    else: # column scope
        for tbl_meta in all_tables:
            tbl_name = tbl_meta["name"]
            if tbl_name not in selected_tables:
                continue
            mapping = {}
            for col in tbl_meta["columns"]:
                col_name = col["name"]
                new_col_name = re.sub(pattern, replacement, col_name)
                if new_col_name != col_name:
                    mapping[col_name] = new_col_name
                    proposals.append({
                        "scope": "column",
                        "table": tbl_name,
                        "old_name": col_name,
                        "new_name": new_col_name
                    })
                    
        if dry_run:
            return {"dry_run": True, "scope": "column", "proposals": proposals}
            
        # Apply column changes per table
        results = []
        tables_to_update = set(p["table"] for p in proposals)
        for tbl in tables_to_update:
            tbl_mapping = {p["old_name"]: p["new_name"] for p in proposals if p["table"] == tbl}
            res = mass_rename_columns(tbl, tbl_mapping, dry_run=False, db_path=db_path)
            results.append(res)
            
        return {"success": True, "results": results}


def apply_preset_normalization(
    preset_name: str,
    tables: Optional[List[str]] = None,
    dry_run: bool = False,
    db_path: Optional[Path] = None
) -> Dict[str, Any]:
    """
    Applies standard cybersecurity schema presets (ECS or OCSF) to current tables.
    """
    preset = PRESET_MAPPINGS.get(preset_name.upper())
    if not preset:
        return {"success": False, "error": f"Unknown preset '{preset_name}'. Choose from: {list(PRESET_MAPPINGS.keys())}"}
        
    proposals = []
    current_tables = {t["name"]: [c["name"] for c in t["columns"]] for t in get_tables(db_path)}
    
    for tbl_name, col_map in preset.items():
        if tables and tbl_name not in tables:
            continue
        if tbl_name in current_tables:
            existing_cols = current_tables[tbl_name]
            for old_col, new_col in col_map.items():
                if old_col in existing_cols:
                    proposals.append({
                        "table": tbl_name,
                        "old_column": old_col,
                        "new_column": new_col
                    })
                    
    if dry_run:
        return {"preset": preset_name, "dry_run": True, "proposals": proposals}
        
    results = []
    tables_affected = set(p["table"] for p in proposals)
    for tbl in tables_affected:
        tbl_map = {p["old_column"]: p["new_column"] for p in proposals if p["table"] == tbl}
        res = mass_rename_columns(tbl, tbl_map, dry_run=False, db_path=db_path)
        results.append(res)
        
    return {"success": True, "preset": preset_name, "results": results}
