"""
Database management module for TelemetryLab.
Provides optimized SQLite connections, schema initialization, table reflection,
and custom security UDFs (Regex, Shannon Entropy, CIDR matching).
"""
import sqlite3
import math
import ipaddress
import re
import time
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path

import config


def _udf_regexp(pattern: str, text: Optional[str]) -> bool:
    """SQLite UDF: Case-insensitive or custom regex matching."""
    if text is None or pattern is None:
        return False
    try:
        return bool(re.search(pattern, str(text), re.IGNORECASE))
    except Exception:
        return False


def _udf_entropy(text: Optional[str]) -> float:
    """
    SQLite UDF: Shannon entropy calculator.
    Essential for detecting DGA domains, base64 payloads, and obfuscated commands.
    """
    if not text:
        return 0.0
    text_str = str(text)
    length = len(text_str)
    if length == 0:
        return 0.0
    
    freq: Dict[str, int] = {}
    for char in text_str:
        freq[char] = freq.get(char, 0) + 1
        
    ent = 0.0
    for count in freq.values():
        p = count / length
        ent -= p * math.log2(p)
    return round(ent, 3)


def _udf_ip_in_cidr(ip_str: Optional[str], cidr_str: Optional[str]) -> bool:
    """
    SQLite UDF: Checks if an IP is within a CIDR range.
    Example: ip_in_cidr(src_ip, '192.168.0.0/16')
    """
    if not ip_str or not cidr_str:
        return False
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        network = ipaddress.ip_network(cidr_str.strip(), strict=False)
        return ip in network
    except Exception:
        return False


def get_connection(db_path: Optional[Path] = None) -> sqlite3.Connection:
    """
    Returns an optimized SQLite connection with detection UDFs registered.
    """
    target_path = Path(db_path) if db_path else config.DB_PATH
    conn = sqlite3.connect(str(target_path), timeout=10.0)
    conn.row_factory = sqlite3.Row
    
    # Apply PRAGMAs
    cursor = conn.cursor()
    for pragma in config.SQLITE_PRAGMAS:
        try:
            cursor.execute(pragma)
        except sqlite3.DatabaseError:
            pass
            
    # Register Security UDFs (case-insensitive in SQLite)
    conn.create_function("REGEXP", 2, _udf_regexp)
    conn.create_function("ENTROPY", 1, _udf_entropy)
    conn.create_function("IP_IN_CIDR", 2, _udf_ip_in_cidr)
    
    return conn


def init_database(db_path: Optional[Path] = None, force: bool = False) -> Dict[str, Any]:
    """
    Initializes the database schema using schema.sql.
    If force=True, recreates tables.
    """
    target_path = Path(db_path) if db_path else config.DB_PATH
    if force and target_path.exists():
        target_path.unlink()
        
    conn = get_connection(target_path)
    with open(config.SCHEMA_FILE, "r", encoding="utf-8") as f:
        schema_sql = f.read()
        
    cursor = conn.cursor()
    cursor.executescript(schema_sql)
    conn.commit()
    conn.close()
    
    return {"status": "success", "db_path": str(target_path)}


def get_tables(db_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    """
    Returns metadata for all user tables, including column count and row count.
    """
    conn = get_connection(db_path)
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT name FROM sqlite_master 
        WHERE type='table' AND name NOT LIKE 'sqlite_%'
        ORDER BY name;
    """)
    table_names = [row["name"] for row in cursor.fetchall()]
    
    tables_meta = []
    for name in table_names:
        # Get count
        try:
            cursor.execute(f"SELECT COUNT(*) as cnt FROM \"{name}\";")
            row_count = cursor.fetchone()["cnt"]
        except Exception:
            row_count = 0
            
        # Get columns
        cursor.execute(f"PRAGMA table_info(\"{name}\");")
        cols = [
            {
                "cid": col["cid"],
                "name": col["name"],
                "type": col["type"],
                "notnull": bool(col["notnull"]),
                "dflt_value": col["dflt_value"],
                "pk": bool(col["pk"])
            }
            for col in cursor.fetchall()
        ]
        
        tables_meta.append({
            "name": name,
            "row_count": row_count,
            "column_count": len(cols),
            "columns": cols
        })
        
    conn.close()
    return tables_meta


def get_table_schema(table_name: str, db_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Returns columns schema for a specific table."""
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute(f"PRAGMA table_info(\"{table_name}\");")
    columns = [dict(col) for col in cursor.fetchall()]
    conn.close()
    return columns


def execute_query(sql: str, params: Optional[Tuple] = None, db_path: Optional[Path] = None, max_rows: int = 2000) -> Dict[str, Any]:
    """
    Executes a query and returns structured results with timing.
    Supports SELECT, INSERT, UPDATE, DELETE, ALTER, etc.
    """
    start_time = time.perf_counter()
    conn = get_connection(db_path)
    cursor = conn.cursor()
    
    try:
        if params:
            cursor.execute(sql, params)
        else:
            cursor.execute(sql)
            
        execution_time_ms = round((time.perf_counter() - start_time) * 1000, 2)
        
        if cursor.description is not None:
            columns = [desc[0] for desc in cursor.description]
            rows = cursor.fetchmany(max_rows)
            # Convert sqlite3.Row to list of dicts
            results = [dict(row) for row in rows]
            conn.close()
            return {
                "success": True,
                "is_select": True,
                "columns": columns,
                "rows": results,
                "row_count": len(results),
                "execution_time_ms": execution_time_ms,
                "truncated": len(results) >= max_rows
            }
        else:
            conn.commit()
            rows_affected = cursor.rowcount
            conn.close()
            return {
                "success": True,
                "is_select": False,
                "columns": [],
                "rows": [],
                "rows_affected": rows_affected,
                "execution_time_ms": execution_time_ms
            }
    except Exception as e:
        conn.close()
        execution_time_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return {
            "success": False,
            "error": str(e),
            "execution_time_ms": execution_time_ms
        }


def export_dump(output_file: Path, db_path: Optional[Path] = None) -> Dict[str, Any]:
    """
    Exports clean SQL dump of the database (schema + data) for Git repo commits.
    """
    target_path = Path(db_path) if db_path else config.DB_PATH
    conn = sqlite3.connect(str(target_path))
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, "w", encoding="utf-8") as f:
        for line in conn.iterdump():
            f.write(f"{line}\n")
            
    conn.close()
    size_bytes = output_path.stat().st_size
    return {
        "status": "success",
        "dump_file": str(output_path),
        "size_kb": round(size_bytes / 1024, 2)
    }


def import_dump(input_file: Path, db_path: Optional[Path] = None) -> Dict[str, Any]:
    """
    Recreates database from a SQL dump file.
    """
    target_path = Path(db_path) if db_path else config.DB_PATH
    input_path = Path(input_file)
    if not input_path.exists():
        raise FileNotFoundError(f"Dump file not found: {input_path}")
        
    conn = get_connection(target_path)
    with open(input_path, "r", encoding="utf-8") as f:
        sql = f.read()
    conn.executescript(sql)
    conn.commit()
    conn.close()
    return {"status": "success", "db_path": str(target_path)}
