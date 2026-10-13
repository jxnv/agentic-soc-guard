#!/usr/bin/env python3
"""
Command-Line Interface (CLI) for TelemetryLab.
Provides terminal workflows for database initialization, mock telemetry seeding,
mass schema transformations, rule evaluation, and git-friendly SQL dumps.
"""
import argparse
import sys
import json
from pathlib import Path

import config
from core.database import (
    init_database, get_tables, get_table_schema, execute_query,
    export_dump, import_dump
)
from core.generator import generate_telemetry
from core.schema_manager import (
    rename_column, rename_table, mass_rename_columns,
    mass_rename_by_pattern, apply_preset_normalization
)
from core.detection_engine import (
    sync_rules_to_db, get_all_rules, run_rule, run_all_rules,
    tune_rule_benchmark, get_mitre_coverage
)
from core.ingest import ingest_csv, ingest_json


def main():
    parser = argparse.ArgumentParser(
        prog="telemetry-lab",
        description="TelemetryLab: Portable SQLite Telemetry Playground & Detection Engineering Suite"
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # init
    p_init = subparsers.add_parser("init", help="Initialize SQLite schema")
    p_init.add_argument("--force", action="store_true", help="Force overwrite existing database")

    # seed
    p_seed = subparsers.add_parser("seed", help="Generate mock telemetry events")
    p_seed.add_argument("--count", type=int, default=500, help="Number of baseline events to generate")
    p_seed.add_argument("--no-attacks", action="store_true", help="Do not inject attack scenarios")
    p_seed.add_argument("--days", type=int, default=3, help="Historical time window in days")

    # tables
    subparsers.add_parser("tables", help="List all tables, row counts, and schema stats")

    # schema
    p_schema = subparsers.add_parser("schema", help="View schema for a specific table")
    p_schema.add_argument("table", type=str, help="Table name")

    # query
    p_query = subparsers.add_parser("query", help="Execute arbitrary SQL query against telemetry database")
    p_query.add_argument("sql", type=str, help="SQL query string")
    p_query.add_argument("--limit", type=int, default=50, help="Max rows to display")

    # run-rules
    p_rules = subparsers.add_parser("run-rules", help="Execute all enabled detection rules")
    p_rules.add_argument("--no-record", action="store_true", help="Do not save alerts to detection_alerts table")

    # test-rule
    p_test_rule = subparsers.add_parser("test-rule", help="Test a specific detection rule by ID")
    p_test_rule.add_argument("rule_id", type=str, help="Rule ID (e.g. DET-EP-001)")
    p_test_rule.add_argument("--tune", action="store_true", help="Apply tuning exclusions filter")

    # tune-benchmark
    p_tune = subparsers.add_parser("tune-benchmark", help="Benchmark false positive suppression before & after tuning")
    p_tune.add_argument("rule_id", type=str, help="Rule ID (e.g. DET-EP-001)")

    # mitre
    subparsers.add_parser("mitre", help="Display MITRE ATT&CK coverage matrix breakdown")

    # mass-rename-cols
    p_mren = subparsers.add_parser("mass-rename-cols", help="Mass rename columns in a table")
    p_mren.add_argument("table", type=str, help="Table name")
    p_mren.add_argument("mapping", type=str, help="Key-value mapping formatted as old1:new1,old2:new2")
    p_mren.add_argument("--dry-run", action="store_true", help="Preview changes without executing")

    # mass-rename-pattern
    p_pat = subparsers.add_parser("mass-rename-pattern", help="Mass rename columns or tables using regex pattern")
    p_pat.add_argument("pattern", type=str, help="Regex pattern (e.g. ^dest_)")
    p_pat.add_argument("replacement", type=str, help="Replacement string (e.g. dst_)")
    p_pat.add_argument("--scope", choices=["column", "table"], default="column", help="Target scope")
    p_pat.add_argument("--dry-run", action="store_true", help="Preview proposed renames")

    # apply-preset
    p_preset = subparsers.add_parser("apply-preset", help="Normalize schema to standard cybersecurity preset (ECS or OCSF)")
    p_preset.add_argument("preset", choices=["ECS", "OCSF"], help="Target schema standard")
    p_preset.add_argument("--dry-run", action="store_true", help="Preview proposed column normalizations")

    # ingest
    p_ingest = subparsers.add_parser("ingest", help="Ingest external CSV, JSON, or JSONL into a table")
    p_ingest.add_argument("file", type=str, help="Path to input data file")
    p_ingest.add_argument("table", type=str, help="Target SQLite table name")

    # export-dump
    p_dump = subparsers.add_parser("export-dump", help="Export clean SQL dump for Git repository portfolio")
    p_dump.add_argument("output", type=str, nargs="?", default="seed.sql", help="Destination SQL dump path")

    # import-dump
    p_imp = subparsers.add_parser("import-dump", help="Restore database from a SQL dump file")
    p_imp.add_argument("input", type=str, help="Input SQL dump file")

    # guard-stream
    subparsers.add_parser("guard-stream", help="Simulate AI Agent MCP tool call stream with OpenTelemetry tracing")

    # guard-detect
    subparsers.add_parser("guard-detect", help="Evaluate OpenTelemetry spans with MCP behavioral abuse detector")

    # triage
    p_triage = subparsers.add_parser("triage", help="Run Autonomous SOC Triage Agent against an alert")
    p_triage.add_argument("--alert-id", type=str, default="ALERT-AI-1048", help="Alert ID to triage")
    p_triage.add_argument("--file", type=str, help="Path to custom alert JSON file")
    p_triage.add_argument("--format", choices=["markdown", "json", "both"], default="both", help="Output format")

    args = parser.parse_args()

    if not args.subcommand:
        parser.print_help()
        sys.exit(0)

    # Dispatch subcommands
    if args.subcommand == "init":
        res = init_database(force=args.force)
        sync_rules_to_db()
        print(f"[*] Initialized database at: {res['db_path']}")
        print(f"[*] Synced detection rules catalog from {config.RULES_MANIFEST.name}")

    elif args.subcommand == "seed":
        print(f"[*] Generating telemetry ({args.count} baseline, attacks={not args.no_attacks})...")
        res = generate_telemetry(num_benign=args.count, inject_attacks=not args.no_attacks, days_back=args.days)
        print(f"[+] Total events generated: {res['total_events']}")
        for tbl, cnt in res['generated_counts'].items():
            print(f"    - {tbl}: {cnt}")

    elif args.subcommand == "tables":
        tables = get_tables()
        print(f"{'Table Name':<25} {'Rows':<10} {'Columns':<8}")
        print("-" * 45)
        for t in tables:
            print(f"{t['name']:<25} {t['row_count']:<10} {t['column_count']:<8}")

    elif args.subcommand == "schema":
        cols = get_table_schema(args.table)
        if not cols:
            print(f"[-] Table '{args.table}' not found or empty.")
            return
        print(f"Schema for table: {args.table}")
        print(f"{'CID':<5} {'Column Name':<25} {'Type':<12} {'NotNull':<8} {'PK':<5}")
        print("-" * 55)
        for c in cols:
            print(f"{c['cid']:<5} {c['name']:<25} {c['type']:<12} {str(c['notnull']):<8} {str(c['pk']):<5}")

    elif args.subcommand == "query":
        res = execute_query(args.sql, max_rows=args.limit)
        if not res["success"]:
            print(f"[-] Query Error: {res.get('error')}")
            sys.exit(1)
        if res.get("is_select"):
            rows = res["rows"]
            cols = res["columns"]
            print(f"[+] Query returned {len(rows)} rows ({res['execution_time_ms']} ms):")
            if not rows:
                print("    (No matching rows)")
                return
            # Print table
            header = " | ".join(cols)
            print(header)
            print("-" * len(header))
            for r in rows:
                print(" | ".join(str(r.get(c, "")) for c in cols))
        else:
            print(f"[+] Statement executed ({res['execution_time_ms']} ms). Rows affected: {res.get('rows_affected')}")

    elif args.subcommand == "run-rules":
        sync_rules_to_db()
        print("[*] Running detection rule evaluation batch suite...")
        res = run_all_rules(record_alerts=not args.no_record)
        print(f"[+] Run ID: {res['run_id']}")
        print(f"[+] Total Rules: {res['total_rules_evaluated']} | Alerts: {res['total_alerts_produced']} | Time: {res['total_execution_time_ms']} ms")
        print("\nBreakdown:")
        print(f"{'Rule ID':<12} {'Severity':<10} {'Alerts':<8} {'Time (ms)':<10} {'Name'}")
        print("-" * 80)
        for rr in res["rule_results"]:
            if rr.get("success"):
                print(f"{rr['rule_id']:<12} {rr['severity']:<10} {rr['alert_count']:<8} {rr['execution_time_ms']:<10} {rr['rule_name']}")
            else:
                print(f"{rr['rule_id']:<12} {'ERROR':<10} {0:<8} {rr.get('execution_time_ms', 0):<10} {rr.get('error')}")

    elif args.subcommand == "test-rule":
        sync_rules_to_db()
        res = run_rule(args.rule_id, record_alerts=False, apply_tuning=args.tune)
        if not res.get("success"):
            print(f"[-] Error: {res.get('error')}")
            sys.exit(1)
        print(f"[+] Rule: [{res['rule_id']}] {res['rule_name']}")
        print(f"    Severity: {res['severity']} | MITRE: {res.get('mitre_attack_id')} ({res.get('mitre_tactic')})")
        print(f"    Matches: {res['alert_count']} (Time: {res['execution_time_ms']} ms, Tuned: {args.tune})")
        for i, m in enumerate(res["matches"][:10], start=1):
            print(f"    [{i}] {json.dumps(m, default=str)}")
        if len(res["matches"]) > 10:
            print(f"    ... and {len(res['matches']) - 10} more matches.")

    elif args.subcommand == "tune-benchmark":
        sync_rules_to_db()
        bench = tune_rule_benchmark(args.rule_id)
        if not bench.get("rule_name"):
            print(f"[-] Error: {bench.get('error')}")
            sys.exit(1)
        print(f"[+] Rule: [{bench['rule_id']}] {bench['rule_name']}")
        print(f"    Raw Alert Count:   {bench['raw_alert_count']}")
        print(f"    Tuned Alert Count: {bench['tuned_alert_count']}")
        print(f"    Alerts Suppressed: {bench['alerts_suppressed']}")
        print(f"    Noise Reduction:   {bench['noise_reduction_percentage']}%")
        print(f"    Exclusion Filter:  {bench['tune_exclusions']}")

    elif args.subcommand == "mitre":
        sync_rules_to_db()
        cov = get_mitre_coverage()
        print(f"[+] Total Rules: {cov['total_rules']} | Tactics Covered: {cov['tactics_covered']}")
        print("=" * 60)
        for tactic, rules_list in cov["coverage"].items():
            print(f"\n[Tactic] {tactic} ({len(rules_list)} rules):")
            for r in rules_list:
                print(f"  - [{r['rule_id']}] {r['technique_id']}: {r['name']} ({r['severity']})")

    elif args.subcommand == "mass-rename-cols":
        mapping = {}
        for pair in args.mapping.split(","):
            if ":" in pair:
                k, v = pair.split(":", 1)
                mapping[k.strip()] = v.strip()
        res = mass_rename_columns(args.table, mapping, dry_run=args.dry_run)
        print(json.dumps(res, indent=2))

    elif args.subcommand == "mass-rename-pattern":
        res = mass_rename_by_pattern(args.pattern, args.replacement, target_scope=args.scope, dry_run=args.dry_run)
        print(json.dumps(res, indent=2))

    elif args.subcommand == "apply-preset":
        res = apply_preset_normalization(args.preset, dry_run=args.dry_run)
        print(json.dumps(res, indent=2))

    elif args.subcommand == "ingest":
        p = Path(args.file)
        if p.suffix.lower() == ".csv":
            res = ingest_csv(p, args.table)
        elif p.suffix.lower() in [".json", ".jsonl"]:
            res = ingest_json(p, args.table)
        else:
            print(f"[-] Unsupported file extension: {p.suffix}")
            sys.exit(1)
        print(json.dumps(res, indent=2))

    elif args.subcommand == "export-dump":
        res = export_dump(Path(args.output))
        print(f"[+] Dump exported to {res['dump_file']} ({res['size_kb']} KB)")

    elif args.subcommand == "import-dump":
        res = import_dump(Path(args.input))
        print(f"[+] Database successfully restored from {args.input}")

    elif args.subcommand == "guard-stream":
        from telemetry_guard.mock_agent_stream import generate_mock_telemetry_stream
        generate_mock_telemetry_stream()

    elif args.subcommand == "guard-detect":
        from telemetry_guard.mcp_tool_abuse_detector import run_standalone_evaluation
        run_standalone_evaluation()

    elif args.subcommand == "triage":
        from autonomous_triage.triage_agent import TriageEngine, find_alert
        raw_alerts_path = Path(__file__).resolve().parent / "sample_data" / "raw_alerts.json"
        target = None
        if args.file:
            with open(args.file, "r", encoding="utf-8") as f:
                target = json.load(f)
        else:
            target = find_alert(args.alert_id, raw_alerts_path)
        if not target:
            print(f"[-] Alert '{args.alert_id}' not found.")
            sys.exit(1)
        engine = TriageEngine()
        brief = engine.triage_alert(target)
        if args.format in ["markdown", "both"]:
            print(brief.ads_markdown_brief)
        if args.format in ["json", "both"]:
            print("=" * 80)
            print("STRUCTURED ADS VERDICT (PYDANTIC v2 VALIDATED JSON):")
            print("=" * 80)
            print(brief.verdict.model_dump_json(indent=2))


if __name__ == "__main__":
    main()
