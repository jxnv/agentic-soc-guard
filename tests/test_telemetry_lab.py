"""
Comprehensive Test Suite for TelemetryLab.
Validates database initialization, security UDFs, telemetry generation,
detection rule evaluation, mass schema renaming, and data ingestion.
"""
import unittest
import tempfile
import json
from pathlib import Path

from core.database import (
    init_database, get_connection, get_tables, execute_query,
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
from core.ingest import ingest_csv, ingest_json, stream_event


class TestTelemetryLab(unittest.TestCase):

    def setUp(self):
        # Create a dedicated temp database for isolated testing
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_telemetry.db"
        init_database(self.db_path, force=True)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_01_schema_initialization(self):
        tables = [t["name"] for t in get_tables(self.db_path)]
        expected = [
            "endpoint_process", "endpoint_file", "endpoint_network",
            "endpoint_registry", "network_flow", "network_dns",
            "network_http", "identity_auth", "identity_cloud_audit",
            "detection_rules", "detection_alerts", "schema_audit_log"
        ]
        for tbl in expected:
            self.assertIn(tbl, tables)

    def test_02_security_udfs(self):
        # Test REGEXP
        res = execute_query(
            "SELECT REGEXP('(?i)powershell', 'C:\\Windows\\powershell.exe') as matched;",
            db_path=self.db_path
        )
        self.assertEqual(res["rows"][0]["matched"], 1)

        # Test ENTROPY
        res = execute_query(
            "SELECT ENTROPY('aaaaaa') as low_ent, ENTROPY('7a8b9c0d1e2f') as high_ent;",
            db_path=self.db_path
        )
        self.assertEqual(res["rows"][0]["low_ent"], 0.0)
        self.assertGreater(res["rows"][0]["high_ent"], 2.5)

        # Test IP_IN_CIDR
        res = execute_query(
            "SELECT IP_IN_CIDR('10.0.1.25', '10.0.0.0/8') as inside, IP_IN_CIDR('192.168.1.1', '10.0.0.0/8') as outside;",
            db_path=self.db_path
        )
        self.assertEqual(res["rows"][0]["inside"], 1)
        self.assertEqual(res["rows"][0]["outside"], 0)

    def test_03_telemetry_generation_and_attacks(self):
        res = generate_telemetry(num_benign=100, inject_attacks=True, db_path=self.db_path)
        self.assertTrue(res["status"] == "success")
        self.assertGreater(res["total_events"], 100)

        # Verify attack scenarios were injected
        # Check PowerShell download cradle
        ps_res = execute_query(
            "SELECT COUNT(*) as cnt FROM endpoint_process WHERE command_line LIKE '%DownloadString%';",
            db_path=self.db_path
        )
        self.assertGreaterEqual(ps_res["rows"][0]["cnt"], 1)

        # Check LSASS dump
        lsass_res = execute_query(
            "SELECT COUNT(*) as cnt FROM endpoint_process WHERE command_line LIKE '%lsass.dmp%';",
            db_path=self.db_path
        )
        self.assertGreaterEqual(lsass_res["rows"][0]["cnt"], 1)

    def test_04_detection_engine_and_rules(self):
        generate_telemetry(num_benign=100, inject_attacks=True, db_path=self.db_path)
        sync_count = sync_rules_to_db(self.db_path)
        self.assertGreaterEqual(sync_count, 10)

        # Run single rule
        rule_res = run_rule("DET-EP-001", record_alerts=True, db_path=self.db_path)
        self.assertTrue(rule_res["success"])
        self.assertGreaterEqual(rule_res["alert_count"], 1)

        # Run all rules batch suite
        batch_res = run_all_rules(record_alerts=True, db_path=self.db_path)
        self.assertGreaterEqual(batch_res["total_rules_evaluated"], 10)
        self.assertGreaterEqual(batch_res["total_alerts_produced"], 5)

        # Verify alert table was populated
        alerts_res = execute_query("SELECT COUNT(*) as cnt FROM detection_alerts;", db_path=self.db_path)
        self.assertGreaterEqual(alerts_res["rows"][0]["cnt"], 5)

        # Test tuning benchmark
        bench = tune_rule_benchmark("DET-EP-001", db_path=self.db_path)
        self.assertIn("noise_reduction_percentage", bench)

        # Test MITRE coverage
        cov = get_mitre_coverage(self.db_path)
        self.assertGreaterEqual(cov["tactics_covered"], 5)

    def test_05_schema_transformations(self):
        generate_telemetry(num_benign=20, inject_attacks=False, db_path=self.db_path)

        # Test single column rename
        ren_res = rename_column("network_http", "uri", "url_path", db_path=self.db_path)
        self.assertTrue(ren_res["success"])
        table_meta = [c for c in get_tables(self.db_path) if c["name"] == "network_http"][0]
        col_names = [col["name"] for col in table_meta["columns"]]
        self.assertIn("url_path", col_names)
        self.assertNotIn("uri", col_names)

        # Test regex pattern rename
        pat_res = mass_rename_by_pattern("^src_", "source_", target_scope="column", dry_run=False, db_path=self.db_path)
        self.assertTrue(pat_res["success"])

        # Test table rename
        tbl_ren = rename_table("endpoint_registry", "edr_registry", db_path=self.db_path)
        self.assertTrue(tbl_ren["success"])
        current_tables = [t["name"] for t in get_tables(self.db_path)]
        self.assertIn("edr_registry", current_tables)
        self.assertNotIn("endpoint_registry", current_tables)

    def test_06_ingest_csv_and_json(self):
        # CSV Ingest
        sample_csv = self.temp_dir.name + "/test_in.csv"
        with open(sample_csv, "w") as f:
            f.write("user,action,score\njohn,login,10\nalice,logout,5\n")

        csv_res = ingest_csv(Path(sample_csv), "custom_csv_table", db_path=self.db_path)
        self.assertTrue(csv_res["success"])
        self.assertEqual(csv_res["rows_inserted"], 2)

        # JSON Ingest
        sample_json = self.temp_dir.name + "/test_in.json"
        with open(sample_json, "w") as f:
            json.dump([{"host": "srv1", "vuln": "CVE-2023-1234"}, {"host": "srv2", "vuln": "CVE-2024-5678"}], f)

        json_res = ingest_json(Path(sample_json), "custom_json_table", db_path=self.db_path)
        self.assertTrue(json_res["success"])
        self.assertEqual(json_res["rows_inserted"], 2)

        # Stream event
        evt_res = stream_event("custom_csv_table", {"user": "bob", "action": "sudo", "score": 99}, db_path=self.db_path)
        self.assertTrue(evt_res["success"])

    def test_07_export_and_import_dump(self):
        generate_telemetry(num_benign=50, inject_attacks=True, db_path=self.db_path)
        dump_file = Path(self.temp_dir.name) / "test_dump.sql"

        # Export
        export_res = export_dump(dump_file, db_path=self.db_path)
        self.assertTrue(dump_file.exists())
        self.assertGreater(export_res["size_kb"], 0)

        # Restore into a fresh new DB
        new_db = Path(self.temp_dir.name) / "restored.db"
        import_res = import_dump(dump_file, db_path=new_db)
        self.assertEqual(import_res["status"], "success")

        # Check tables in restored DB
        restored_tables = get_tables(new_db)
        self.assertGreaterEqual(len(restored_tables), 10)


if __name__ == "__main__":
    unittest.main()
