"""
Real-time behavioral detection engine inspecting OpenTelemetry spans emitted
by AI Agent Model Context Protocol (MCP) tool invocations.
"""
from __future__ import annotations

import re
import json
import time
import sqlite3
import datetime
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional

import config


@dataclass
class AgentAlert:
    """Standardized security alert produced by the MCP Agent Telemetry Guard."""
    alert_id: str
    rule_name: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    mitre_atlas_id: str
    agent_id: str
    tool_name: str
    evidence: str
    timestamp: str = ""
    details: Optional[Dict[str, Any]] = None

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        if self.details is None:
            self.details = {}

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class MCPAgentDetector:
    """
    Evaluates OpenTelemetry spans emitted by AI Agent MCP tool executions
    against behavioral detection rules and security boundaries.
    """

    FORBIDDEN_FILE_PATTERNS = [
        r"/\.aws/credentials",
        r"/\.ssh/id_rsa",
        r"/\.ssh/id_ed25519",
        r"/etc/shadow",
        r"/etc/passwd",
        r"\.kube/config",
        r"\.env($|\.)",
        r"/etc/hosts",
        r"(\.\./){2,}",          # Path traversal attacks
        r"(\.\.\\){2,}",
        r"SAM$",                 # Windows credential hives
        r"SYSTEM$",
    ]

    SUSPICIOUS_CMD_PATTERNS = [
        r"curl\s+.*\|\s*(bash|sh)",
        r"wget\s+.*\|\s*(bash|sh)",
        r"nc\s+.*-e\s+",
        r"base64\s+-d",
        r"chmod\s+\+x",
        r"iptables\s+-F",
        r"rm\s+-rf\s+/",
        r"mkfifo\s+",
        r"/dev/tcp/",
        r"powershell.*(-enc|-encodedcommand)",
        r"invoke-expression",
        r"downloadstring",
    ]

    INDIRECT_INJECTION_PATTERNS = [
        r"ignore\s+(all\s+)?previous\s+instructions",
        r"disregard\s+(all\s+)?prior\s+rules",
        r"system\s+prompt\s+override",
        r"you\s+are\s+now\s+in\s+(developer|god|unrestricted)\s+mode",
        r"bypass\s+(safety|content)\s+filter",
        r"new\s+instruction:\s*",
    ]

    VELOCITY_WINDOW_SECONDS = 5.0
    VELOCITY_THRESHOLD = 8
    MAX_ALLOWED_DEPTH = 6

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or config.DB_PATH
        self.call_history: List[Dict[str, Any]] = []
        self._last_untrusted_input: Optional[Dict[str, Any]] = None

    def reset_state(self) -> None:
        """Resets in-memory call history and correlation tracking."""
        self.call_history.clear()
        self._last_untrusted_input = None

    def evaluate_tool_span(self, span: Dict[str, Any]) -> List[AgentAlert]:
        """
        Analyzes OpenTelemetry span metadata from an MCP tool execution
        and returns any triggered AgentAlerts.
        """
        alerts: List[AgentAlert] = []
        attrs = span.get("attributes", {})
        tool_name = str(attrs.get("agent.tool.name", "unknown"))
        raw_args = attrs.get("agent.tool.arguments", "")
        tool_args = str(raw_args)
        agent_id = str(attrs.get("agent.session_id", "default_agent"))
        call_depth = int(attrs.get("agent.call_depth", 1))
        span_id = span.get("context", {}).get("span_id", "unknown_span")
        timestamp = span.get("start_time") or datetime.datetime.now(datetime.timezone.utc).isoformat()

        # Record into history for velocity and sequence correlation
        self.call_history.append({
            "timestamp": time.time(),
            "iso_time": timestamp,
            "tool_name": tool_name,
            "tool_args": tool_args,
            "agent_id": agent_id,
            "span_id": span_id,
            "call_depth": call_depth,
        })

        # Rule 1: High-Risk System File Access & Path Traversal
        if tool_name in ["read_file", "view_file", "fs_cat", "open_file", "read_path", "cat"]:
            for pattern in self.FORBIDDEN_FILE_PATTERNS:
                if re.search(pattern, tool_args, re.IGNORECASE):
                    alerts.append(AgentAlert(
                        alert_id=f"ALT-MCP-{span_id[:8]}",
                        rule_name="AI_AGENT_SENSITIVE_CREDENTIAL_READ",
                        severity="CRITICAL",
                        mitre_atlas_id="AML.T0054 / T1552",
                        agent_id=agent_id,
                        tool_name=tool_name,
                        evidence=f"Agent attempted unauthorized read on sensitive path: {tool_args}",
                        timestamp=timestamp,
                        details={"target_pattern": pattern, "arguments": tool_args}
                    ))
                    break

        # Rule 2: Dangerous Shell Execution via Agent Shell Tool
        if tool_name in ["run_bash", "terminal_exec", "execute_command", "execute_shell", "bash", "sh"]:
            for pattern in self.SUSPICIOUS_CMD_PATTERNS:
                if re.search(pattern, tool_args, re.IGNORECASE):
                    alerts.append(AgentAlert(
                        alert_id=f"ALT-MCP-{span_id[:8]}",
                        rule_name="AI_AGENT_ARBITRARY_CODE_EXECUTION",
                        severity="CRITICAL",
                        mitre_atlas_id="AML.T0051 / T1059",
                        agent_id=agent_id,
                        tool_name=tool_name,
                        evidence=f"Agent invoked shell execution with malicious payload: {tool_args}",
                        timestamp=timestamp,
                        details={"matched_pattern": pattern, "command_payload": tool_args}
                    ))
                    break

        # Rule 3: Indirect Prompt Injection Pattern in Arguments or Chained Inputs
        for pattern in self.INDIRECT_INJECTION_PATTERNS:
            if re.search(pattern, tool_args, re.IGNORECASE):
                alerts.append(AgentAlert(
                    alert_id=f"ALT-MCP-{span_id[:8]}",
                    rule_name="AI_AGENT_INDIRECT_PROMPT_INJECTION",
                    severity="HIGH",
                    mitre_atlas_id="AML.T0054 / AML.T0051",
                    agent_id=agent_id,
                    tool_name=tool_name,
                    evidence=f"Detected prompt injection jailbreak signature in tool payload: {pattern}",
                    timestamp=timestamp,
                    details={"matched_pattern": pattern, "raw_snippet": tool_args[:200]}
                ))
                break

        # Rule 4: Chained Context Poisoning (Untrusted fetch followed immediately by privileged execution)
        if tool_name in ["fetch_webpage", "read_email", "scrape_url", "fetch_url"]:
            for pattern in self.INDIRECT_INJECTION_PATTERNS:
                if re.search(pattern, tool_args, re.IGNORECASE):
                    self._last_untrusted_input = {
                        "agent_id": agent_id,
                        "time": time.time(),
                        "tool_name": tool_name,
                        "pattern": pattern
                    }
                    break
        elif self._last_untrusted_input and self._last_untrusted_input.get("agent_id") == agent_id:
            if time.time() - self._last_untrusted_input["time"] < 60.0:
                if tool_name in ["run_bash", "execute_command", "execute_shell", "terminal_exec"]:
                    alerts.append(AgentAlert(
                        alert_id=f"ALT-MCP-{span_id[:8]}",
                        rule_name="AI_AGENT_POISONED_CONTEXT_CHAIN_EXECUTION",
                        severity="CRITICAL",
                        mitre_atlas_id="AML.T0054 / AML.T0051",
                        agent_id=agent_id,
                        tool_name=tool_name,
                        evidence=(
                            f"Agent executed privileged shell tool '{tool_name}' immediately following untrusted "
                            f"ingestion via '{self._last_untrusted_input['tool_name']}'."
                        ),
                        timestamp=timestamp,
                        details={"chained_from": self._last_untrusted_input}
                    ))
                    self._last_untrusted_input = None

        # Rule 5: Call Depth & Denial-of-Wallet Loop Detection
        if call_depth >= self.MAX_ALLOWED_DEPTH:
            alerts.append(AgentAlert(
                alert_id=f"ALT-MCP-{span_id[:8]}",
                rule_name="AI_AGENT_CALL_DEPTH_EXCEEDED",
                severity="HIGH",
                mitre_atlas_id="AML.T0040 / T1499",
                agent_id=agent_id,
                tool_name=tool_name,
                evidence=f"Call depth {call_depth} exceeded maximum safety limit ({self.MAX_ALLOWED_DEPTH})",
                timestamp=timestamp,
                details={"call_depth": call_depth, "limit": self.MAX_ALLOWED_DEPTH}
            ))

        # Velocity check: Out-of-Distribution Call Frequency
        now = time.time()
        recent_calls = [
            c for c in self.call_history
            if c["agent_id"] == agent_id and (now - c["timestamp"]) <= self.VELOCITY_WINDOW_SECONDS
        ]
        if len(recent_calls) >= self.VELOCITY_THRESHOLD:
            alerts.append(AgentAlert(
                alert_id=f"ALT-MCP-{span_id[:8]}",
                rule_name="AI_AGENT_DENIAL_OF_WALLET_LOOP",
                severity="HIGH",
                mitre_atlas_id="AML.T0040 / T1499",
                agent_id=agent_id,
                tool_name=tool_name,
                evidence=(
                    f"Out-of-distribution call velocity: {len(recent_calls)} tool calls within "
                    f"{self.VELOCITY_WINDOW_SECONDS}s window (Potential infinite agent loop)."
                ),
                timestamp=timestamp,
                details={"recent_calls_count": len(recent_calls), "window_seconds": self.VELOCITY_WINDOW_SECONDS}
            ))

        return alerts

    def evaluate_span_stream(self, spans: List[Dict[str, Any]]) -> List[AgentAlert]:
        """Evaluates an ordered list of OpenTelemetry spans."""
        all_alerts: List[AgentAlert] = []
        for span in spans:
            fired = self.evaluate_tool_span(span)
            all_alerts.extend(fired)
        return all_alerts

    def save_alerts_to_sqlite(self, alerts: List[AgentAlert]) -> int:
        """
        Saves generated AgentAlerts into the detection_alerts table in telemetry.db.
        Returns the number of saved alerts.
        """
        if not alerts:
            return 0

        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        saved_count = 0

        # Check if detection_alerts table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='detection_alerts'")
        if not cursor.fetchone():
            conn.close()
            return 0

        run_id = f"RUN-MCP-{int(time.time())}"
        for alt in alerts:
            context_json = json.dumps({
                "mitre_atlas": alt.mitre_atlas_id,
                "tool_name": alt.tool_name,
                "evidence": alt.evidence,
                "details": alt.details or {}
            })
            cursor.execute(
                """
                INSERT INTO detection_alerts 
                (run_id, rule_id, rule_name, severity, alert_time, entity_host, entity_user, context_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    alt.alert_id,
                    alt.rule_name,
                    alt.severity,
                    alt.timestamp,
                    "ai-agent-runtime-host",
                    alt.agent_id,
                    context_json
                )
            )
            saved_count += 1

        conn.commit()
        conn.close()
        return saved_count


def run_standalone_evaluation() -> None:
    """CLI Runner: Reads sample_data/otel_spans.json and evaluates detection rules."""
    print("=" * 80)
    print("AI-NATIVE TELEMETRY GUARD: MCP TOOL ABUSE DETECTION ENGINE")
    print("=" * 80)

    spans_path = Path(__file__).resolve().parent.parent / "sample_data" / "otel_spans.json"
    if not spans_path.exists():
        print(f"[-] Trace file not found at {spans_path}. Please run mock stream first:")
        print("    python3 -m telemetry_guard.mock_agent_stream")
        return

    with open(spans_path, "r", encoding="utf-8") as f:
        spans = json.load(f)

    print(f"[*] Ingested {len(spans)} OpenTelemetry spans from {spans_path.name}")
    print("[*] Evaluating behavioral detection rules against MCP tool invocations...")

    detector = MCPAgentDetector()
    alerts = detector.evaluate_span_stream(spans)

    print(f"\n[+] Analysis complete: {len(alerts)} High-Fidelity Alert(s) Fired!\n")
    print("-" * 80)

    for i, alert in enumerate(alerts, 1):
        sev_color = "\033[91m" if alert.severity == "CRITICAL" else "\033[93m"
        rst = "\033[0m"
        print(f"[{i}] {sev_color}[{alert.severity}]{rst} {alert.rule_name} ({alert.alert_id})")
        print(f"    MITRE ATLAS / ATT&CK : {alert.mitre_atlas_id}")
        print(f"    Target Tool          : {alert.tool_name}")
        print(f"    Agent Session        : {alert.agent_id}")
        print(f"    Evidence             : {alert.evidence}")
        print("-" * 80)

    # Persist to database if present
    saved = detector.save_alerts_to_sqlite(alerts)
    if saved > 0:
        print(f"[+] Persisted {saved} alerts into SQLite telemetry bus (telemetry.db:detection_alerts).")
    print("=" * 80)


if __name__ == "__main__":
    run_standalone_evaluation()
