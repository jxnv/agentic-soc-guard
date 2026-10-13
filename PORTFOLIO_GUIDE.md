# Detection Engineering Portfolio Showcase Guide

This guide helps you present **TelemetryLab** on your GitHub security portfolio, technical resume, and during interviews for **Detection Engineer**, **Threat Hunter**, and **Security Operations (SOC) Analyst** roles.

---

## Executive Summary for Your Portfolio

> *"Built **TelemetryLab**, a portable SQLite-based detection engineering laboratory to model multi-stage adversary tradecraft across Endpoint, Network, Identity, and Cloud telemetry pillars. Implemented a detection evaluation engine with custom SQLite UDFs (Regex, Shannon Entropy, CIDR matching), an automated false-positive tuning benchmark, and schema normalization pipelines mapping raw logs to Elastic Common Schema (ECS) and OCSF standards."*

---

## Resume Bullet Points

You can adapt these bullet points to your resume under Projects or Experience:

- **Detection Engineering & Testing Framework**:
  - *Engineered a lightweight, reproducible SQLite telemetry playground modeling 4 enterprise log pillars (Sysmon, Zeek, Okta/AD, CloudTrail) with injected MITRE ATT&CK adversary scenarios (T1059, T1003, T1110, T1071).*
  - *Created a SQL detection rule engine with sub-millisecond execution times, automated true-positive alert generation, and tuning suppression metrics to calculate false-positive reduction percentages.*

- **Data Engineering & Schema Normalization**:
  - *Architected a mass schema transformation toolkit enabling regex-driven column/table migrations and automated alignment to Elastic Common Schema (ECS) and Open Cybersecurity Schema Framework (OCSF).*
  - *Developed an extensible data ingestion pipeline for CSV and JSON/NDJSON log feeds with automatic schema inference and live streaming simulation.*

- **Advanced Querying & Tooling**:
  - *Implemented SQLite User-Defined Functions (UDFs) in Python for Shannon entropy calculation (detecting DGA domains and obfuscated payloads), case-insensitive regex, and CIDR subnet evaluation.*
  - *Designed complex SQL detection logic including recursive Common Table Expressions (CTEs) for parent-child process tree lineage and statistical baselining.*

---

## Technical Interview Talking Points

### 1. "How do you test detection rules before deploying to SIEM/EDR?"
> **Answer**:  
> *"In production environments, testing rules directly against live SIEM data can be slow, expensive, and risky. In TelemetryLab, I created a local offline SQLite playground where I can inject both normal baseline enterprise noise and realistic attack scenarios (e.g. Office spawning encoded PowerShell, LSASS dumping via Procdump, or password spraying). This allows me to verify that the query catches the malicious activity (True Positive) while also stress-testing the query against benign noise to measure and tune false positives before pushing to production."*

### 2. "How do you approach detection tuning and noise reduction?"
> **Answer**:  
> *"Detection engineering isn't just writing an alert; it's managing the rule's lifecycle. In TelemetryLab, each rule includes a `tune_exclusions` filter and a benchmark runner. The runner evaluates baseline alert volume versus tuned alert volume and outputs a quantitative metric (e.g., '82% noise reduction'). This ensures that every exclusion is documented, justified, and testable."*

### 3. "How do you handle inconsistent field names across multiple log sources?"
> **Answer**:  
> *"Schema discrepancies between vendors (e.g. `src_ip`, `SourceIp`, `client_ip`) create friction for detection rules. I built a schema normalization engine that supports 1-click conversion to ECS and OCSF standards, as well as regex-based mass renames. Every schema change is audited in a SQLite log table to maintain data integrity."*

---

## GitHub Repository Recommendations

### Suggested Repository Details:
- **Repository Name**: `telemetry-database` or `detection-engineering-lab`
- **Short Description**: `Portable SQLite telemetry playground & detection engineering testbed with MITRE ATT&CK scenarios, ECS/OCSF schema normalizer, and web SQL editor.`
- **Topics/Tags**:
  `detection-engineering`, `threat-hunting`, `sqlite`, `security-operations`, `mitre-attack`, `siem`, `cybersecurity-portfolio`, `python`, `infosec`

### What to Commit:
1. `seed.sql`: Clean SQL dump (allows anyone to inspect or run without binary SQLite files).
2. `core/`, `rules/`, `schema/`, `web/`: All Python, SQL, and Web assets.
3. `cli.py` & `app.py`: Entry points.
4. `sample_data/`: Sample CSV and JSON logs.
5. `tests/`: Automated unit tests.

### What to Ignore (`.gitignore`):
- `telemetry.db-wal`, `telemetry.db-shm` (temporary WAL files)
- `__pycache__/`
- `.DS_Store`
*(Note: You can commit `telemetry.db` directly if you want instant zero-command execution, or let users generate it with `python3 cli.py init && python3 cli.py seed` or `python3 cli.py import-dump seed.sql`).*

---

## Ideas for Future Enhancements to Showcase

1. **Sigma Rule Transpiler**:
   - Write a script that parses community Sigma YAML rules and translates them directly into TelemetryLab SQLite queries.
2. **Additional Telemetry Tables**:
   - Add specialized tables like `endpoint_pipe` (Named Pipes for Cobalt Strike / PsExec detection) or `identity_kerberos` (Event ID 4768/4769 for Kerberoasting / AS-REP Roasting).
3. **CI/CD Integration**:
   - Add a GitHub Actions workflow that executes `python3 -m unittest` and `python3 cli.py run-rules` on every push to demonstrate automated detection continuous integration (CI)!
