-- ==============================================================================
-- TelemetryLab: Core SQLite Telemetry Database Schema
-- Designed for Detection Engineering, Threat Hunting, and Lifecycle Detections
-- ==============================================================================

PRAGMA foreign_keys = ON;

-- ------------------------------------------------------------------------------
-- 1. ENDPOINT TELEMETRY (Sysmon / EDR style)
-- ------------------------------------------------------------------------------

-- Process Creation Telemetry (Sysmon Event ID 1 / Defender / CrowdStrike)
CREATE TABLE IF NOT EXISTS endpoint_process (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,                -- ISO 8601 (YYYY-MM-DDTHH:MM:SSZ)
    host_name TEXT NOT NULL,
    user_name TEXT NOT NULL,
    process_name TEXT NOT NULL,             -- e.g. powershell.exe, cmd.exe
    process_path TEXT NOT NULL,             -- Full path
    process_id INTEGER NOT NULL,            -- PID
    parent_process_id INTEGER NOT NULL,     -- PPID
    parent_process_name TEXT NOT NULL,      -- e.g. explorer.exe, winword.exe
    parent_process_path TEXT,
    command_line TEXT NOT NULL,
    parent_command_line TEXT,
    process_hash_sha256 TEXT,
    integrity_level TEXT DEFAULT 'Medium',  -- Low, Medium, High, System
    is_elevated INTEGER DEFAULT 0           -- 0 = No, 1 = Yes
);

CREATE INDEX IF NOT EXISTS idx_ep_proc_time ON endpoint_process(timestamp);
CREATE INDEX IF NOT EXISTS idx_ep_proc_host ON endpoint_process(host_name);
CREATE INDEX IF NOT EXISTS idx_ep_proc_name ON endpoint_process(process_name);
CREATE INDEX IF NOT EXISTS idx_ep_proc_user ON endpoint_process(user_name);
CREATE INDEX IF NOT EXISTS idx_ep_proc_parent ON endpoint_process(parent_process_name);

-- File System Activity (Sysmon Event ID 11)
CREATE TABLE IF NOT EXISTS endpoint_file (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    host_name TEXT NOT NULL,
    user_name TEXT NOT NULL,
    process_name TEXT NOT NULL,
    process_id INTEGER,
    target_filename TEXT NOT NULL,
    target_filepath TEXT NOT NULL,
    file_hash_sha256 TEXT,
    action TEXT NOT NULL                    -- CREATE, MODIFY, DELETE, RENAME
);

CREATE INDEX IF NOT EXISTS idx_ep_file_time ON endpoint_file(timestamp);
CREATE INDEX IF NOT EXISTS idx_ep_file_host ON endpoint_file(host_name);
CREATE INDEX IF NOT EXISTS idx_ep_file_path ON endpoint_file(target_filepath);

-- Endpoint Network Connections (Sysmon Event ID 3)
CREATE TABLE IF NOT EXISTS endpoint_network (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    host_name TEXT NOT NULL,
    process_name TEXT NOT NULL,
    process_id INTEGER,
    src_ip TEXT NOT NULL,
    src_port INTEGER NOT NULL,
    dest_ip TEXT NOT NULL,
    dest_port INTEGER NOT NULL,
    protocol TEXT DEFAULT 'TCP',
    direction TEXT DEFAULT 'outbound'      -- inbound, outbound
);

CREATE INDEX IF NOT EXISTS idx_ep_net_time ON endpoint_network(timestamp);
CREATE INDEX IF NOT EXISTS idx_ep_net_dest ON endpoint_network(dest_ip, dest_port);

-- Windows Registry Modifications (Sysmon Event ID 12/13)
CREATE TABLE IF NOT EXISTS endpoint_registry (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    host_name TEXT NOT NULL,
    user_name TEXT,
    process_name TEXT NOT NULL,
    target_object TEXT NOT NULL,            -- e.g. HKLM\Software\Microsoft\Windows\CurrentVersion\Run
    details TEXT,
    event_type TEXT NOT NULL                -- SetInformation, CreateKey, DeleteKey
);

CREATE INDEX IF NOT EXISTS idx_ep_reg_time ON endpoint_registry(timestamp);
CREATE INDEX IF NOT EXISTS idx_ep_reg_target ON endpoint_registry(target_object);

-- ------------------------------------------------------------------------------
-- 2. NETWORK TELEMETRY (Zeek / VPC Flow / Firewall style)
-- ------------------------------------------------------------------------------

-- Network Flow Logs
CREATE TABLE IF NOT EXISTS network_flow (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    src_port INTEGER NOT NULL,
    dest_ip TEXT NOT NULL,
    dest_port INTEGER NOT NULL,
    protocol TEXT NOT NULL,                 -- TCP, UDP, ICMP
    bytes_sent INTEGER DEFAULT 0,
    bytes_recv INTEGER DEFAULT 0,
    packets INTEGER DEFAULT 0,
    action TEXT DEFAULT 'ALLOW',            -- ALLOW, BLOCK
    app_proto TEXT,                         -- http, ssl, dns, ssh
    conn_state TEXT                         -- SF, S0, REJ, OTH
);

CREATE INDEX IF NOT EXISTS idx_net_flow_time ON network_flow(timestamp);
CREATE INDEX IF NOT EXISTS idx_net_flow_src ON network_flow(src_ip);
CREATE INDEX IF NOT EXISTS idx_net_flow_dest ON network_flow(dest_ip, dest_port);

-- DNS Queries (Zeek dns.log / Sysmon Event ID 22)
CREATE TABLE IF NOT EXISTS network_dns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    host_name TEXT,
    src_ip TEXT NOT NULL,
    query TEXT NOT NULL,                    -- Domain requested
    qtype TEXT DEFAULT 'A',                 -- A, AAAA, TXT, MX
    answers TEXT,
    rcode TEXT DEFAULT 'NOERROR',           -- NOERROR, NXDOMAIN, SERVFAIL
    query_length INTEGER GENERATED ALWAYS AS (LENGTH(query)) VIRTUAL
);

CREATE INDEX IF NOT EXISTS idx_net_dns_time ON network_dns(timestamp);
CREATE INDEX IF NOT EXISTS idx_net_dns_query ON network_dns(query);

-- HTTP / Web Proxy Logs
CREATE TABLE IF NOT EXISTS network_http (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    dest_ip TEXT NOT NULL,
    method TEXT NOT NULL,                   -- GET, POST, PUT, DELETE
    host TEXT NOT NULL,
    uri TEXT NOT NULL,
    user_agent TEXT,
    status_code INTEGER DEFAULT 200,
    bytes INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_net_http_time ON network_http(timestamp);
CREATE INDEX IF NOT EXISTS idx_net_http_host ON network_http(host);

-- ------------------------------------------------------------------------------
-- 3. IDENTITY & CLOUD TELEMETRY (Active Directory / Okta / CloudTrail)
-- ------------------------------------------------------------------------------

-- Authentication Logs (Win Event ID 4624/4625, Okta, Azure AD)
CREATE TABLE IF NOT EXISTS identity_auth (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    user_name TEXT NOT NULL,
    user_domain TEXT DEFAULT 'CORP',
    src_ip TEXT NOT NULL,
    logon_type TEXT DEFAULT 'Network',      -- Interactive, Network, RemoteInteractive (RDP)
    auth_status TEXT NOT NULL,              -- SUCCESS, FAILURE
    failure_reason TEXT,                    -- BadPassword, AccountLocked, UserNotFound
    target_service TEXT,                    -- workstation-01, o365, vpn
    mfa_used INTEGER DEFAULT 0,             -- 0 = No, 1 = Yes
    geo_country TEXT DEFAULT 'US',
    user_agent TEXT
);

CREATE INDEX IF NOT EXISTS idx_id_auth_time ON identity_auth(timestamp);
CREATE INDEX IF NOT EXISTS idx_id_auth_user ON identity_auth(user_name);
CREATE INDEX IF NOT EXISTS idx_id_auth_status ON identity_auth(auth_status);
CREATE INDEX IF NOT EXISTS idx_id_auth_ip ON identity_auth(src_ip);

-- Cloud Infrastructure Audit Logs (AWS CloudTrail / GCP Audit / Azure Activity)
CREATE TABLE IF NOT EXISTS identity_cloud_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    actor TEXT NOT NULL,                    -- IAM user / role / service account
    actor_type TEXT DEFAULT 'IAMUser',
    action TEXT NOT NULL,                   -- e.g. CreateAccessKey, StopLogging, AuthorizeSecurityGroupIngress
    resource_name TEXT,
    resource_type TEXT,
    src_ip TEXT NOT NULL,
    user_agent TEXT,
    status TEXT DEFAULT 'SUCCESS',          -- SUCCESS, AccessDenied, ClientError
    error_code TEXT
);

CREATE INDEX IF NOT EXISTS idx_cloud_time ON identity_cloud_audit(timestamp);
CREATE INDEX IF NOT EXISTS idx_cloud_actor ON identity_cloud_audit(actor);
CREATE INDEX IF NOT EXISTS idx_cloud_action ON identity_cloud_audit(action);

-- ------------------------------------------------------------------------------
-- 4. DETECTION ENGINE & EXPERIMENTATION METADATA
-- ------------------------------------------------------------------------------

-- Detection Rules Catalog
CREATE TABLE IF NOT EXISTS detection_rules (
    rule_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    severity TEXT NOT NULL CHECK(severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'INFORMATIONAL')),
    mitre_attack_id TEXT,                   -- e.g. T1059.001
    mitre_tactic TEXT,                      -- e.g. Execution, Defense Evasion
    mitre_technique TEXT,
    description TEXT,
    sql_query TEXT NOT NULL,
    threshold INTEGER DEFAULT 1,
    lifecycle_stage TEXT DEFAULT 'Active',  -- Prototype, Testing, Active, Deprecated
    status TEXT DEFAULT 'ENABLED',          -- ENABLED, DISABLED
    tune_exclusions TEXT                    -- JSON or SQL WHERE clause filter
);

-- Detection Alerts Produced by Test Runs
CREATE TABLE IF NOT EXISTS detection_alerts (
    alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    alert_time TEXT NOT NULL,
    matched_record_id INTEGER,
    entity_host TEXT,
    entity_user TEXT,
    context_json TEXT,
    FOREIGN KEY(rule_id) REFERENCES detection_rules(rule_id)
);

CREATE INDEX IF NOT EXISTS idx_alert_run ON detection_alerts(run_id);
CREATE INDEX IF NOT EXISTS idx_alert_rule ON detection_alerts(rule_id);
CREATE INDEX IF NOT EXISTS idx_alert_time ON detection_alerts(alert_time);

-- Schema Migrations & Mass-Rename Audit Log
CREATE TABLE IF NOT EXISTS schema_audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    operation_type TEXT NOT NULL,           -- RENAME_COLUMN, RENAME_TABLE, NORMALIZE_ECS, NORMALIZE_OCSF
    target_table TEXT NOT NULL,
    old_value TEXT NOT NULL,
    new_value TEXT NOT NULL,
    status TEXT NOT NULL                    -- SUCCESS, FAILED
);
