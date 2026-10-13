-- ==============================================================================
-- Rule ID: DET-ID-001 - Password Spraying: Multiple Accounts Failed from Same Source IP
-- Severity: HIGH | Stage: Active
-- MITRE ATT&CK: T1110.003 (Credential Access - Brute Force: Password Spraying)
-- Description: Detects single source IPs generating authentication failures across 5 or more distinct user accounts.
-- Tuning Exclusion: AND src_ip NOT IN ('10.0.4.99')
-- False Positives: Internal vulnerability scanners (e.g. Nessus, Qualys) performing authenticated testing. Exclude known scanner IPs.
-- ==============================================================================

SELECT src_ip, COUNT(DISTINCT user_name) AS targeted_users, COUNT(*) AS failure_count, GROUP_CONCAT(DISTINCT user_name) AS user_list, MIN(timestamp) AS start_time, MAX(timestamp) AS end_time
FROM identity_auth
WHERE auth_status = 'FAILURE'
GROUP BY src_ip
HAVING COUNT(DISTINCT user_name) >= 4;
