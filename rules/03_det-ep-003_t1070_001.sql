-- ==============================================================================
-- Rule ID: DET-EP-003 - Security Event Log Cleared via Wevtutil
-- Severity: HIGH | Stage: Active
-- MITRE ATT&CK: T1070.001 (Defense Evasion - Indicator Removal: Clear Windows Event Logs)
-- Description: Detects execution of wevtutil.exe to clear the Security or System event logs, often used by attackers to hide tracks.
-- Tuning Exclusion: AND user_name NOT LIKE 'svc_installer'
-- False Positives: Automated system deployment or imaging scripts might reset logs. Verify parent process and execution user.
-- ==============================================================================

SELECT id, timestamp, host_name, user_name, process_name, command_line
FROM endpoint_process
WHERE LOWER(process_name) = 'wevtutil.exe'
  AND command_line REGEXP '(?i)\s+(cl|cleareventlog)\s+(security|system|application)';
