-- ==============================================================================
-- Rule ID: DET-EP-005 - Process Tree Anomaly: Suspicious Child Processes of System Daemons
-- Severity: MEDIUM | Stage: Testing
-- MITRE ATT&CK: T1059.003 (Execution - Command and Scripting Interpreter: Windows Command Shell)
-- Description: Detects interactive command shells spawned directly by background Windows services (services.exe, svchost.exe).
-- Tuning Exclusion: 
-- False Positives: Occasionally triggered by legacy monitoring agents or custom Windows services.
-- ==============================================================================

SELECT id, timestamp, host_name, user_name, process_name, parent_process_name, command_line
FROM endpoint_process
WHERE LOWER(parent_process_name) IN ('services.exe', 'spoolsv.exe')
  AND LOWER(process_name) IN ('cmd.exe', 'powershell.exe', 'whoami.exe', 'net.exe');
