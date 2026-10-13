-- ==============================================================================
-- Rule ID: DET-EP-001 - PowerShell Download Cradle Spawned by Office Application
-- Severity: CRITICAL | Stage: Active
-- MITRE ATT&CK: T1059.001 (Execution - Command and Scripting Interpreter: PowerShell)
-- Description: Detects Microsoft Office processes (Word, Excel) spawning PowerShell with download cradles (IEX, WebClient) or bypass flags.
-- Tuning Exclusion: AND user_name NOT IN ('svc_automation')
-- False Positives: Legitimate enterprise macro workflows may occasionally spawn scripts. Tune out specific signed automation scripts or service accounts.
-- ==============================================================================

SELECT id, timestamp, host_name, user_name, process_name, parent_process_name, command_line
FROM endpoint_process
WHERE LOWER(parent_process_name) IN ('winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe')
  AND LOWER(process_name) IN ('powershell.exe', 'pwsh.exe', 'cmd.exe')
  AND (command_line REGEXP '(?i)(downloadstring|downloadfile|iex|invoke-expression|-enc|-encodedcommand)');
