-- ==============================================================================
-- Rule ID: DET-EP-002 - LSASS Memory Dumping via Procdump or Comsvcs
-- Severity: CRITICAL | Stage: Active
-- MITRE ATT&CK: T1003.001 (Credential Access - OS Credential Dumping: LSASS Memory)
-- Description: Detects command lines indicating dumping of Local Security Authority Subsystem Service (LSASS) memory to disk.
-- Tuning Exclusion: AND host_name NOT LIKE '%-SANDBOX%'
-- False Positives: Extremely rare in benign environments. Authorized crash dump troubleshooting by sysadmins should be investigated.
-- ==============================================================================

SELECT id, timestamp, host_name, user_name, process_name, command_line
FROM endpoint_process
WHERE (command_line REGEXP '(?i)(procdump.*-ma.*lsass|comsvcs(\.dll)?.*minidump|rundll32.*comsvcs.*minidump)')
   OR (LOWER(command_line) LIKE '%lsass.dmp%');
