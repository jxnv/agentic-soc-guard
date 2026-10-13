-- ==============================================================================
-- Rule ID: DET-EP-004 - Persistence via Windows Registry Run Keys
-- Severity: HIGH | Stage: Active
-- MITRE ATT&CK: T1547.001 (Persistence - Boot or Logon Autostart Execution: Registry Run Keys)
-- Description: Detects modifications to Windows Run or RunOnce keys commonly abused to maintain persistence across reboots.
-- Tuning Exclusion: AND details NOT LIKE '%Slack.exe%'
-- False Positives: Legitimate enterprise software updates (OneDrive, Slack, Zoom). Exclude known signed enterprise vendor executables.
-- ==============================================================================

SELECT id, timestamp, host_name, user_name, process_name, target_object, details
FROM endpoint_registry
WHERE (target_object LIKE '%\CurrentVersion\Run%' OR target_object LIKE '%\CurrentVersion\RunOnce%')
  AND details NOT LIKE '%Google\Chrome%'
  AND details NOT LIKE '%Microsoft\OneDrive%';
