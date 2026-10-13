-- ==============================================================================
-- Rule ID: DET-ID-003 - CloudTrail Tampering: StopLogging / DeleteTrail Action
-- Severity: CRITICAL | Stage: Active
-- MITRE ATT&CK: T1562.001 (Defense Evasion - Impair Defenses: Disable Cloud Logs)
-- Description: Detects cloud audit events where an actor attempts to stop logging or delete security audit trails.
-- Tuning Exclusion: AND actor NOT LIKE '%Terraform%'
-- False Positives: Infrastructure-as-code teardown during maintenance windows. Validate actor credentials and ticket authorization.
-- ==============================================================================

SELECT id, timestamp, actor, action, resource_name, src_ip, status
FROM identity_cloud_audit
WHERE action IN ('StopLogging', 'DeleteTrail', 'UpdateTrail', 'DeleteFlowLogs')
  AND status = 'SUCCESS';
