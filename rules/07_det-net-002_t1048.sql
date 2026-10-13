-- ==============================================================================
-- Rule ID: DET-NET-002 - Data Exfiltration via Massive Outbound Flow
-- Severity: HIGH | Stage: Active
-- MITRE ATT&CK: T1048 (Exfiltration - Exfiltration Over Alternative Protocol)
-- Description: Detects outbound network flows exceeding 1 GB from internal subnets to external non-RFC1918 addresses.
-- Tuning Exclusion: AND dest_port != 873
-- False Positives: Offsite database backups, cloud storage syncs (S3, Dropbox). Filter destination IP ranges belonging to known backup providers.
-- ==============================================================================

SELECT id, timestamp, src_ip, dest_ip, dest_port, protocol, bytes_sent, ROUND(bytes_sent / 1073741824.0, 2) AS gb_sent
FROM network_flow
WHERE bytes_sent > 1000000000
  AND IP_IN_CIDR(src_ip, '10.0.0.0/8')
  AND NOT IP_IN_CIDR(dest_ip, '10.0.0.0/8');
