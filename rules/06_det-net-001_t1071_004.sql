-- ==============================================================================
-- Rule ID: DET-NET-001 - DNS Tunneling & DGA via High Shannon Entropy Queries
-- Severity: HIGH | Stage: Active
-- MITRE ATT&CK: T1071.004 (Command and Control - Application Layer Protocol: DNS)
-- Description: Detects DNS queries with high Shannon entropy (score > 3.6) and length > 25 characters, characteristic of DNS tunneling and DGAs.
-- Tuning Exclusion: AND query NOT LIKE '%.cloudfront.net'
-- False Positives: CDNs (Akamai, CloudFront) and anti-virus telemetry endpoints often use pseudo-random subdomains. Tune known CDNs.
-- ==============================================================================

SELECT id, timestamp, host_name, src_ip, query, query_length, ENTROPY(query) AS entropy_score
FROM network_dns
WHERE query_length > 25
  AND ENTROPY(query) > 3.6
  AND query NOT LIKE '%.corp.local'
  AND query NOT LIKE '%.google.com';
