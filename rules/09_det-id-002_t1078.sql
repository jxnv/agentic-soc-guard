-- ==============================================================================
-- Rule ID: DET-ID-002 - Impossible Travel: User Authenticating from Multiple Countries
-- Severity: HIGH | Stage: Active
-- MITRE ATT&CK: T1078 (Defense Evasion - Valid Accounts)
-- Description: Detects single user accounts successfully logging in from two different countries within the dataset timeframe.
-- Tuning Exclusion: AND user_name NOT LIKE 'svc_%'
-- False Positives: Users connecting via corporate VPN while simultaneously roaming, or utilizing cloud proxies (Zscaler).
-- ==============================================================================

SELECT user_name, COUNT(DISTINCT geo_country) AS country_count, GROUP_CONCAT(DISTINCT geo_country) AS countries, GROUP_CONCAT(DISTINCT src_ip) AS ips, MIN(timestamp) AS first_seen, MAX(timestamp) AS last_seen
FROM identity_auth
WHERE auth_status = 'SUCCESS'
GROUP BY user_name
HAVING COUNT(DISTINCT geo_country) > 1;
