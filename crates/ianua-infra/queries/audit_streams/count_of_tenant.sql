-- How many places a tenant streams its audit trail to against its plan,
-- failing and paused ones too.
SELECT count(*) AS "count!"
FROM audit_streams
WHERE tenant_id = $1
