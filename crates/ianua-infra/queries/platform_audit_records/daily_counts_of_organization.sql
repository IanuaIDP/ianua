-- How many of an organization's own records fell on each UTC day of the
-- window, by event type.
SELECT (occurred_at AT TIME ZONE 'UTC')::date AS "day!", event_type, count(*) AS "count!"
FROM platform_audit_records
WHERE organization_id = $1 AND occurred_at >= $2 AND occurred_at < $3
GROUP BY 1, 2
