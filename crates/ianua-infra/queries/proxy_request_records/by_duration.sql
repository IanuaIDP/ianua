-- The requests of the given tenants in the window, by how many
-- milliseconds they took: how many took each, and how many of those were
-- refused. Few distinct durations exist, so the rows stay few.
SELECT duration_ms AS "duration_ms!", count(*) AS "requests!",
       count(*) FILTER (WHERE outcome <> 'allowed') AS "refused!"
FROM proxy_request_records
WHERE tenant_id = ANY($1) AND occurred_at >= $2 AND occurred_at < $3
GROUP BY duration_ms
