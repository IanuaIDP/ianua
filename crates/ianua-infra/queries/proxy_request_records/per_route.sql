-- The tenant's traffic per route in the window, busiest first, at most the
-- given number of routes: requests, refusals, upstream failures and the
-- median and 95th-percentile times, with the names the route and its
-- service have now. Traffic that matched no route is left out.
SELECT p.route_id AS "route_id!", r.name AS "route_name?", r.service_id AS "service_id?",
       s.name AS "service_name?", count(*) AS "requests!",
       count(*) FILTER (WHERE p.outcome <> 'allowed') AS "denied!",
       count(*) FILTER (WHERE p.outcome = 'allowed' AND p.status >= 500) AS "server_errors!",
       round(percentile_cont(0.5) WITHIN GROUP (ORDER BY p.duration_ms))::integer AS "p50?",
       round(percentile_cont(0.95) WITHIN GROUP (ORDER BY p.duration_ms))::integer AS "p95?"
FROM proxy_request_records p
LEFT JOIN routes r ON r.tenant_id = p.tenant_id AND r.id = p.route_id
LEFT JOIN services s ON s.tenant_id = r.tenant_id AND s.id = r.service_id
WHERE p.tenant_id = $1 AND p.route_id IS NOT NULL
    AND p.occurred_at >= $2 AND p.occurred_at < $3
GROUP BY p.route_id, r.name, r.service_id, s.name
ORDER BY count(*) DESC, p.route_id
LIMIT $4
