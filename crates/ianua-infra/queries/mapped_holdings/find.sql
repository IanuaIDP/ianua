-- What a connection's group mapping gave one account of a tenant: the
-- roles and the groups, each in the order they were given.
SELECT h.connection_id, h.user_id,
       ARRAY(
           SELECT r.role_id
           FROM mapped_holding_roles r
           WHERE r.tenant_id = h.tenant_id AND r.connection_id = h.connection_id
             AND r.user_id = h.user_id
           ORDER BY r.position
       ) AS "role_ids!",
       ARRAY(
           SELECT g.group_id
           FROM mapped_holding_groups g
           WHERE g.tenant_id = h.tenant_id AND g.connection_id = h.connection_id
             AND g.user_id = h.user_id
           ORDER BY g.position
       ) AS "group_ids!"
FROM mapped_holdings h
WHERE h.tenant_id = $1 AND h.connection_id = $2 AND h.user_id = $3
