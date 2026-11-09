-- Whether some session of a tenant names the given one as the session it
-- replaced.
SELECT EXISTS (
    SELECT 1 FROM sessions WHERE tenant_id = $1 AND parent_id = $2
) AS "rotated!"
