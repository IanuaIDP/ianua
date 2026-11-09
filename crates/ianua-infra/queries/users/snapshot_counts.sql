-- The counts a snapshot keeps of one tenant at the given moment: its
-- people, every account not deactivated or closing, and its active
-- sessions not yet expired.
SELECT (SELECT count(*) FROM users
        WHERE tenant_id = $1
            AND status IN ('invited', 'pending_verification', 'active', 'locked'))
           AS "users_count!",
       (SELECT count(*) FROM sessions
        WHERE tenant_id = $1 AND status = 'active' AND expires_at > $2)
           AS "active_sessions_count!"
