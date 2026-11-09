-- Keeps a support impersonation: a new one is added, a known one of the same
-- tenant takes where it stands. Who acts as whom, why, for how long and
-- when it was asked for never change. It only moves the way the domain
-- allows from where it stands now: one awaiting consent to any state, an
-- active one only to ended, a declined or ended one nowhere. A save of a
-- copy read before another move changes nothing, so an ended request never
-- comes back.
INSERT INTO support_impersonations
    (id, tenant_id, admin_id, user_id, reason, window_minutes, consent, status,
     since, requested_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT (id) DO UPDATE SET
    status = EXCLUDED.status,
    since = EXCLUDED.since
WHERE support_impersonations.tenant_id = EXCLUDED.tenant_id
    AND (support_impersonations.status = 'awaiting_consent'
        OR (support_impersonations.status = 'active' AND EXCLUDED.status = 'ended'))
