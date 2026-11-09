-- Forgets the notes one tenant's monitors made before the given time: the
-- bus hands none of their events out again.
DELETE FROM event_reactions
WHERE tenant_id = $1 AND noted_at < $2
