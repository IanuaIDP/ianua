-- Deletes the members' sessions that expired before the given time, the
-- end of their retention. A session in force expires later, so it stays.
DELETE FROM org_sessions
WHERE expires_at < $1
