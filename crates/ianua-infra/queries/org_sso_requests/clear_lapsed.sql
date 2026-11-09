-- Forgets the sign-ins whose time to be answered ran out by the given time.
DELETE FROM org_sso_requests
WHERE lapses_at <= $1
