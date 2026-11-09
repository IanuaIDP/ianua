-- Removes the challenges that ran out by the given moment.
DELETE FROM acme_challenges
WHERE expires_at <= $1
