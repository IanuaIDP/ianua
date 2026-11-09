-- Withdraws the challenge a token names.
DELETE FROM acme_challenges
WHERE token = $1
