-- The challenge a token names, if one is outstanding.
SELECT token, key_authorization, domain, expires_at
FROM acme_challenges
WHERE token = $1
