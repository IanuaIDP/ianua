-- Every client one person of one tenant consented to, with the session
-- they consented in, each pair once, from the codes still kept.
SELECT DISTINCT client_id, session_id
FROM oauth_codes
WHERE tenant_id = $1 AND user_id = $2
