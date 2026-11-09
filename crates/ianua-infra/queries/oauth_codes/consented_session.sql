-- Only the client pairs reached by the selected person's session.
SELECT DISTINCT client_id, session_id
FROM oauth_codes
WHERE tenant_id = $1 AND user_id = $2 AND session_id = $3
