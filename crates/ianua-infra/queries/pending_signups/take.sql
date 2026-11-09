-- Hands out the sign-up whose link carries the token with the given hash and
-- forgets it in the same statement, so a link works once.
DELETE FROM pending_signups
WHERE token_hash = $1
RETURNING token_hash, email, company_name, tenant_name, admin_display_name, password_hash,
          timezone, locale, requested_at, expires_at
