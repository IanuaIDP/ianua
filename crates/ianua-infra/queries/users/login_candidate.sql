-- The account of a tenant at the given address that has a password, as a
-- password sign-in needs it: its standing, its password's hash, whether an
-- accepted invitation still vouches for it, whether it holds a confirmed
-- second factor answered with a code, and how many passkeys it holds.
SELECT u.id, u.status, u.email_verified, u.route_vouches, p.password_hash,
       EXISTS (
           SELECT 1 FROM mfa_enrollments m
           WHERE m.tenant_id = u.tenant_id AND m.user_id = u.id AND m.status = 'verified'
       ) AS "code_factor!",
       (
           SELECT count(*) FROM passkey_credentials k
           WHERE k.tenant_id = u.tenant_id AND k.user_id = u.id
       ) AS "passkeys!"
FROM users u
JOIN user_passwords p ON p.tenant_id = u.tenant_id AND p.user_id = u.id
WHERE u.tenant_id = $1 AND u.email = $2
