-- The countries a user of a tenant signed in from, each with the place and
-- time of the latest sign-in from it, the latest first.
SELECT country_code, latitude, longitude, city, signed_in_at
FROM sign_in_countries
WHERE tenant_id = $1 AND user_id = $2
ORDER BY signed_in_at DESC, country_code
