-- Records a sign-in by a user of a tenant from a place in a country: a
-- first one from the country is added, a later one takes the country's
-- place and time, and an earlier one changes nothing.
INSERT INTO sign_in_countries
    (tenant_id, user_id, country_code, latitude, longitude, city, signed_in_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (tenant_id, user_id, country_code) DO UPDATE SET
    latitude = EXCLUDED.latitude,
    longitude = EXCLUDED.longitude,
    city = EXCLUDED.city,
    signed_in_at = EXCLUDED.signed_in_at
WHERE sign_in_countries.signed_in_at < EXCLUDED.signed_in_at
