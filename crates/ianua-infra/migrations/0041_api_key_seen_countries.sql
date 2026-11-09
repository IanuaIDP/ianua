-- The countries the key signed in from, oldest first, at most sixteen: a
-- sign-in from one not here is recorded as news.
ALTER TABLE api_keys ADD COLUMN seen_countries text[] DEFAULT '{}'::text[] NOT NULL;

ALTER TABLE api_keys ADD CONSTRAINT api_keys_seen_countries_bounded CHECK ((cardinality(seen_countries) <= 16)) NOT VALID;
ALTER TABLE api_keys VALIDATE CONSTRAINT api_keys_seen_countries_bounded;
