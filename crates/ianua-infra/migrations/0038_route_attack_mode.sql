-- Until when the route is in attack mode, every request to it checked
-- harder before its pipeline; NULL when it is not. It ends on its own.
ALTER TABLE routes ADD COLUMN attack_mode_until timestamp with time zone;

-- Attack mode ends after the route was made.
ALTER TABLE routes ADD CONSTRAINT routes_attack_mode_after_created CHECK ((attack_mode_until > created_at)) NOT VALID;
ALTER TABLE routes VALIDATE CONSTRAINT routes_attack_mode_after_created;
