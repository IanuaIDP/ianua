-- Claims round $2 of sweep $1 at $3, answering the round when this was the
-- first claim. Rounds claimed before $4 are removed on the way.
WITH cleared AS (
    DELETE FROM platform_sweep_claims WHERE claimed_at < $4
)
INSERT INTO platform_sweep_claims (sweep, round, claimed_at)
VALUES ($1, $2, $3)
ON CONFLICT (sweep, round) DO NOTHING
RETURNING round
