-- Keeps an organization member's or operator's address change, replacing
-- any earlier one of the same person whole: a new change is asked for at
-- its own time. A change keeps its cancel link for life, so a row with the
-- same cancel link is the same change, and once confirmed or cancelled it
-- takes nothing new: of a confirmation and a cancellation read together,
-- or two confirmations, only the first is kept.
INSERT INTO org_email_changes
    (principal_id, from_email, new_email, token_hash, cancel_token_hash,
     state, settled_at, created_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
ON CONFLICT (principal_id) DO UPDATE SET
    from_email = EXCLUDED.from_email,
    new_email = EXCLUDED.new_email,
    token_hash = EXCLUDED.token_hash,
    cancel_token_hash = EXCLUDED.cancel_token_hash,
    state = EXCLUDED.state,
    settled_at = EXCLUDED.settled_at,
    created_at = EXCLUDED.created_at,
    expires_at = EXCLUDED.expires_at
WHERE org_email_changes.state = 'waiting'
    OR org_email_changes.cancel_token_hash <> EXCLUDED.cancel_token_hash
