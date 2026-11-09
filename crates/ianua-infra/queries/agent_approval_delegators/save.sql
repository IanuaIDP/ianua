-- Keeps the people behind the delegation of an approval request of a
-- tenant in one statement. They are named once, when the request is
-- raised, so those already kept stay as they are.
INSERT INTO agent_approval_delegators (tenant_id, approval_id, place, account_kind, account_id,
                                       person)
SELECT $1, $2, kept.place, kept.account_kind, kept.account_id, kept.person
FROM UNNEST($3::smallint[], $4::text[], $5::uuid[], $6::text[])
    AS kept (place, account_kind, account_id, person)
ON CONFLICT (tenant_id, approval_id, place) DO NOTHING
