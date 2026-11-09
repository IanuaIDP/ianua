-- The latest decision a member of an organization made on one kind of
-- consent.
SELECT id, organization_id, org_user_id, consent_type, granted, version,
       ip_address, recorded_at
FROM org_consents
WHERE organization_id = $1 AND org_user_id = $2 AND consent_type = $3
ORDER BY recorded_at DESC, id DESC
LIMIT 1
