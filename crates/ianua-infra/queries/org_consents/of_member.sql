-- Every consent decision a member of an organization made, newest first.
SELECT id, organization_id, org_user_id, consent_type, granted, version,
       ip_address, recorded_at
FROM org_consents
WHERE organization_id = $1 AND org_user_id = $2
ORDER BY recorded_at DESC, id DESC
