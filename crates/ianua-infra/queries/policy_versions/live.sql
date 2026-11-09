-- The live version of a tenant's access policy, which every request
-- reads, if one is live.
SELECT version, status, based_on, based_on_version, default_action, rules,
       submitted_by_kind, submitted_by_id, submitted_by_person
FROM policy_versions
WHERE tenant_id = $1 AND status = 'active'
