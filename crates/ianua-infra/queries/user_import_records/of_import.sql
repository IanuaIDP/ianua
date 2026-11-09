-- The records one import of a tenant was sent, in the order they came.
SELECT email, display_name, given_name, family_name, preferred_username, picture,
       phone_number, external_id, department, manager_id, employee_number,
       password_hash
FROM user_import_records
WHERE tenant_id = $1 AND import_id = $2
ORDER BY line
