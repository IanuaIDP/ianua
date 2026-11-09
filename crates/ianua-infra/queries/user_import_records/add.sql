-- Writes every record one import of a tenant was sent, in one statement,
-- each on the line it stood on.
INSERT INTO user_import_records
    (tenant_id, import_id, line, email, display_name, given_name, family_name,
     preferred_username, picture, phone_number, external_id, department,
     manager_id, employee_number, password_hash)
SELECT $1, $2, sent.line, sent.email, sent.display_name, sent.given_name,
       sent.family_name, sent.preferred_username, sent.picture, sent.phone_number,
       sent.external_id, sent.department, sent.manager_id, sent.employee_number,
       sent.password_hash
FROM UNNEST($3::integer[], $4::text[], $5::text[], $6::text[], $7::text[], $8::text[],
            $9::text[], $10::text[], $11::text[], $12::text[], $13::uuid[], $14::text[],
            $15::text[])
    AS sent (line, email, display_name, given_name, family_name, preferred_username,
             picture, phone_number, external_id, department, manager_id,
             employee_number, password_hash)
