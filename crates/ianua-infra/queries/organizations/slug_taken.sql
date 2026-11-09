-- Whether an organization already has the given slug.
SELECT EXISTS (SELECT 1 FROM organizations WHERE slug = $1) AS "taken!"
