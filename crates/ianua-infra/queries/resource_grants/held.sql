-- Which of the given relations on named resources a principal of a tenant
-- holds, each relation at the same place in the two lists as its
-- resource.
SELECT g.relation, g.object_ref
FROM resource_grants g
WHERE g.tenant_id = $1 AND g.subject_kind = $2 AND g.subject_id = $3
  AND (g.relation, g.object_ref) IN (
      SELECT wanted.relation, wanted.object_ref
      FROM UNNEST($4::text[], $5::text[]) AS wanted (relation, object_ref)
  )
