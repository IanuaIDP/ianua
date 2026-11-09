-- Whether the platform has any operator at all, read from one row at most.
SELECT EXISTS (SELECT 1 FROM operators LIMIT 1) AS "any!"
