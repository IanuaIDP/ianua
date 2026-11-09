-- How many notifications of an operator's inbox are not yet read.
SELECT count(*) AS "count!"
FROM platform_notifications
WHERE operator_id = $1 AND NOT read
