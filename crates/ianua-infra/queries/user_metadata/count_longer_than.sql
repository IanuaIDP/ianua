-- How many users of a tenant hold, under one attribute, a text or a list
-- item longer than the given number of characters.
SELECT count(*) AS "count!"
FROM user_metadata
WHERE tenant_id = $1 AND namespace = $2 AND key = $3
  AND (
      char_length(value_text) > $4
      OR EXISTS (
          SELECT 1 FROM UNNEST(value_array) AS item (word)
          WHERE char_length(item.word) > $4
      )
  )
