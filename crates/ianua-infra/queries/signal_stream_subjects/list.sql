-- Lists the given users and agents on a signal stream of a tenant, all in
-- one statement, each at its place in the list: at each place a user or an
-- agent, the other left empty.
INSERT INTO signal_stream_subjects (tenant_id, stream_id, position, user_id, agent_id)
SELECT $1, $2, listed.position, listed.user_id, listed.agent_id
FROM UNNEST($3::uuid[], $4::uuid[]) WITH ORDINALITY AS listed (user_id, agent_id, position)
