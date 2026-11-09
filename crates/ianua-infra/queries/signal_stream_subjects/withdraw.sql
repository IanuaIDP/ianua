-- Takes every subject a signal stream of a tenant lists off it.
DELETE FROM signal_stream_subjects
WHERE tenant_id = $1 AND stream_id = $2
