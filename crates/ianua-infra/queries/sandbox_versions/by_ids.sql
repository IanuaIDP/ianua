-- The sandbox versions of one tenant that the ids name.
SELECT id, sandbox_id, number, program, runtime, image, code, packages, image_bytes,
    run_seconds, memory_mib, build, bundle_digest, bundle_bytes, unlisted, failure,
    failure_detail, scan_high, scan_medium, scan_low, saved_by, created_at, updated_at,
    allowed_hosts, source_integration, source_repository, source_path, source_commit,
    held_agent
FROM sandbox_versions
WHERE tenant_id = $1 AND id = ANY($2)
