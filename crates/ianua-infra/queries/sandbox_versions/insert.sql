-- Adds a version just saved. A sandbox's number is taken once, so a second
-- save made from the same read is refused by its constraint.
INSERT INTO sandbox_versions
    (id, tenant_id, sandbox_id, number, program, runtime, image, code, packages, image_bytes,
     run_seconds, memory_mib, build, bundle_digest, bundle_bytes, unlisted, failure,
     failure_detail, scan_high, scan_medium, scan_low, saved_by, created_at, updated_at,
     allowed_hosts, source_integration, source_repository, source_path, source_commit,
     held_agent)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19,
    $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30)
