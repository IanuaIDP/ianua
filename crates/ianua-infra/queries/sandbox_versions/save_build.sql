-- Writes what building a version's bundle, or scanning its image, came to,
-- only while it is still being built: a second try that raced the first
-- finds no row, and the first result stands.
UPDATE sandbox_versions SET
    build = $3,
    bundle_digest = $4,
    bundle_bytes = $5,
    unlisted = $6,
    failure = $7,
    failure_detail = $8,
    scan_high = $9,
    scan_medium = $10,
    scan_low = $11,
    updated_at = $12
WHERE tenant_id = $1 AND id = $2 AND build = 'building'
