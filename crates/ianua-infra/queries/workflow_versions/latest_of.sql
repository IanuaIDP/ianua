-- The highest-numbered version of each workflow of one tenant named, with
-- where each workflow came from.
SELECT v.workflow_id, v.version, v.name, v.graph, v.trigger_kind, v.trigger_schedule,
    v.trigger_event, v.trigger_service, v.trigger_change, v.run_limit_secs, v.status, v.created_by, v.edited_by, v.authors,
    v.published_by, v.hold, v.description, v.layout, v.failure_alert, w.origin, w.flow_description, v.created_at, v.updated_at
FROM workflow_versions v
JOIN workflows w ON w.tenant_id = v.tenant_id AND w.id = v.workflow_id
WHERE v.tenant_id = $1 AND v.workflow_id = ANY($2)
    AND NOT EXISTS (
        SELECT 1 FROM workflow_versions later
        WHERE later.tenant_id = v.tenant_id AND later.workflow_id = v.workflow_id
            AND later.version > v.version
    )
