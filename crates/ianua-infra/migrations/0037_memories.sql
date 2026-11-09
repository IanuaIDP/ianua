-- Memories: a tenant's named stores of texts and their vectors, which
-- workflow steps keep texts in and search for the most similar, filled by
-- the embedding model a model provider offers beside its chat model.
--
-- The vectors are kept with pgvector, inside the platform's own Postgres,
-- where row-level security keeps each tenant's rows to itself as it does
-- every other table. A deployment may keep them in another vector store
-- instead; the memories themselves are kept here either way.

CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE memories (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    embedding_source text NOT NULL,
    -- no foreign key: the memory names the provider it was filled through
    -- for good; once that provider is gone it takes no texts, and its own
    -- are kept until a person deletes it.
    provider_id uuid,
    embedding_model text NOT NULL,
    vector_size integer NOT NULL,
    clearance text NOT NULL,
    status text NOT NULL,
    deleted_after timestamptz,
    created_by jsonb NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT memories_tenant_id_key UNIQUE (tenant_id, id),
    CONSTRAINT memories_source_known CHECK (
        (embedding_source = 'platform' AND provider_id IS NULL)
        OR (embedding_source = 'provider' AND provider_id IS NOT NULL)
    ),
    CONSTRAINT memories_vector_size_in_range CHECK (vector_size BETWEEN 1 AND 4096),
    CONSTRAINT memories_status_known CHECK (
        (status = 'active' AND deleted_after IS NULL)
        OR (status = 'deletion_requested' AND deleted_after IS NOT NULL)
    ),
    CONSTRAINT memories_clearance_known CHECK (clearance IN (
        'public', 'internal', 'confidential', 'restricted'
    )),
    CONSTRAINT memories_changed_after_made CHECK (updated_at >= created_at)
);

ALTER TABLE memories ENABLE ROW LEVEL SECURITY;
ALTER TABLE memories FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON memories
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- The tenant's memories by name, and the ones waiting to be deleted by
-- when they are due, for the sweep.
CREATE INDEX memories_by_name ON memories (tenant_id, name, id);
CREATE INDEX memories_by_deletion ON memories (deleted_after, tenant_id)
    WHERE status = 'deletion_requested';

-- One text a memory keeps, with its vector. A search compares the vectors
-- of one memory exactly, nearest first.
CREATE TABLE memory_entries (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    memory_id uuid NOT NULL,
    text text NOT NULL,
    embedding vector NOT NULL,
    exposure text NOT NULL,
    created_at timestamptz NOT NULL,
    FOREIGN KEY (tenant_id, memory_id)
        REFERENCES memories (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT memory_entries_exposure_known CHECK (exposure IN (
        'public', 'internal', 'confidential', 'restricted'
    ))
);

ALTER TABLE memory_entries ENABLE ROW LEVEL SECURITY;
ALTER TABLE memory_entries FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON memory_entries
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- One memory's entries, for a search and for deleting them all.
CREATE INDEX memory_entries_by_memory ON memory_entries (tenant_id, memory_id);
