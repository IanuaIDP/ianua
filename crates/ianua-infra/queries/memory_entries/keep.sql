-- Keeps one text of a memory with its vector, written as pgvector reads a
-- vector from text.
INSERT INTO memory_entries (id, tenant_id, memory_id, text, embedding, exposure, created_at)
VALUES ($1, $2, $3, $4, $5::text::vector, $6, $7)
