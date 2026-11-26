ALTER TABLE boards ADD COLUMN created_at_ms INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE boards ADD COLUMN created_by TEXT;
    ALTER TABLE boards ADD COLUMN archived_at_ms INTEGER;