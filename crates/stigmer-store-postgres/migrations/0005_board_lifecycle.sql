ALTER TABLE boards ADD COLUMN created_at_ms bigint NOT NULL DEFAULT 0;
ALTER TABLE boards ADD COLUMN created_by text COLLATE "C";
ALTER TABLE boards ADD COLUMN archived_at_ms bigint;
