ALTER TABLE messages ADD COLUMN author_kind text COLLATE "C" NOT NULL DEFAULT 'local';
