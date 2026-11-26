ALTER TABLE messages ADD COLUMN idempotency_key TEXT;
    CREATE UNIQUE INDEX messages_idempotency
        ON messages (board_id, author, idempotency_key)
        WHERE idempotency_key IS NOT NULL;