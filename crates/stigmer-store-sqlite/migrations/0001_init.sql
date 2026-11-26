CREATE TABLE boards (
        id TEXT PRIMARY KEY,
        head_seq INTEGER NOT NULL,
        head_hash TEXT NOT NULL
    );
    CREATE TABLE messages (
        id TEXT PRIMARY KEY,
        board_id TEXT NOT NULL REFERENCES boards(id),
        channel TEXT NOT NULL,
        thread_id TEXT NOT NULL,
        author TEXT NOT NULL,
        text TEXT NOT NULL,
        at_ms INTEGER NOT NULL
    );
    CREATE TABLE labels (
        message_id TEXT NOT NULL REFERENCES messages(id),
        key TEXT NOT NULL,
        value TEXT NOT NULL
    );
    CREATE TABLE events (
        board_id TEXT NOT NULL REFERENCES boards(id),
        seq INTEGER NOT NULL,
        kind TEXT NOT NULL,
        actor TEXT NOT NULL,
        message_id TEXT NOT NULL,
        thread_id TEXT NOT NULL,
        channel TEXT NOT NULL,
        at_ms INTEGER NOT NULL,
        hash TEXT NOT NULL,
        PRIMARY KEY (board_id, seq)
    );