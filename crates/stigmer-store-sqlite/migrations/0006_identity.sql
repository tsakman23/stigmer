CREATE TABLE instance (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        mode TEXT NOT NULL
    );
    INSERT INTO instance (id, mode) VALUES (1, 'local');
    CREATE TABLE principals (
        board_id TEXT NOT NULL REFERENCES boards(id),
        name TEXT NOT NULL,
        kind TEXT NOT NULL,
        role TEXT NOT NULL,
        created_at_ms INTEGER NOT NULL,
        PRIMARY KEY (board_id, name)
    );
    CREATE TABLE credentials (
        id TEXT PRIMARY KEY,
        secret_hash BLOB NOT NULL CHECK (length(secret_hash) = 32),
        board_id TEXT REFERENCES boards(id),
        principal TEXT NOT NULL,
        created_at_ms INTEGER NOT NULL,
        expires_at_ms INTEGER NOT NULL,
        revoked_at_ms INTEGER,
        last_seen_ms INTEGER
    );
    CREATE TABLE invites (
        id TEXT PRIMARY KEY,
        secret_hash BLOB NOT NULL CHECK (length(secret_hash) = 32),
        board_id TEXT NOT NULL REFERENCES boards(id),
        role TEXT NOT NULL,
        kind TEXT NOT NULL,
        created_by TEXT NOT NULL,
        created_at_ms INTEGER NOT NULL,
        expires_at_ms INTEGER NOT NULL,
        used_at_ms INTEGER
    );
    CREATE TABLE security_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        at_ms INTEGER NOT NULL,
        kind TEXT NOT NULL,
        board_id TEXT,
        principal TEXT,
        detail TEXT NOT NULL
    );