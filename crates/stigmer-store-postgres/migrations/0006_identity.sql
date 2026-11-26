CREATE TABLE instance (
    id integer PRIMARY KEY CHECK (id = 1),
    mode text COLLATE "C" NOT NULL
);
INSERT INTO instance (id, mode) VALUES (1, 'local');
CREATE TABLE principals (
    board_id text COLLATE "C" NOT NULL REFERENCES boards(id),
    name text COLLATE "C" NOT NULL,
    kind text COLLATE "C" NOT NULL,
    role text COLLATE "C" NOT NULL,
    created_at_ms bigint NOT NULL,
    PRIMARY KEY (board_id, name)
);
CREATE TABLE credentials (
    id text COLLATE "C" PRIMARY KEY,
    secret_hash bytea NOT NULL CHECK (octet_length(secret_hash) = 32),
    board_id text COLLATE "C" REFERENCES boards(id),
    principal text COLLATE "C" NOT NULL,
    created_at_ms bigint NOT NULL,
    expires_at_ms bigint NOT NULL,
    revoked_at_ms bigint,
    last_seen_ms bigint
);
CREATE TABLE invites (
    id text COLLATE "C" PRIMARY KEY,
    secret_hash bytea NOT NULL CHECK (octet_length(secret_hash) = 32),
    board_id text COLLATE "C" NOT NULL REFERENCES boards(id),
    role text COLLATE "C" NOT NULL,
    kind text COLLATE "C" NOT NULL,
    created_by text COLLATE "C" NOT NULL,
    created_at_ms bigint NOT NULL,
    expires_at_ms bigint NOT NULL,
    used_at_ms bigint
);
CREATE TABLE security_log (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    at_ms bigint NOT NULL,
    kind text COLLATE "C" NOT NULL,
    board_id text COLLATE "C",
    principal text COLLATE "C",
    detail text NOT NULL
);
