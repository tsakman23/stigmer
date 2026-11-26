CREATE TABLE boards (
    id text COLLATE "C" PRIMARY KEY,
    head_seq bigint NOT NULL,
    head_hash bytea NOT NULL CHECK (octet_length(head_hash) = 32)
);
CREATE TABLE messages (
    id text COLLATE "C" PRIMARY KEY,
    board_id text COLLATE "C" NOT NULL REFERENCES boards(id),
    channel text COLLATE "C" NOT NULL,
    thread_id text COLLATE "C" NOT NULL,
    author text COLLATE "C" NOT NULL,
    text text NOT NULL,
    at_ms bigint NOT NULL
);
CREATE TABLE labels (
    message_id text COLLATE "C" NOT NULL REFERENCES messages(id),
    position integer NOT NULL,
    key text COLLATE "C" NOT NULL,
    value text COLLATE "C" NOT NULL,
    PRIMARY KEY (message_id, position)
);
CREATE TABLE events (
    board_id text COLLATE "C" NOT NULL REFERENCES boards(id),
    seq bigint NOT NULL,
    kind text COLLATE "C" NOT NULL,
    actor text COLLATE "C" NOT NULL,
    message_id text COLLATE "C" NOT NULL,
    thread_id text COLLATE "C" NOT NULL,
    channel text COLLATE "C" NOT NULL,
    at_ms bigint NOT NULL,
    hash bytea NOT NULL CHECK (octet_length(hash) = 32),
    PRIMARY KEY (board_id, seq)
);
