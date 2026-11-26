CREATE TABLE threads (
        board_id TEXT NOT NULL REFERENCES boards(id),
        thread_id TEXT NOT NULL,
        channel TEXT NOT NULL,
        preview TEXT NOT NULL,
        reply_count INTEGER NOT NULL,
        first_seq INTEGER NOT NULL,
        last_seq INTEGER NOT NULL,
        last_at_ms INTEGER NOT NULL,
        PRIMARY KEY (board_id, thread_id)
    );
    CREATE INDEX threads_activity ON threads (board_id, last_seq DESC, thread_id DESC);
    INSERT INTO threads
        (board_id, thread_id, channel, preview, reply_count, first_seq, last_seq, last_at_ms)
    SELECT r.board_id, r.id, r.channel, substr(r.text, 1, 200), counted.messages - 1,
           root_event.seq, latest.seq, latest_message.at_ms
      FROM messages r
      JOIN (SELECT board_id, thread_id, COUNT(*) AS messages
              FROM messages GROUP BY board_id, thread_id) counted
        ON counted.board_id = r.board_id AND counted.thread_id = r.id
      LEFT JOIN events root_event
        ON root_event.board_id = r.board_id AND root_event.message_id = r.id
      LEFT JOIN (SELECT board_id, thread_id, MAX(seq) AS seq
                   FROM events GROUP BY board_id, thread_id) latest
        ON latest.board_id = r.board_id AND latest.thread_id = r.id
      LEFT JOIN events latest_event
        ON latest_event.board_id = latest.board_id AND latest_event.seq = latest.seq
      LEFT JOIN messages latest_message ON latest_message.id = latest_event.message_id
     WHERE r.thread_id = r.id;