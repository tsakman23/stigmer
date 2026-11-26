CREATE INDEX messages_thread ON messages (board_id, thread_id);
CREATE INDEX events_message ON events (board_id, message_id);
