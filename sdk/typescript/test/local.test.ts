import assert from "node:assert/strict";
import { after, before, test } from "node:test";

import { Stigmer, StigmerError } from "../src/index.js";
import { cleanup, startServer, type TestServer } from "./harness.js";

let server: TestServer;
before(async () => {
  server = await startServer();
});
after(async () => {
  await server?.stop();
  await cleanup();
});

const as = (name: string) => new Stigmer({ url: server.url, as: name });

test("post_then_read_thread_roundtrip", async () => {
  const alice = as("alice");
  const posted = await alice.post("rt/roundtrip", "hello board", { labels: { kind: "note" } });
  assert.equal(posted.replayed, false);
  assert.equal(posted.message.author, "alice");
  assert.equal(posted.message.channel, "rt/roundtrip");

  const thread = await alice.readThread(posted.message.id);
  assert.equal(thread.root.text, "hello board");
  assert.deepEqual(thread.root.labels, [{ key: "kind", value: "note" }]);
  assert.deepEqual(thread.replies, []);

  const listing = await alice.readChannel("rt/");
  assert.ok(listing.some((t) => t.thread_id === posted.message.id && t.root_text_preview === "hello board"));
});

test("reply_in_thread", async () => {
  const root = await as("alice").post("rt/reply", "question?");
  const reply = await as("bob").reply(root.message.id, "answer");
  assert.equal(reply.message.thread_id, root.message.id);
  assert.equal(reply.event.kind, "message.replied");
  const thread = await as("alice").readThread(root.message.id);
  assert.deepEqual(thread.replies.map((m) => [m.author, m.text]), [["bob", "answer"]]);
});

test("idempotency_key_replays", async () => {
  const alice = as("alice");
  const first = await alice.post("rt/idem", "once", { key: "idem-key-1" });
  const second = await alice.post("rt/idem", "once", { key: "idem-key-1" });
  assert.equal(first.replayed, false);
  assert.equal(second.replayed, true);
  assert.equal(second.message.id, first.message.id);
});

test("events_filters_by_channel_thread_label", async () => {
  const alice = as("alice");
  const a = await alice.post("rt/filter/a", "in a", { labels: { team: "red" } });
  const b = await alice.post("rt/filter/b", "in b", { labels: { team: "blue" } });
  const reply = await alice.reply(a.message.id, "reply in a");

  const byChannel = await alice.events({ channel: "rt/filter/b" });
  assert.deepEqual(byChannel.events.map((e) => e.message_id), [b.message.id]);

  const byThread = await alice.events({ thread: a.message.id });
  assert.deepEqual(byThread.events.map((e) => e.message_id), [a.message.id, reply.message.id]);

  const byLabel = await alice.events({ channel: "rt/filter", label: "team=blue" });
  assert.deepEqual(byLabel.events.map((e) => e.message_id), [b.message.id]);
});

test("wait_returns_when_another_client_posts", async () => {
  const waiting = as("carol").wait({ fromNow: true, channel: "rt/wake", timeoutMs: 20_000 });
  await new Promise((r) => setTimeout(r, 300));
  const posted = await as("alice").post("rt/wake", "wake up");
  const result = await waiting;
  assert.equal(result.timedOut, false);
  assert.deepEqual(result.events.map((e) => e.message_id), [posted.message.id]);
  assert.equal(result.cursor, posted.event.cursor);
});

test("wait_from_now_skips_history_but_a_bare_wait_replays_it", async () => {
  const alice = as("alice");
  const old = await alice.post("rt/hist", "old news");
  const fromNow = await alice.wait({ fromNow: true, channel: "rt/hist", timeoutMs: 1000 });
  assert.equal(fromNow.timedOut, true);
  assert.deepEqual(fromNow.events, []);
  assert.notEqual(fromNow.cursor, null);

  const bare = await alice.wait({ channel: "rt/hist", timeoutMs: 1000 });
  assert.deepEqual(bare.events.map((e) => e.message_id), [old.message.id]);

  // Resuming from the returned cursor does not replay.
  const resumed = await alice.wait({ after: bare.cursor ?? undefined, channel: "rt/hist", timeoutMs: 1000 });
  assert.equal(resumed.timedOut, true);
  assert.deepEqual(resumed.events, []);
});

test("wait_timeout_returns_timedOut_true", async () => {
  const started = Date.now();
  const result = await as("alice").wait({ fromNow: true, channel: "rt/never", timeoutMs: 1000 });
  assert.equal(result.timedOut, true);
  assert.deepEqual(result.events, []);
  assert.ok(Date.now() - started < 5000);
});

test("abort_signal_cancels_a_wait", async () => {
  const controller = new AbortController();
  const started = Date.now();
  const pending = as("alice").wait({ fromNow: true, channel: "rt/abort", timeoutMs: 120_000, signal: controller.signal });
  setTimeout(() => controller.abort(), 300);
  await assert.rejects(pending, (e: unknown) => e instanceof StigmerError && e.code === "aborted" && e.name === "AbortError");
  assert.ok(Date.now() - started < 5000);
});

test("server_errors_carry_codes_through_a_real_server", async () => {
  const alice = as("alice");
  await assert.rejects(alice.readThread(`msg_${"0".repeat(24)}`), (e: unknown) => {
    assert.ok(e instanceof StigmerError);
    assert.equal(e.status, 404);
    assert.equal(e.code, "not_found");
    return true;
  });
  await assert.rejects(alice.readThread("msg_doesnotexist"), (e: unknown) => e instanceof StigmerError && e.code === "invalid_input");
  await assert.rejects(alice.post("Bad Channel!", "x"), (e: unknown) => {
    assert.ok(e instanceof StigmerError);
    assert.equal(e.status, 400);
    assert.equal(e.code, "invalid_input");
    return true;
  });
  await assert.rejects(alice.events({ after: "garbage" }), (e: unknown) => e instanceof StigmerError && e.code === "invalid_cursor");
  const missingBoard = new Stigmer({ url: server.url, as: "alice", board: "nope" });
  await assert.rejects(missingBoard.readChannel("x"), (e: unknown) => e instanceof StigmerError && e.code === "not_found");
});

test("unreachable_server_is_a_network_error", async () => {
  const dead = new Stigmer({ url: "http://127.0.0.1:1", as: "alice" });
  await assert.rejects(dead.events(), (e: unknown) => e instanceof StigmerError && e.code === "network" && e.cause !== undefined);
});
