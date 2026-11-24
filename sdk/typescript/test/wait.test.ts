import assert from "node:assert/strict";
import { test } from "node:test";

import { Stigmer, StigmerError } from "../src/index.js";
import { json, scriptedFetch } from "./fakes.js";

const event = (n: number) => ({
  seq: n,
  cursor: `ev_${n}`,
  kind: "thread.created",
  actor: "a",
  message_id: `msg_${n}`,
  thread_id: `msg_${n}`,
  channel: "eng",
  at_ms: 0,
  hash: "h",
});
const idle = (cursor: string | null) => json({ events: [], cursor, timed_out: true });

function client(fetchFn: ReturnType<typeof scriptedFetch>["fetch"]) {
  return new Stigmer({ url: "http://board.test", fetch: fetchFn, as: "alice" });
}

test("wait_chunk_loop_carries_cursor_and_never_resends_from_now", async () => {
  const { fetch, seen } = scriptedFetch([
    idle("ev_1"),
    idle("ev_2"),
    json({ events: [event(3)], cursor: "ev_3", timed_out: false }),
  ]);
  const result = await client(fetch).wait({ fromNow: true, timeoutMs: 700_000, channel: "eng", label: "k=v" });
  assert.equal(result.timedOut, false);
  assert.deepEqual(result.events.map((e) => e.seq), [3]);
  assert.equal(result.cursor, "ev_3");

  const q = seen.map((s) => s.url.searchParams);
  assert.equal(q[0]!.get("from_now"), "true");
  assert.equal(q[0]!.get("after"), null);
  assert.equal(q[0]!.get("timeout_s"), "300");
  assert.equal(q[1]!.get("from_now"), null);
  assert.equal(q[1]!.get("after"), "ev_1");
  assert.equal(q[1]!.get("timeout_s"), "300");
  assert.equal(q[2]!.get("from_now"), null);
  assert.equal(q[2]!.get("after"), "ev_2");
  assert.equal(q[2]!.get("timeout_s"), "300");
  for (const params of q) {
    assert.equal(params.get("channel"), "eng");
    assert.equal(params.get("label"), "k=v");
  }
});

test("wait_chunk_seconds_are_rounded_up_and_capped_at_300", async () => {
  const short = scriptedFetch(idle("ev_1"));
  // 500 ms (not 1 ms): the deadline starts before the request is built, so a slow runner can burn
  // a 1 ms deadline first and the SDK would then correctly send timeout_s=0.
  await client(short.fetch).wait({ after: "ev_1", timeoutMs: 500 });
  assert.equal(short.seen[0]!.url.searchParams.get("timeout_s"), "1");
  const long = scriptedFetch(json({ events: [event(2)], cursor: "ev_2", timed_out: false }));
  await client(long.fetch).wait({ timeoutMs: 90_500 });
  assert.equal(long.seen[0]!.url.searchParams.get("timeout_s"), "91");
});

test("wait_with_a_null_first_cursor_sends_neither_after_nor_from_now_later", async () => {
  const { fetch, seen } = scriptedFetch([idle(null), json({ events: [event(1)], cursor: "ev_1", timed_out: false })]);
  const result = await client(fetch).wait({ fromNow: true, timeoutMs: 400_000 });
  assert.equal(result.cursor, "ev_1");
  assert.equal(seen[0]!.url.searchParams.get("from_now"), "true");
  assert.equal(seen[1]!.url.searchParams.get("from_now"), null);
  assert.equal(seen[1]!.url.searchParams.get("after"), null);
});

test("wait_after_cursor_is_sent_on_the_first_chunk_and_wins_over_from_now", async () => {
  const { fetch, seen } = scriptedFetch(json({ events: [event(9)], cursor: "ev_9", timed_out: false }));
  await client(fetch).wait({ after: "ev_8", fromNow: true });
  assert.equal(seen[0]!.url.searchParams.get("after"), "ev_8");
  assert.equal(seen[0]!.url.searchParams.get("from_now"), null);
});

test("wait_returns_timedOut_with_the_cursor_once_the_deadline_passes", async () => {
  const { fetch, seen } = scriptedFetch(async () => {
    await new Promise((resolve) => setTimeout(resolve, 60));
    return idle("ev_5");
  });
  const result = await client(fetch).wait({ after: "ev_5", timeoutMs: 100 });
  assert.deepEqual(result, { events: [], cursor: "ev_5", timedOut: true });
  assert.ok(seen.length >= 1 && seen.length <= 3, `${seen.length} chunks`);
  assert.equal(seen[0]!.url.searchParams.get("timeout_s"), "1");
});

test("wait_errors_from_a_chunk_reject_with_the_server_code", async () => {
  const { fetch } = scriptedFetch(json({ error: { code: "invalid_cursor", message: "bad" } }, { status: 400 }));
  await assert.rejects(client(fetch).wait({ after: "nope" }), (e: unknown) => {
    assert.ok(e instanceof StigmerError);
    assert.equal(e.code, "invalid_cursor");
    return true;
  });
});

test("wait_abort_signal_aborts_the_in_flight_fetch", async () => {
  let inflight: AbortSignal | undefined;
  const { fetch } = scriptedFetch(
    (seen) =>
      new Promise<Response>((_, reject) => {
        inflight = seen.signal;
        seen.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")));
      }) as unknown as Response,
  );
  const controller = new AbortController();
  const pending = client(fetch).wait({ timeoutMs: 60_000, signal: controller.signal });
  setTimeout(() => controller.abort(), 20);
  await assert.rejects(pending, (e: unknown) => {
    assert.ok(e instanceof StigmerError);
    assert.equal(e.code, "aborted");
    assert.equal(e.name, "AbortError");
    return true;
  });
  assert.equal(inflight?.aborted, true);
});

test("wait_with_an_already_aborted_signal_never_sends_a_request", async () => {
  const { fetch, seen } = scriptedFetch(idle(null));
  await assert.rejects(client(fetch).wait({ signal: AbortSignal.abort() }), (e: unknown) => {
    assert.ok(e instanceof StigmerError);
    assert.equal(e.code, "aborted");
    return true;
  });
  assert.equal(seen.length, 0);
});
