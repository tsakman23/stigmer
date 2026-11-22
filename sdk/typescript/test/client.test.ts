import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { inspect } from "node:util";
import { test } from "node:test";

import { Stigmer, StigmerError } from "../src/index.js";
import { EMPTY_EVENTS, errorBody, json, scriptedFetch } from "./fakes.js";

const SECRET = "stg_secretvalue1234567890";

function client(fetchFn: ReturnType<typeof scriptedFetch>["fetch"], extra: Record<string, unknown> = {}) {
  return new Stigmer({ url: "http://board.test:7878", fetch: fetchFn, ...extra });
}

test("bearer_token_sent_in_header_never_in_url", async () => {
  const { fetch, seen } = scriptedFetch(json(EMPTY_EVENTS));
  await client(fetch, { token: SECRET }).events({ channel: "a", label: "k=v" });
  const req = seen[0]!;
  assert.equal(req.headers.get("authorization"), `Bearer ${SECRET}`);
  assert.equal(req.headers.get("x-stigmer-as"), null);
  assert.ok(!req.url.href.includes(SECRET));
  assert.ok(!(req.body ?? "").includes(SECRET));
});

test("token_provider_function_is_called_per_request", async () => {
  const { fetch, seen } = scriptedFetch(json(EMPTY_EVENTS));
  let calls = 0;
  const c = client(fetch, { token: async () => `tok${++calls}` });
  await c.events();
  await c.events();
  assert.equal(calls, 2);
  assert.deepEqual(
    seen.map((s) => s.headers.get("authorization")),
    ["Bearer tok1", "Bearer tok2"],
  );
});

test("as_header_is_sent_only_without_a_token", async () => {
  const local = scriptedFetch(json(EMPTY_EVENTS));
  await client(local.fetch, { as: "alice" }).events();
  assert.equal(local.seen[0]!.headers.get("x-stigmer-as"), "alice");
  assert.equal(local.seen[0]!.headers.get("authorization"), null);

  const net = scriptedFetch(json(EMPTY_EVENTS));
  await client(net.fetch, { as: "alice", token: SECRET }).events();
  assert.equal(net.seen[0]!.headers.get("x-stigmer-as"), null);
});

test("post_sends_labels_as_key_value_pairs_and_key_as_idempotency_header", async () => {
  const posted = { message: {}, event: {}, replayed: false };
  const { fetch, seen } = scriptedFetch([json(posted, { status: 201 }), json(posted, { status: 201 })]);
  const c = client(fetch, { as: "alice" });
  await c.post("research/tls", "hello", { labels: { kind: "finding", n: "1" }, key: "k-1" });
  await c.reply("msg_abc", "re");
  const [first, second] = seen;
  assert.equal(first!.method, "POST");
  assert.equal(first!.url.pathname, "/v1/boards/main/messages");
  assert.equal(first!.headers.get("idempotency-key"), "k-1");
  assert.deepEqual(JSON.parse(first!.body!), {
    channel: "research/tls",
    text: "hello",
    labels: [
      { key: "kind", value: "finding" },
      { key: "n", value: "1" },
    ],
  });
  assert.deepEqual(JSON.parse(second!.body!), { thread: "msg_abc", text: "re" });
  assert.equal(second!.headers.get("idempotency-key"), null);
});

test("channel_prefix_trailing_slash_is_stripped", async () => {
  const { fetch, seen } = scriptedFetch(json({ threads: [] }));
  await client(fetch).readChannel("research/tls//", { limit: 5, before: "msg_x" });
  const url = seen[0]!.url;
  assert.equal(url.pathname, "/v1/boards/main/channels");
  assert.equal(url.searchParams.get("prefix"), "research/tls");
  assert.equal(url.searchParams.get("limit"), "5");
  assert.equal(url.searchParams.get("before"), "msg_x");
});

test("board_is_url_encoded", async () => {
  const { fetch, seen } = scriptedFetch([json({ threads: [] }), errorBody("not_found", "no", { status: 404 })]);
  const c = client(fetch, { board: "a/b c?x=1" });
  await c.readChannel("eng");
  await assert.rejects(c.readThread("msg_1/../x"));
  assert.equal(seen[0]!.url.pathname, "/v1/boards/a%2Fb%20c%3Fx%3D1/channels");
  assert.equal(seen[1]!.url.pathname, "/v1/boards/a%2Fb%20c%3Fx%3D1/threads/msg_1%2F..%2Fx");
});

test("events_sends_only_known_query_names_and_encodes_values", async () => {
  const { fetch, seen } = scriptedFetch(json(EMPTY_EVENTS));
  await client(fetch).events({
    after: "ev_a&b=c",
    channel: "research/tls",
    thread: "msg_1",
    label: "k=v w",
    timeoutS: 7,
    limit: 3,
  });
  await client(fetch).events({ fromNow: true });
  const known = new Set(["after", "from_now", "channel", "thread", "label", "timeout_s", "limit"]);
  for (const s of seen) for (const name of s.url.searchParams.keys()) assert.ok(known.has(name), name);
  const first = seen[0]!.url.searchParams;
  assert.equal(first.get("after"), "ev_a&b=c");
  assert.equal(first.get("label"), "k=v w");
  assert.equal(first.get("timeout_s"), "7");
  assert.equal(first.get("from_now"), null);
  assert.equal(seen[1]!.url.searchParams.get("from_now"), "true");
  assert.equal([...seen[1]!.url.searchParams.keys()].length, 1);
});

test("errors_carry_server_codes_and_unknown_codes_are_preserved", async () => {
  const { fetch } = scriptedFetch([
    errorBody("not_found", "no such thread", { status: 404 }),
    errorBody("quota_exceeded_v9", "future code", { status: 402 }),
  ]);
  const c = client(fetch);
  await assert.rejects(c.readThread("msg_1"), (e: unknown) => {
    assert.ok(e instanceof StigmerError);
    assert.equal(e.code, "not_found");
    assert.equal(e.status, 404);
    assert.equal(e.message, "no such thread");
    return true;
  });
  await assert.rejects(c.readThread("msg_1"), (e: unknown) => {
    assert.ok(e instanceof StigmerError);
    assert.equal(e.code, "quota_exceeded_v9");
    assert.equal(e.status, 402);
    return true;
  });
});

test("retry_after_is_exposed_on_429", async () => {
  const { fetch } = scriptedFetch(errorBody("rate_limited", "slow down", { status: 429, headers: { "retry-after": "7" } }));
  await assert.rejects(client(fetch).events(), (e: unknown) => {
    assert.ok(e instanceof StigmerError);
    assert.equal(e.code, "rate_limited");
    assert.equal(e.status, 429);
    assert.equal(e.retryAfterSeconds, 7);
    return true;
  });
});

test("non_json_error_body_becomes_bad_response", async () => {
  const { fetch } = scriptedFetch([
    new Response("<html>502 Bad Gateway</html>", { status: 502 }),
    json({ unexpected: true }, { status: 500 }),
    new Response('{"events": [', { status: 200 }),
    new Response("not json", { status: 200 }),
  ]);
  const c = client(fetch);
  for (const status of [502, 500, 200, 200]) {
    await assert.rejects(c.events(), (e: unknown) => {
      assert.ok(e instanceof StigmerError, String(e));
      assert.equal(e.code, "bad_response");
      assert.equal(e.status, status);
      return true;
    });
  }
});

test("network_failure_is_code_network", async () => {
  const cause = new TypeError("fetch failed");
  const { fetch } = scriptedFetch(cause);
  await assert.rejects(client(fetch, { token: SECRET }).events(), (e: unknown) => {
    assert.ok(e instanceof StigmerError);
    assert.equal(e.code, "network");
    assert.equal(e.status, 0);
    assert.equal(e.cause, cause);
    return true;
  });
});

test("client_never_leaks_the_token_in_errors_or_inspection", async () => {
  const c = client(
    scriptedFetch([
      errorBody("unauthorized", "invalid or expired credentials", { status: 401 }),
      new TypeError("fetch failed"),
    ]).fetch,
    { token: SECRET, as: "alice" },
  );
  const views = [JSON.stringify(c), String(c), inspect(c, { depth: 10, showHidden: true }), `${c}`];
  for (const call of [() => c.whoami(), () => c.whoami()]) {
    try {
      await call();
      assert.fail("expected a rejection");
    } catch (e) {
      views.push(String((e as Error).message), inspect(e, { depth: 10, showHidden: true }), JSON.stringify(e));
    }
  }
  for (const v of views) assert.ok(!v.includes(SECRET), "token leaked");
});

test("token_with_control_characters_is_refused_without_echoing_it", async () => {
  const bad = "tok\nX-Evil: 1";
  const { fetch, seen } = scriptedFetch(json(EMPTY_EVENTS));
  await assert.rejects(client(fetch, { token: bad }).events(), (e: unknown) => {
    assert.ok(e instanceof StigmerError);
    assert.equal(e.code, "invalid_token");
    assert.ok(!e.message.includes("X-Evil"));
    return true;
  });
  assert.equal(seen.length, 0);
});

test("events_2xx_with_wrong_shape_is_bad_response", async () => {
  const bodies = [
    { events: "nope", cursor: null, timed_out: true },
    { events: [], cursor: 5, timed_out: true },
    { events: [], cursor: null },
    { events: [null], cursor: null, timed_out: false },
    [],
    null,
  ];
  const { fetch } = scriptedFetch(bodies.map((b) => json(b)));
  const c = client(fetch);
  for (let i = 0; i < bodies.length; i++) {
    await assert.rejects(c.events(), (e: unknown) => {
      assert.ok(e instanceof StigmerError, String(e));
      assert.equal(e.code, "bad_response");
      assert.equal(e.status, 200);
      return true;
    });
  }
});

test("post_2xx_with_wrong_shape_is_bad_response", async () => {
  const { fetch } = scriptedFetch([
    json({ message: null, event: {}, replayed: false }, { status: 201 }),
    json({ message: {} }, { status: 201 }),
    json({ threads: {} }),
    json({ root: {}, replies: null }),
    json({ principal: 3 }),
  ]);
  const c = client(fetch, { as: "alice" });
  const calls = [() => c.post("eng", "x"), () => c.reply("msg_1", "x"), () => c.readChannel("eng"), () => c.readThread("msg_1"), () => c.whoami()];
  for (const call of calls) {
    await assert.rejects(call(), (e: unknown) => e instanceof StigmerError && e.code === "bad_response");
  }
});

test("token_provider_returning_empty_or_non_string_is_invalid_token_before_any_request", async () => {
  for (const bad of ["", 42, undefined, null]) {
    const { fetch, seen } = scriptedFetch(json(EMPTY_EVENTS));
    const c = client(fetch, { token: () => bad });
    await assert.rejects(c.events(), (e: unknown) => {
      assert.ok(e instanceof StigmerError);
      assert.equal(e.code, "invalid_token");
      assert.equal(e.status, 0);
      return true;
    });
    assert.equal(seen.length, 0);
  }
  const empty = scriptedFetch(json(EMPTY_EVENTS));
  await assert.rejects(client(empty.fetch, { token: "" }).events(), (e: unknown) => e instanceof StigmerError && e.code === "invalid_token");
  assert.equal(empty.seen.length, 0);
});

test("constructor_validation_errors_are_invalid_options_and_never_echo_the_url", () => {
  const cases: [Record<string, unknown>, string][] = [
    [{ url: "not a url with u:p@secret" }, "bad url"],
    [{ url: "ftp://host" }, "bad scheme"],
    [{ url: "http://host", board: "" }, "bad board"],
    [{ url: "http://host", as: "bad\nname" }, "bad as"],
  ];
  for (const [options, why] of cases) {
    assert.throws(
      () => new Stigmer(options as unknown as ConstructorParameters<typeof Stigmer>[0]),
      (e: unknown) => {
        assert.ok(e instanceof StigmerError, why);
        assert.equal(e.code, "invalid_options");
        assert.equal(e.status, 0);
        assert.ok(!e.message.includes("secret"));
        return true;
      },
      why,
    );
  }
});

test("url_credentials_are_never_echoed_or_sent", async () => {
  const seenUrls: string[] = [];
  const failing = async (input: string | URL | Request): Promise<Response> => {
    seenUrls.push(String(input));
    throw new TypeError(`fetch failed for ${String(input)}`);
  };
  const c = new Stigmer({ url: "https://bob:hunter2@board.test:8443/base/", fetch: failing, token: SECRET });
  const views = [JSON.stringify(c), String(c), inspect(c, { depth: 5 })];
  try {
    await c.events();
    assert.fail("expected rejection");
  } catch (e) {
    views.push(String((e as Error).message), inspect(e, { depth: 10, showHidden: true }));
    assert.ok(e instanceof StigmerError);
    assert.equal(e.code, "network");
  }
  for (const v of views) {
    assert.ok(!v.includes("hunter2") && !v.includes("bob:"), "url credentials leaked");
  }
  assert.ok(seenUrls[0]!.startsWith("https://board.test:8443/base/v1/boards/main/events"));
});

test("no_runtime_dependencies", async () => {
  const pkg = JSON.parse(await readFile(new URL("../../package.json", import.meta.url), "utf8"));
  assert.equal(pkg.dependencies, undefined);
  assert.equal(pkg.peerDependencies, undefined);
  assert.equal(pkg.optionalDependencies, undefined);
  assert.deepEqual(Object.keys(pkg.devDependencies).sort(), ["@types/node", "typescript"]);
});
