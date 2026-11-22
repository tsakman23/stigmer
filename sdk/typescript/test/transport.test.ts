import assert from "node:assert/strict";
import { test } from "node:test";

import { Stigmer, StigmerError } from "../src/index.js";
import { EMPTY_EVENTS, errorBody, json, scriptedFetch } from "./fakes.js";

const SECRET = "stg1_0123456789abcdef_secretsecretsecretsecretsecretsecretsec";

// The same decision table as the CLI's check_credential_transport (crates/stigmer-cli/src/tls.rs).
const REFUSED = [
  "http://board.example.com",
  "http://10.0.0.1:7878",
  "http://[::2]:7878",
  "http://localhost.example.com",
  "http://128.0.0.1",
  "http://localhost@evil.example",
  "http://localhost:7878@evil.example:7878",
  "http://127.0.0.1.evil.example",
  "http://evil-localhost",
  "http://localhost.",
];

const ALLOWED = [
  "http://127.0.0.1:7878",
  "http://127.9.9.9",
  "http://localhost:7878/",
  "http://LOCALHOST",
  "http://[::1]:7878",
  "http://[::ffff:127.0.0.1]:7878",
  "https://board.example.com",
  "https://10.0.0.1:443",
];

test("token_over_plain_http_to_a_non_loopback_host_is_refused", async () => {
  for (const url of REFUSED) {
    const { fetch, seen } = scriptedFetch(json(EMPTY_EVENTS));
    for (const token of [SECRET, () => SECRET]) {
      assert.throws(
        () => new Stigmer({ url, token, fetch }),
        (err: unknown) => {
          assert.ok(err instanceof StigmerError, url);
          assert.equal(err.code, "insecure_transport", url);
          assert.equal(err.status, 0);
          assert.ok(!err.message.includes(SECRET), url);
          return true;
        },
        url,
      );
    }
    assert.equal(seen.length, 0, `${url}: nothing may be sent`);
  }
});

test("token_over_https_or_to_loopback_is_sent", async () => {
  for (const url of ALLOWED) {
    const { fetch, seen } = scriptedFetch(json(EMPTY_EVENTS));
    await new Stigmer({ url, token: SECRET, fetch }).events();
    assert.equal(seen[0]!.headers.get("authorization"), `Bearer ${SECRET}`, url);
  }
});

test("allow_insecure_sends_a_token_over_plain_http_to_a_remote_host", async () => {
  const { fetch, seen } = scriptedFetch(json(EMPTY_EVENTS));
  await new Stigmer({ url: "http://board.example.com:7878", token: SECRET, fetch, allowInsecure: true }).events();
  assert.equal(seen[0]!.headers.get("authorization"), `Bearer ${SECRET}`);
});

test("without_a_token_plain_http_to_a_remote_host_is_allowed", async () => {
  const { fetch, seen } = scriptedFetch(json(EMPTY_EVENTS));
  await new Stigmer({ url: "http://board.example.com:7878", as: "alice", fetch }).events();
  assert.equal(seen[0]!.headers.get("authorization"), null);
});

test("redirects_are_never_followed", async () => {
  const { fetch, seen } = scriptedFetch([json(EMPTY_EVENTS), json({ message: {}, event: {}, replayed: false }, { status: 201 })]);
  const c = new Stigmer({ url: "https://board.example.com", token: SECRET, fetch });
  await c.events();
  await c.post("eng", "hi");
  assert.deepEqual(
    seen.map((s) => s.redirect),
    ["error", "error"],
  );
});

test("a_redirect_answer_is_an_error_and_the_token_goes_nowhere_else", async () => {
  // Node's fetch with redirect: "error" rejects instead of following; a fake that follows only
  // when allowed shows the token never reaches the other host.
  const hosts: string[] = [];
  const fetchFn: typeof fetch = async (input, init) => {
    hosts.push(new URL(String(input)).host);
    if (init?.redirect !== "error") {
      hosts.push("evil.example");
    }
    throw new TypeError("fetch failed: unexpected redirect");
  };
  const c = new Stigmer({ url: "https://board.example.com", token: SECRET, fetch: fetchFn });
  await assert.rejects(c.events(), (err: unknown) => err instanceof StigmerError && err.code === "network");
  assert.deepEqual(hosts, ["board.example.com"]);
});

test("request_timeout_from_the_server_is_passed_through", async () => {
  const { fetch } = scriptedFetch(errorBody("request_timeout", "request body not received in time", { status: 408 }));
  await assert.rejects(
    new Stigmer({ url: "http://127.0.0.1:7878", as: "alice", fetch }).post("eng", "hi"),
    (err: unknown) => err instanceof StigmerError && err.code === "request_timeout" && err.status === 408,
  );
});
