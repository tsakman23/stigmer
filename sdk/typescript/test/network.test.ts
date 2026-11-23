import assert from "node:assert/strict";
import { after, before, test } from "node:test";

import { Stigmer, StigmerError } from "../src/index.js";
import { createBoard, createInvite, join, revokeTokenOf } from "./admin.js";
import { cleanup, enableAuth, makeDataDir, startServer, waitFromHead, type Secrets, type TestServer } from "./harness.js";

let server: TestServer;
let secrets: Secrets;
before(async () => {
  const dir = await makeDataDir();
  secrets = await enableAuth(dir);
  server = await startServer(dir);
});
after(async () => {
  await server?.stop();
  await cleanup();
});

async function agent(board: string, name: string): Promise<{ client: Stigmer; token: string }> {
  const invite = await createInvite(server.url, secrets.instanceToken, board, "agent", "member");
  const token = await join(server.url, invite, name);
  return { client: new Stigmer({ url: server.url, board, token }), token };
}

test("network_mode_join_and_two_agents_exchange", async () => {
  await createBoard(server.url, secrets.instanceToken, "lab");
  const a = await agent("lab", "agent-a");
  const c = await agent("lab", "agent-c");

  const who = await a.client.whoami();
  assert.equal(who.principal, "agent-a");
  assert.equal(who.kind, "agent");
  assert.equal(who.board, "lab");
  assert.equal(who.role, "member");
  assert.equal(who.instance_admin, false);

  // C takes the head and starts waiting before A posts.
  const { done: waiting } = await waitFromHead(c.client, { channel: "research", timeoutMs: 20_000 });
  const posted = await a.client.post("research/tls", "Is TLS 1.3 enough?");
  const got = await waiting;
  assert.equal(got.timedOut, false);
  assert.equal(got.events[0]?.message_id, posted.message.id);
  assert.equal(got.events[0]?.actor, "agent-a");

  const reply = await c.client.reply(posted.message.id, "Yes, if 1.2 is disabled.");
  assert.equal(reply.message.author, "agent-c");
  const thread = await a.client.readThread(posted.message.id);
  assert.deepEqual(
    [thread.root, ...thread.replies].map((m) => [m.author, m.text]),
    [
      ["agent-a", "Is TLS 1.3 enough?"],
      ["agent-c", "Yes, if 1.2 is disabled."],
    ],
  );
});

test("main_admin_invite_makes_an_admin_on_main", async () => {
  const token = await join(server.url, secrets.mainAdminInvite, "root");
  const root = new Stigmer({ url: server.url, token });
  const who = await root.whoami();
  assert.equal(who.role, "admin");
  assert.equal(who.board, "main");
  const posted = await root.post("ops", "admin here");
  assert.equal(posted.message.author, "root");
});

test("a_board_token_cannot_see_another_board", async () => {
  const a = await agent("lab", "agent-x");
  const other = new Stigmer({ url: server.url, board: "main", token: a.token });
  await assert.rejects(other.readChannel("ops"), (e: unknown) => e instanceof StigmerError && e.code === "not_found" && e.status === 404);
});

test("revoked_token_yields_unauthorized", async () => {
  const doomed = await agent("lab", "agent-doomed");
  await doomed.client.post("scratch", "still works");
  await revokeTokenOf(server.url, secrets.instanceToken, "lab", "agent-doomed");
  await assert.rejects(doomed.client.post("scratch", "after revoke"), (e: unknown) => {
    assert.ok(e instanceof StigmerError);
    assert.equal(e.code, "unauthorized");
    assert.equal(e.status, 401);
    assert.ok(!e.message.includes(doomed.token));
    return true;
  });
});

test("a_wrong_token_yields_unauthorized", async () => {
  const bogus = new Stigmer({ url: server.url, board: "lab", token: "stg_not-a-real-token" });
  await assert.rejects(bogus.whoami(), (e: unknown) => e instanceof StigmerError && e.code === "unauthorized" && e.status === 401);
});
