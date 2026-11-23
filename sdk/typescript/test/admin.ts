/*
 * Plain-fetch helpers for admin operations. The SDK has no admin wrappers in M1, so tests talk
 * to the HTTP API directly. Failures name the status and code only, never a credential.
 */

interface Called {
  status: number;
  body: any;
}

async function call(url: string, token: string | undefined, method: string, path: string, body?: unknown): Promise<Called> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (token) headers["Authorization"] = `Bearer ${token}`;
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const res = await fetch(`${url}${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await res.text();
  let parsed: any = null;
  try {
    parsed = JSON.parse(text);
  } catch {
    // leave null; the status is enough for the message
  }
  if (!res.ok) {
    throw new Error(`${method} ${path} failed: HTTP ${res.status} ${parsed?.error?.code ?? "no code"}`);
  }
  return { status: res.status, body: parsed };
}

export async function createBoard(url: string, adminToken: string, name: string): Promise<void> {
  await call(url, adminToken, "POST", "/v1/boards", { name });
}

export async function createInvite(
  url: string,
  adminToken: string,
  board: string,
  kind: "human" | "agent" | "bridge" = "agent",
  role: "admin" | "member" | "bridge" = "member",
): Promise<string> {
  const { body } = await call(url, adminToken, "POST", `/v1/boards/${encodeURIComponent(board)}/invites`, { kind, role });
  return body.invite as string;
}

/** Redeems an invite and returns the new token. */
export async function join(url: string, invite: string, name: string): Promise<string> {
  const { body } = await call(url, undefined, "POST", "/v1/join", { invite, name });
  return body.token as string;
}

/** Revokes the (single) token issued to `principal` on `board`. */
export async function revokeTokenOf(url: string, adminToken: string, board: string, principal: string): Promise<void> {
  const path = `/v1/boards/${encodeURIComponent(board)}/tokens`;
  const { body } = await call(url, adminToken, "GET", path);
  const ids = (body.tokens as { id: string; principal: string }[]).filter((t) => t.principal === principal).map((t) => t.id);
  if (ids.length !== 1) throw new Error(`expected one token for ${principal}, found ${ids.length}`);
  await call(url, adminToken, "DELETE", `${path}/${encodeURIComponent(ids[0]!)}`);
}
