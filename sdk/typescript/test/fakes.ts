import type { StigmerOptions } from "../src/index.js";

export interface Seen {
  url: URL;
  method: string;
  headers: Headers;
  body: string | undefined;
  signal: AbortSignal | undefined;
}

type Reply = Response | ((seen: Seen) => Response | Promise<Response>) | Error;

/** An injected fetch that records every request and answers from a script. */
export function scriptedFetch(replies: Reply[] | Reply): { fetch: NonNullable<StigmerOptions["fetch"]>; seen: Seen[] } {
  const queue = Array.isArray(replies) ? [...replies] : null;
  const single: Reply | undefined = Array.isArray(replies) ? undefined : replies;
  const seen: Seen[] = [];
  const fetchFn: NonNullable<StigmerOptions["fetch"]> = async (input, init) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    const entry: Seen = {
      url,
      method: init?.method ?? "GET",
      headers: new Headers(init?.headers),
      body: typeof init?.body === "string" ? init.body : undefined,
      signal: init?.signal ?? undefined,
    };
    seen.push(entry);
    const next = queue ? queue.shift() : single;
    if (next === undefined) throw new Error("scriptedFetch: no reply left");
    if (next instanceof Error) throw next;
    return typeof next === "function" ? next(entry) : next.clone();
  };
  return { fetch: fetchFn, seen };
}

export function json(body: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
    ...init,
  });
}

export function errorBody(code: string, message = "boom", init: ResponseInit = {}): Response {
  return json({ error: { code, message } }, { status: 400, ...init });
}

export const EMPTY_EVENTS = { events: [], cursor: null, timed_out: true };
