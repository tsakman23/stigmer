import { StigmerError } from "./errors.js";
import type { Event, EventsResponse, WaitResult } from "./types.js";

/** The longest the server blocks one events request; it clamps larger `timeout_s` to this. */
export const MAX_CHUNK_SECONDS = 300;
const DEFAULT_TIMEOUT_MS = 300_000;

export interface WaitOptions {
  /** Resume after this cursor. Without it a wait replays matching history first. */
  after?: string;
  /** Skip history: start after the board's head as the server sees it. Only the first chunk sends it. */
  fromNow?: boolean;
  channel?: string;
  thread?: string;
  /** `key=value`. */
  label?: string;
  /** Overall limit in milliseconds across all chunks (default 300000). */
  timeoutMs?: number;
  signal?: AbortSignal;
}

export type EventsFn = (opts: {
  after?: string;
  fromNow?: boolean;
  channel?: string;
  thread?: string;
  label?: string;
  timeoutS: number;
  signal?: AbortSignal;
}) => Promise<EventsResponse>;

type Start = { kind: "beginning" } | { kind: "now" } | { kind: "after"; cursor: string };

/**
 * Long-polls the event feed, chunked at the server's 300 s clamp, until events arrive or
 * `timeoutMs` passes. Same rules as the CLI (docs/adr/0005): the first chunk alone may ask for
 * "from now"; every later chunk resumes from the cursor the previous one returned, so nothing
 * landing between chunks is skipped. A null cursor after a "from now" chunk means the board was
 * empty, so the next chunk starts at the beginning.
 */
export async function wait(events: EventsFn, opts: WaitOptions): Promise<WaitResult> {
  const { signal } = opts;
  if (signal?.aborted) throw new StigmerError("aborted", 0, "the wait was aborted");
  const deadline = Date.now() + (opts.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  let start: Start =
    opts.after !== undefined
      ? { kind: "after", cursor: opts.after }
      : opts.fromNow === true
        ? { kind: "now" }
        : { kind: "beginning" };
  let cursor: string | null = opts.after ?? null;

  for (;;) {
    const remainingMs = Math.max(0, deadline - Date.now());
    const timeoutS = Math.min(Math.ceil(remainingMs / 1000), MAX_CHUNK_SECONDS);
    const response: EventsResponse = await events({
      ...(start.kind === "after" ? { after: start.cursor } : {}),
      ...(start.kind === "now" ? { fromNow: true } : {}),
      ...(opts.channel !== undefined ? { channel: opts.channel } : {}),
      ...(opts.thread !== undefined ? { thread: opts.thread } : {}),
      ...(opts.label !== undefined ? { label: opts.label } : {}),
      timeoutS,
      ...(signal ? { signal } : {}),
    });
    cursor = response.cursor ?? cursor;
    if (response.events.length > 0) {
      return { events: response.events as Event[], cursor, timedOut: false };
    }
    if (Date.now() >= deadline) return { events: [], cursor, timedOut: true };
    if (response.cursor !== null) start = { kind: "after", cursor: response.cursor };
    else if (start.kind === "now") start = { kind: "beginning" };
  }
}
