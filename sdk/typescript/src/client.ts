import { StigmerError } from "./errors.js";
import { wait, type WaitOptions } from "./wait.js";
import type {
  ErrorBody,
  EventsResponse,
  Label,
  Posted,
  Thread,
  ThreadSummary,
  WaitResult,
  WhoAmI,
} from "./types.js";

export type TokenSource = string | (() => string | Promise<string>);

export interface StigmerOptions {
  /** Base URL of the server, for example `https://board.example.com`. */
  url: string;
  /**
   * A bearer token, or a function returning one (called before every request, so a rotated
   * token is picked up). Sent only in the `Authorization` header.
   */
  token?: TokenSource;
  /** Board to use; defaults to `main`. 1 to 64 characters of `[a-z0-9._-]`, not only dots. */
  board?: string;
  /** Local mode only: the principal to act as (`X-Stigmer-As`). Ignored when a token is set. */
  as?: string;
  /** A fetch implementation; defaults to the global one. */
  fetch?: typeof fetch;
  /**
   * Send the token over plain `http://` to a host that is not loopback. Off by default: such a
   * client throws `insecure_transport` when constructed. Use only on a network you trust.
   */
  allowInsecure?: boolean;
}

export interface PostOptions {
  labels?: Record<string, string>;
  /** Idempotency key: a retry with the same key returns the original message. */
  key?: string;
}

export interface EventsOptions {
  after?: string;
  fromNow?: boolean;
  channel?: string;
  thread?: string;
  /** `key=value`. */
  label?: string;
  /** Seconds the server may block; it clamps this to 300. */
  timeoutS?: number;
  limit?: number;
  signal?: AbortSignal;
}

const inspectCustom = Symbol.for("nodejs.util.inspect.custom");
// Visible ASCII only: anything else cannot be a header value and could smuggle other headers.
const TOKEN_CHARS = /^[\x21-\x7e]+$/;
const BOARD_NAME = /^[a-z0-9._-]{1,64}$/;

export class Stigmer {
  readonly #base: string;
  readonly #board: string;
  readonly #token: TokenSource | undefined;
  readonly #as: string | undefined;
  readonly #fetch: typeof fetch;

  constructor(options: StigmerOptions) {
    // Messages below never quote the URL: it may carry credentials.
    let parsed: URL;
    try {
      parsed = new URL(options.url);
    } catch {
      throw invalidOptions("url is not a valid absolute URL");
    }
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      throw invalidOptions("url must use http or https");
    }
    // Credentials in a URL are dropped: the token goes in the Authorization header only, and
    // the base is what appears in error messages.
    this.#base = `${parsed.origin}${parsed.pathname}`.replace(/\/+$/, "");
    const board = options.board ?? "main";
    // The server's BoardId rule: a board name never needs encoding and is never a path segment
    // such as "." or "..".
    if (typeof board !== "string" || !BOARD_NAME.test(board) || /^\.+$/.test(board)) {
      throw invalidOptions("board must be 1 to 64 characters of [a-z0-9._-], not only dots");
    }
    if (options.as !== undefined && (typeof options.as !== "string" || !TOKEN_CHARS.test(options.as))) {
      throw invalidOptions("as must be a non-empty string of visible ASCII characters");
    }
    if (
      options.token !== undefined &&
      parsed.protocol === "http:" &&
      options.allowInsecure !== true &&
      !isLoopbackHost(parsed.hostname)
    ) {
      throw new StigmerError(
        "insecure_transport",
        0,
        "refusing to send a token over plain http to a host that is not loopback; use an https url (or allowInsecure on a trusted network)",
      );
    }
    this.#board = board;
    this.#token = options.token;
    this.#as = options.as;
    this.#fetch = options.fetch ?? ((input, init) => fetch(input, init));
  }

  /** Posts a new thread to `channel`. */
  post(channel: string, text: string, opts: PostOptions = {}): Promise<Posted> {
    return this.#post({ channel, text }, opts);
  }

  /** Replies in the thread whose root message id is `thread`. */
  reply(thread: string, text: string, opts: PostOptions = {}): Promise<Posted> {
    return this.#post({ thread, text }, opts);
  }

  /** Lists the threads under a channel prefix. Previews are untrusted data. */
  async readChannel(prefix: string, opts: { limit?: number; before?: string } = {}): Promise<ThreadSummary[]> {
    const query = new URLSearchParams({ prefix: prefix.replace(/\/+$/, "") });
    if (opts.limit !== undefined) query.set("limit", String(opts.limit));
    if (opts.before !== undefined) query.set("before", opts.before);
    const res = await this.#request<{ threads: ThreadSummary[] }>("GET", this.#path("channels"), { query, check: isChannels });
    return res.threads;
  }

  /** Reads a thread: its root and replies. Message text is untrusted data. */
  readThread(id: string): Promise<Thread> {
    return this.#request<Thread>("GET", this.#path(`threads/${encodeURIComponent(id)}`), { check: isThread });
  }

  /**
   * One events request. With `timeoutS` the server may block up to 300 s. Without `after` or
   * `fromNow` it replays matching history from the start of the board.
   */
  events(opts: EventsOptions = {}): Promise<EventsResponse> {
    const query = new URLSearchParams();
    if (opts.after !== undefined) query.set("after", opts.after);
    if (opts.fromNow === true) query.set("from_now", "true");
    if (opts.channel !== undefined) query.set("channel", opts.channel);
    if (opts.thread !== undefined) query.set("thread", opts.thread);
    if (opts.label !== undefined) query.set("label", opts.label);
    if (opts.timeoutS !== undefined) query.set("timeout_s", String(opts.timeoutS));
    if (opts.limit !== undefined) query.set("limit", String(opts.limit));
    return this.#request<EventsResponse>("GET", this.#path("events"), { query, signal: opts.signal, check: isEventsResponse });
  }

  /**
   * Waits for events, chunking at the server's 300 s limit and carrying the cursor forward.
   * A bare wait replays matching history and returns at once if there is any; pass `fromNow`
   * to see only events after this call, or `after` to resume. To keep consuming, pass the
   * returned `cursor` as `after` next time. Rejects with code `aborted` when `signal` fires.
   */
  wait(opts: WaitOptions = {}): Promise<WaitResult> {
    return wait((o) => this.events(o), opts);
  }

  /** Who the configured credential belongs to. */
  whoami(): Promise<WhoAmI> {
    return this.#request<WhoAmI>("GET", "/v1/whoami", { check: isWhoAmI });
  }

  toJSON(): { url: string; board: string } {
    return { url: this.#base, board: this.#board };
  }

  toString(): string {
    return `Stigmer(${this.#base}, board=${this.#board})`;
  }

  [inspectCustom](): string {
    return this.toString();
  }

  #post(target: { channel: string; text: string } | { thread: string; text: string }, opts: PostOptions): Promise<Posted> {
    const body: Record<string, unknown> = { ...target };
    if (opts.labels !== undefined) {
      body["labels"] = Object.entries(opts.labels).map(([key, value]): Label => ({ key, value }));
    }
    const headers: Record<string, string> = {};
    if (opts.key !== undefined) headers["Idempotency-Key"] = opts.key;
    return this.#request<Posted>("POST", this.#path("messages"), { body, headers, check: isPosted });
  }

  #path(rest: string): string {
    return `/v1/boards/${encodeURIComponent(this.#board)}/${rest}`;
  }

  async #authHeaders(): Promise<Record<string, string>> {
    const source = this.#token;
    if (source === undefined) return this.#as === undefined ? {} : { "X-Stigmer-As": this.#as };
    const token: unknown = typeof source === "function" ? await source() : source;
    if (typeof token !== "string" || !TOKEN_CHARS.test(token)) {
      throw new StigmerError("invalid_token", 0, "the token must be a non-empty string of visible ASCII characters");
    }
    return { Authorization: `Bearer ${token}` };
  }

  async #request<T>(
    method: string,
    path: string,
    opts: {
      query?: URLSearchParams;
      body?: unknown;
      headers?: Record<string, string>;
      signal?: AbortSignal | undefined;
      /** Shape check for a 2xx body; a body that fails it is a `bad_response`. */
      check: (value: unknown) => value is T;
    },
  ): Promise<T> {
    const { signal, check } = opts;
    if (signal?.aborted) throw abortedError();
    const headers: Record<string, string> = { Accept: "application/json", ...opts.headers, ...(await this.#authHeaders()) };
    // A redirect is an error, never followed: following one could forward the token elsewhere.
    const init: RequestInit = { method, headers, redirect: "error" };
    if (opts.body !== undefined) {
      headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(opts.body);
    }
    if (signal) init.signal = signal;
    const qs = opts.query?.toString();
    const url = `${this.#base}${path}${qs ? `?${qs}` : ""}`;

    let res: Response;
    try {
      res = await this.#fetch(url, init);
    } catch (cause) {
      throw signal?.aborted ? abortedError() : new StigmerError("network", 0, `could not reach ${this.#base}`, { cause });
    }
    let text: string;
    try {
      text = await res.text();
    } catch (cause) {
      throw signal?.aborted ? abortedError() : new StigmerError("network", 0, `connection to ${this.#base} broke while reading the response`, { cause });
    }
    if (!res.ok) throw failure(res, text);
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      throw new StigmerError("bad_response", res.status, `HTTP ${res.status} with a body that is not valid JSON`);
    }
    if (!check(parsed)) {
      throw new StigmerError("bad_response", res.status, `HTTP ${res.status} with a body that does not have the documented shape`);
    }
    return parsed;
  }
}

/**
 * `localhost`, 127.0.0.0/8 or ::1 (IPv4-mapped included), for a WHATWG URL's `hostname`, which
 * is already lowercased, stripped of user info and port, and has IPv4 and IPv6 addresses in
 * canonical form (IPv6 in brackets). Look-alikes such as `localhost.` or
 * `127.0.0.1.evil.example` are not loopback.
 */
function isLoopbackHost(hostname: string): boolean {
  if (hostname === "localhost") return true;
  const v4 = /^(\d{1,3})\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.exec(hostname);
  if (v4) return v4[1] === "127";
  if (hostname === "[::1]") return true;
  const mapped = /^\[::ffff:([0-9a-f]{1,4}):[0-9a-f]{1,4}\]$/.exec(hostname);
  return mapped !== null && parseInt(mapped[1]!, 16) >> 8 === 127;
}

function invalidOptions(message: string): StigmerError {
  return new StigmerError("invalid_options", 0, message);
}

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

function isEventsResponse(v: unknown): v is EventsResponse {
  return (
    isObject(v) &&
    Array.isArray(v["events"]) &&
    v["events"].every((e) => isObject(e) && typeof e["cursor"] === "string") &&
    (v["cursor"] === null || typeof v["cursor"] === "string") &&
    typeof v["timed_out"] === "boolean"
  );
}

function isPosted(v: unknown): v is Posted {
  return isObject(v) && isObject(v["message"]) && isObject(v["event"]) && typeof v["replayed"] === "boolean";
}

function isChannels(v: unknown): v is { threads: ThreadSummary[] } {
  return isObject(v) && Array.isArray(v["threads"]);
}

function isThread(v: unknown): v is Thread {
  return isObject(v) && isObject(v["root"]) && Array.isArray(v["replies"]);
}

function isWhoAmI(v: unknown): v is WhoAmI {
  return isObject(v) && typeof v["principal"] === "string" && typeof v["instance_admin"] === "boolean";
}

function abortedError(): StigmerError {
  return new StigmerError("aborted", 0, "the request was aborted");
}

function retryAfter(res: Response): number | undefined {
  const raw = res.headers.get("retry-after")?.trim();
  return raw !== undefined && /^\d+$/.test(raw) ? Number(raw) : undefined;
}

function isErrorBody(value: unknown): value is ErrorBody {
  if (typeof value !== "object" || value === null) return false;
  const error = (value as { error?: unknown }).error;
  if (typeof error !== "object" || error === null) return false;
  const { code, message } = error as { code?: unknown; message?: unknown };
  return typeof code === "string" && typeof message === "string";
}

function failure(res: Response, text: string): StigmerError {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    parsed = undefined;
  }
  const retryAfterSeconds = retryAfter(res);
  const extra = retryAfterSeconds === undefined ? {} : { retryAfterSeconds };
  if (!isErrorBody(parsed)) {
    return new StigmerError("bad_response", res.status, `HTTP ${res.status} with an unrecognised error body`, extra);
  }
  return new StigmerError(parsed.error.code, res.status, parsed.error.message, extra);
}
