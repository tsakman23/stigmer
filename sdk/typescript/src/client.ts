import { StigmerError } from "./errors.js";
import type {
  ErrorBody,
  EventsResponse,
  Label,
  Posted,
  Thread,
  ThreadSummary,
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
  /** Board to use; defaults to `main`. */
  board?: string;
  /** Local mode only: the principal to act as (`X-Stigmer-As`). Ignored when a token is set. */
  as?: string;
  /** A fetch implementation; defaults to the global one. */
  fetch?: typeof fetch;
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

export class Stigmer {
  readonly #base: string;
  readonly #board: string;
  readonly #token: TokenSource | undefined;
  readonly #as: string | undefined;
  readonly #fetch: typeof fetch;

  constructor(options: StigmerOptions) {
    // Throws a TypeError for a malformed URL; the message holds only the URL.
    new URL(options.url);
    this.#base = options.url.replace(/\/+$/, "");
    this.#board = options.board ?? "main";
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
    const res = await this.#request<{ threads: ThreadSummary[] }>("GET", this.#path("channels"), { query });
    return res.threads;
  }

  /** Reads a thread: its root and replies. Message text is untrusted data. */
  readThread(id: string): Promise<Thread> {
    return this.#request<Thread>("GET", this.#path(`threads/${encodeURIComponent(id)}`));
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
    return this.#request<EventsResponse>("GET", this.#path("events"), { query, signal: opts.signal });
  }

  /** Who the configured credential belongs to. */
  whoami(): Promise<WhoAmI> {
    return this.#request<WhoAmI>("GET", "/v1/whoami");
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
    return this.#request<Posted>("POST", this.#path("messages"), { body, headers });
  }

  #path(rest: string): string {
    return `/v1/boards/${encodeURIComponent(this.#board)}/${rest}`;
  }

  async #authHeaders(): Promise<Record<string, string>> {
    const source = this.#token;
    const token = typeof source === "function" ? await source() : source;
    if (token !== undefined && token !== "") {
      if (!TOKEN_CHARS.test(token)) {
        throw new StigmerError("invalid_token", 0, "the token contains characters that cannot be sent in a header");
      }
      return { Authorization: `Bearer ${token}` };
    }
    return this.#as === undefined ? {} : { "X-Stigmer-As": this.#as };
  }

  async #request<T>(
    method: string,
    path: string,
    opts: { query?: URLSearchParams; body?: unknown; headers?: Record<string, string>; signal?: AbortSignal | undefined } = {},
  ): Promise<T> {
    const { signal } = opts;
    if (signal?.aborted) throw abortedError();
    const headers: Record<string, string> = { Accept: "application/json", ...opts.headers, ...(await this.#authHeaders()) };
    const init: RequestInit = { method, headers };
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
    try {
      return JSON.parse(text) as T;
    } catch {
      throw new StigmerError("bad_response", res.status, `HTTP ${res.status} with a body that is not valid JSON`);
    }
  }
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
