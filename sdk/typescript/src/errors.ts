/**
 * An error from a Stigmer call.
 *
 * - `code` is the server's error code string (for example `not_found`, `unauthorized`,
 *   `rate_limited`). A code this SDK does not know is kept verbatim.
 * - The SDK adds three codes of its own: `network` (no HTTP response; `cause` holds the
 *   underlying error), `bad_response` (the body was not the JSON the API documents) and
 *   `aborted` (the caller's AbortSignal fired), plus `invalid_token` (the configured token
 *   cannot be sent as a header value).
 * - `status` is the HTTP status, or 0 when there was no response.
 *
 * Messages never contain credentials.
 */
export class StigmerError extends Error {
  readonly code: string;
  readonly status: number;
  /** From the `Retry-After` header, when the server sent whole seconds (a 429 does). */
  readonly retryAfterSeconds?: number;

  constructor(
    code: string,
    status: number,
    message: string,
    options: { retryAfterSeconds?: number; cause?: unknown } = {},
  ) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = code === "aborted" ? "AbortError" : "StigmerError";
    this.code = code;
    this.status = status;
    if (options.retryAfterSeconds !== undefined) this.retryAfterSeconds = options.retryAfterSeconds;
  }
}
