/**
 * Parse the Retry-After header as per spec:
 * https://datatracker.ietf.org/doc/html/rfc9110#section-10.2.3
 */
export function parseRetryAfter(
  headers: Headers,
  now: Date = new Date(),
): Date | null {
  const retryAfter = headers.get("Retry-After");
  if (!retryAfter) return null;

  const value = retryAfter.trim();
  if (value.length === 0) return null;

  // delta-seconds (non-negative integer)
  if (/^\d+$/.test(value)) {
    const seconds = Number(value);
    return new Date(now.getTime() + seconds * 1000);
  }

  // HTTP-date: ensure it's actually a date-like string (contains letters)
  if (!/[a-zA-Z]/.test(value)) return null;
  const timestamp = Date.parse(value);
  if (Number.isNaN(timestamp)) return null;
  return new Date(timestamp);
}

/** Resolves after `ms`; rejects with the signal's reason once it aborts. */
export function delay(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(signal.reason);
      return;
    }
    const onAbort = () => {
      clearTimeout(timer);
      reject(signal!.reason);
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

/**
 * One fetch shared by concurrent calls and started by the first of them.
 * Every call gets the fetch's own outcome: its value or its error, such as
 * the `AbortError` of an aborted fetch. The fetch is aborted once every call
 * that joined it has aborted.
 */
export class SharedFetchRequest<T> {
  readonly #fetch: (signal: AbortSignal) => Promise<T>;
  readonly #controller = new AbortController();
  #promise: Promise<T> | null = null;
  /** Calls that joined and have not aborted. */
  #waiting = 0;

  constructor(fetch: (signal: AbortSignal) => Promise<T>) {
    this.#fetch = fetch;
  }

  /** Whether every call that joined has aborted, and so has the fetch. */
  get aborted(): boolean {
    return this.#controller.signal.aborted;
  }

  /** Resolves with the fetch's value; rejects with the fetch's error. */
  async get(signal?: AbortSignal): Promise<T> {
    // Without a signal, the call keeps the fetch going.
    this.#waiting++;
    const onAbort = () => {
      if (--this.#waiting === 0) this.#controller.abort();
    };
    if (signal?.aborted) onAbort();
    else signal?.addEventListener("abort", onAbort, { once: true });
    // Started after joining, so an aborted first call sends nothing.
    this.#promise ??= this.#fetch(this.#controller.signal);
    try {
      return await this.#promise;
    } finally {
      signal?.removeEventListener("abort", onAbort);
    }
  }
}
