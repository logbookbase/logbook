export class LogbookError extends Error {
  override readonly name = 'LogbookError';
  constructor(
    public readonly statusCode: number | null,
    public readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

export type HttpClientOptions = {
  baseUrl: string;
  timeoutMs?: number;
  maxRetries?: number;
  fetch?: typeof fetch;
};

export class HttpClient {
  private readonly baseUrl: string;
  private readonly timeoutMs: number;
  private readonly maxRetries: number;
  private readonly fetcher: typeof fetch;

  constructor(opts: HttpClientOptions) {
    this.baseUrl = opts.baseUrl.replace(/\/+$/, '');
    this.timeoutMs = opts.timeoutMs ?? 10_000;
    this.maxRetries = opts.maxRetries ?? 2;
    this.fetcher = opts.fetch ?? globalThis.fetch;
    if (!this.fetcher) {
      throw new LogbookError(null, 'no_fetch', 'global fetch is not available; pass a fetch implementation');
    }
  }

  async get<T>(path: string): Promise<T> {
    return this.request<T>('GET', path);
  }

  async post<T>(path: string, body: unknown): Promise<T> {
    return this.request<T>('POST', path, body);
  }

  private async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    let attempt = 0;
    let lastErr: unknown = null;

    while (attempt <= this.maxRetries) {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), this.timeoutMs);

      try {
        const res = await this.fetcher(this.baseUrl + path, {
          method,
          headers: body !== undefined ? { 'content-type': 'application/json' } : undefined,
          body: body !== undefined ? JSON.stringify(body) : undefined,
          signal: controller.signal,
        });

        const text = await res.text();
        const json = text ? safeJsonParse(text) : null;

        if (!res.ok) {
          // retry on 5xx, fail fast on 4xx
          if (res.status >= 500 && attempt < this.maxRetries) {
            attempt++;
            lastErr = new LogbookError(res.status, 'server_error', text || res.statusText);
            await sleep(backoffMs(attempt));
            continue;
          }
          const errCode = (json as { error?: string } | null)?.error ?? 'http_error';
          const errMsg = (json as { message?: string } | null)?.message ?? (text || res.statusText);
          throw new LogbookError(res.status, errCode, errMsg);
        }

        return json as T;
      } catch (err) {
        if (err instanceof LogbookError) throw err;
        // network/abort errors — retry
        if (attempt < this.maxRetries) {
          attempt++;
          lastErr = err;
          await sleep(backoffMs(attempt));
          continue;
        }
        throw new LogbookError(null, 'network_error', (err as Error).message || 'request failed');
      } finally {
        clearTimeout(timeout);
      }
    }

    throw lastErr instanceof Error
      ? lastErr
      : new LogbookError(null, 'unknown_error', 'request failed');
  }
}

function safeJsonParse(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function backoffMs(attempt: number): number {
  return Math.min(1000 * 2 ** (attempt - 1), 4000);
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}
