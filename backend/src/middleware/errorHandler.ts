import type { NextFunction, Request, RequestHandler, Response } from 'express';

/** Wraps an async route handler so rejected promises reach the error middleware. */
export function asyncHandler(
  fn: (req: Request, res: Response, next: NextFunction) => Promise<void>,
): RequestHandler {
  return (req, res, next) => {
    fn(req, res, next).catch(next);
  };
}

export class HttpError extends Error {
  constructor(
    public readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

function isBodyParserSyntaxError(err: unknown): boolean {
  return (
    err instanceof SyntaxError &&
    'status' in err &&
    (err as { status?: unknown }).status === 400 &&
    'body' in err
  );
}

// eslint-disable-next-line @typescript-eslint/no-unused-vars
export function errorHandler(err: unknown, req: Request, res: Response, next: NextFunction): void {
  if (err instanceof HttpError) {
    res.status(err.status).json({ error: err.message });
    return;
  }

  // express.json() throws a SyntaxError for malformed request bodies —
  // that's a client mistake (400), not a server fault (500).
  if (isBodyParserSyntaxError(err)) {
    res.status(400).json({ error: 'invalid request' });
    return;
  }

  // Log only the message — never the full error object, which for DB
  // errors can include query text, and never req.body, which can contain
  // secret plaintext or JWTs. Stack traces and internal paths never reach
  // the client response below.
  console.error('[unhandled error]', err instanceof Error ? err.message : 'non-error thrown');
  if (res.headersSent) {
    next(err);
    return;
  }
  res.status(500).json({ error: 'internal error' });
}

export function notFoundHandler(_req: Request, res: Response): void {
  res.status(404).json({ error: 'not found' });
}
