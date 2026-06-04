export class HttpError extends Error {
  override readonly name = 'HttpError';
  constructor(
    public readonly statusCode: number,
    public readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

export const badRequest = (code: string, msg: string): HttpError =>
  new HttpError(400, code, msg);

export const notFound = (code: string, msg: string): HttpError =>
  new HttpError(404, code, msg);

export const conflict = (code: string, msg: string): HttpError =>
  new HttpError(409, code, msg);

export const unauthorized = (code: string, msg: string): HttpError =>
  new HttpError(401, code, msg);
