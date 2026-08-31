/** Structured API failure so callers can branch on HTTP status instead of message text. */
export class ApiError extends Error {
	status: number;

	constructor(message: string, status: number) {
		super(message);
		this.name = 'ApiError';
		this.status = status;
	}
}

export function isApiError(err: unknown): err is ApiError {
	return err instanceof ApiError;
}

export function isForbidden(err: unknown): boolean {
	return isApiError(err) && (err.status === 403 || err.status === 401);
}
