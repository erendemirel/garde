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

/** True when the session cookie is no longer valid (not mere authorization denial). */
export function isSessionInvalidMessage(message: string): boolean {
	const msg = message.toLowerCase();
	return (
		msg.includes('session invalid') ||
		msg.includes('no active session') ||
		msg.includes('invalid session id')
	);
}

/** Authorization denied — distinct from an expired/invalid session. */
export function isForbidden(err: unknown): boolean {
	if (!isApiError(err)) return false;
	if (err.status === 403) return true;
	if (err.status === 401) {
		return !isSessionInvalidMessage(err.message);
	}
	return false;
}
