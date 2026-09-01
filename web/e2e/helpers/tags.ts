/**
 * Playwright test tags — filter with `--grep @tag` or `--grep-invert @tag`.
 *
 * Layers: @focused (default short specs), @journey (multi-actor), @epic (long integration).
 * Domains: @auth, @registration, @request-update, @active-session, @dashboard, @admin, …
 */
export const TAG = {
	/** Long cross-feature integration (outcome assertions only). */
	epic: '@epic',
	/** Multi-actor domain journey (focused cases). */
	journey: '@journey',
	/** Single-feature or role spec (default CI signal). */
	focused: '@focused',

	auth: '@auth',
	registration: '@registration',
	requestUpdate: '@request-update',
	activeSession: '@active-session',
	dashboard: '@dashboard',
	selfService: '@self-service',
	admin: '@admin',
	superuser: '@superuser',
	userDetail: '@user-detail',
	regular: '@regular',
	nav: '@nav',
	catalog: '@catalog',
	security: '@security'
} as const;

export type Tag = (typeof TAG)[keyof typeof TAG];

/** Shorthand for `test.describe(..., { tag: [...] })`. */
export function describeTags(...tags: Tag[]) {
	return { tag: tags };
}
