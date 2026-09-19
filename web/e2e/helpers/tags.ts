/**
 * Playwright test tags — filter with `--grep @tag` or `--grep-invert @tag`.
 *
 * Layers: @focused (single-feature), @journey (multi-actor), @epic (long integration).
 * Domains: @auth, @registration, @request-update, @api-keys, @access-tokens, …
 */
export const TAG = {
	/** Long cross-feature integration (outcome assertions only). */
	epic: '@epic',
	/** Multi-actor domain journey. */
	journey: '@journey',
	/** Single-feature / page / actor spec. */
	focused: '@focused',
	/** Shared widget interaction locks (ui-contracts/). */
	uiContracts: '@ui-contracts',

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
	security: '@security',
	apiKeys: '@api-keys',
	accessTokens: '@access-tokens'
} as const;

export type Tag = (typeof TAG)[keyof typeof TAG];

/** Shorthand for `test.describe(..., { tag: [...] })`. */
export function describeTags(...tags: Tag[]) {
	return { tag: tags };
}
