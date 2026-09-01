import { expect, type Page, type Response } from '@playwright/test';

/** Session boot and API-backed panel waits (override via PLAYWRIGHT_LOAD_TIMEOUT if needed). */
export const LOAD_TIMEOUT = Number(process.env.PLAYWRIGHT_LOAD_TIMEOUT || 30_000);

/** Redirects, login page, and other public-route navigation. */
export const REDIRECT_TIMEOUT = 15_000;

/** Toast auto-hides after 5s — deadline timer in app resists background-tab throttling. */
export const TOAST_DISMISS_TIMEOUT = Number(process.env.PLAYWRIGHT_TOAST_TIMEOUT || 8_000);

export async function waitForToastGone(page: Page, timeout = TOAST_DISMISS_TIMEOUT) {
	await expect(page.getByTestId('toast')).toBeHidden({ timeout });
}

type UsersListRequestParams = {
	page?: number;
	limit?: number;
	q?: string;
	sort?: string;
	order?: string;
};

/** Match GET /api/users with exact query params (avoids `page=2` matching `page=20`). */
export function matchUsersListRequest(res: Response, params: UsersListRequestParams = {}) {
	if (res.request().method() !== 'GET') return false;
	try {
		const url = new URL(res.url());
		if (!url.pathname.endsWith('/api/users')) return false;
		for (const [key, value] of Object.entries(params)) {
			if (value === undefined) continue;
			if (url.searchParams.get(key) !== String(value)) return false;
		}
		return true;
	} catch {
		return false;
	}
}

/** POST /api/sessions/revoke */
export function matchRevokeSessions(res: Response) {
	return res.request().method() === 'POST' && res.url().includes('/api/sessions/revoke');
}

/** PUT /api/users/:id (approve/reject/lock/etc.). */
export function matchUserUpdate(res: Response) {
	if (res.request().method() !== 'PUT') return false;
	try {
		return /\/api\/users\/[^/]+$/.test(new URL(res.url()).pathname);
	} catch {
		return false;
	}
}

/** GET /api/users/me — protected layout boot. */
export function matchMeGet(res: Response) {
	if (res.request().method() !== 'GET') return false;
	try {
		return new URL(res.url()).pathname.endsWith('/api/users/me');
	} catch {
		return false;
	}
}

/** Match GET /api/users/:id */
export function matchUserGet(res: Response, userId?: string) {
	if (res.request().method() !== 'GET') return false;
	try {
		const path = new URL(res.url()).pathname;
		if (!/\/api\/users\/[^/]+$/.test(path)) return false;
		if (userId && !path.endsWith(`/api/users/${userId}`)) return false;
		return true;
	} catch {
		return false;
	}
}

/**
 * Admin opened a user outside their scope.
 * Backend: GET /users/:id returns 401 + "unauthorized" (authorization failure, not session expiry).
 * UI: user-detail shows access denied; the admin session stays signed in.
 */
export async function waitForOutOfScopeDenied(
	page: Page,
	userId: string,
	path = `/admin/users/${userId}`,
	timeout = LOAD_TIMEOUT
) {
	const userResponse = page.waitForResponse(
		(res) => matchUserGet(res, userId),
		{ timeout }
	);
	await page.goto(path);
	const res = await userResponse;
	expect(res.status()).toBe(401);
	const body = await res.json().catch(() => ({}));
	const message = String(body?.error?.message ?? '').toLowerCase();
	expect(message).toContain('unauthorized');
	expect(message).not.toContain('session invalid');

	await waitForSessionReady(page, timeout);
	await expect(page.getByTestId('app-nav')).toBeVisible({ timeout });
	await expect(page.getByTestId('login-page')).toHaveCount(0);
	await expect(page.getByTestId('user-detail-access-denied')).toBeVisible({ timeout });
}

/** POST /api/users/password/change */
export function matchPasswordChange(res: Response) {
	if (res.request().method() !== 'POST') return false;
	try {
		return new URL(res.url()).pathname.endsWith('/api/users/password/change');
	} catch {
		return false;
	}
}

/** Panels that swap a loading testid for a ready marker after fetch. */
async function waitOutOfLoading(
	page: Page,
	loadingTestId: string,
	ready: ReturnType<Page['getByTestId']>,
	timeout = LOAD_TIMEOUT
) {
	const loading = page.getByTestId(loadingTestId);
	await expect(ready.or(loading)).toBeVisible({ timeout });
	await expect(loading).toHaveCount(0, { timeout });
	await expect(ready).toBeVisible({ timeout });
}

/**
 * Protected layout boots via /api/users/me before any page shell mounts.
 * Dashboard also refetches on mount after mutations that affect the signed-in user.
 */
export async function waitForSessionReady(page: Page, timeout = LOAD_TIMEOUT) {
	const nav = page.getByTestId('app-nav');
	const loading = page.getByTestId('session-loading');
	await expect(nav.or(loading)).toBeVisible({ timeout });
	await expect(loading).toHaveCount(0, { timeout });
	await expect(nav).toBeVisible({ timeout });
}

/** After goto/nav into a protected route — session + page shell. */
export async function waitForPageShell(page: Page, testId: string, timeout = LOAD_TIMEOUT) {
	await waitForSessionReady(page, timeout);
	await expect(page.getByTestId(testId)).toBeVisible({ timeout });
}

/** Request-update catalog fetch — form exposes data-ready once options are loaded. */
export async function waitForRequestUpdateCatalog(page: Page, timeout = LOAD_TIMEOUT) {
	await expect(page.getByTestId('request-update-form')).toBeVisible({ timeout });
	await expect(page.getByTestId('request-update-form')).toHaveAttribute('data-ready', 'true', {
		timeout
	});
	await expect(page.getByTestId('request-update-catalog-loading')).toHaveCount(0, { timeout });
}

/** Groups multiselect mounted and populated (ephemeral users with group_a should always have addable groups). */
export async function waitForRequestUpdateGroups(page: Page, timeout = LOAD_TIMEOUT) {
	await waitForRequestUpdateCatalog(page, timeout);
	await expect(page.getByTestId('request-update-groups')).toBeVisible({ timeout });
}

/** UsersListPanel — `users-list` mounts only after the first fetch. */
export async function waitForUsersList(page: Page, timeout = LOAD_TIMEOUT) {
	await waitForSessionReady(page, timeout);
	await waitOutOfLoading(
		page,
		'users-list-loading',
		page.getByTestId('users-list'),
		timeout
	);
}

/** Admin permissions/groups catalog table. */
export async function waitForAdminCatalog(page: Page, timeout = LOAD_TIMEOUT) {
	await waitForSessionReady(page, timeout);
	await waitOutOfLoading(
		page,
		'admin-catalog-loading',
		page.getByTestId('admin-catalog-table'),
		timeout
	);
}

/** Superuser permissions/groups catalog table. */
export async function waitForSuperuserCatalog(page: Page, timeout = LOAD_TIMEOUT) {
	await waitForSessionReady(page, timeout);
	await waitOutOfLoading(
		page,
		'superuser-catalog-loading',
		page.getByTestId('superuser-catalog-table'),
		timeout
	);
}

/** Permission visibility — search (list/matrix) or empty-prereq when catalog is empty. */
export async function waitForVisibilityPanel(page: Page, timeout = LOAD_TIMEOUT) {
	await waitForSessionReady(page, timeout);
	const ready = page
		.getByTestId('superuser-visibility-search')
		.or(page.getByTestId('superuser-visibility-empty-prereq'));
	await waitOutOfLoading(page, 'superuser-visibility-loading', ready, timeout);
}

/** Admin-User Management table. */
export async function waitForAdminManagement(page: Page, timeout = LOAD_TIMEOUT) {
	await waitForSessionReady(page, timeout);
	await waitOutOfLoading(
		page,
		'admin-mgmt-loading',
		page.getByTestId('admin-mgmt-table'),
		timeout
	);
}

/** Wait until a specific admin row is rendered (users cache + management map settled). */
export async function waitForAdminManagementRow(
	page: Page,
	adminEmail: string,
	timeout = LOAD_TIMEOUT
) {
	await waitForAdminManagement(page, timeout);
	const row = page.locator(
		`[data-testid="admin-mgmt-row"][data-admin-email="${adminEmail}"]`
	);
	await expect(row).toBeVisible({ timeout });
	return row;
}


/** User detail — email is present once the user payload has loaded. */
export async function waitForUserDetail(page: Page, timeout = LOAD_TIMEOUT) {
	await waitForSessionReady(page, timeout);
	await waitOutOfLoading(page, 'user-detail-loading', page.getByTestId('user-detail-email'), timeout);
}

/**
 * After revoke/lock/delete invalidates a session — reload or navigate and wait for login.
 * Waits for /api/me to settle so we do not assert while "Loading session…" is still up.
 */
export async function waitForSignedOut(
	page: Page,
	opts?: { path?: string; reload?: boolean; timeout?: number }
) {
	const timeout = opts?.timeout ?? REDIRECT_TIMEOUT;
	const meResponse = page.waitForResponse(matchMeGet, { timeout: LOAD_TIMEOUT }).catch(() => undefined);
	if (opts?.reload) {
		await page.reload();
	} else {
		await page.goto(opts?.path ?? '/dashboard');
	}
	await meResponse;
	await expect(page.getByTestId('login-page')).toBeVisible({ timeout });
	await expect(page.getByTestId('app-nav')).toHaveCount(0);
}

/** Password change signs out immediately after success — wait for API then login redirect. */
export async function waitForPasswordChangeSignOut(page: Page) {
	const changeResponse = page.waitForResponse(matchPasswordChange, { timeout: LOAD_TIMEOUT });
	await page.getByTestId('confirm-modal-confirm').click();
	const res = await changeResponse;
	expect(res.ok()).toBeTruthy();
	await expect(page.getByTestId('login-page')).toBeVisible({ timeout: REDIRECT_TIMEOUT });
}
