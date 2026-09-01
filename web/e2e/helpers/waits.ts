import { expect, type Page, type Response } from '@playwright/test';

/** Panel/session waits — raise via PLAYWRIGHT_LOAD_TIMEOUT under heavy worker load. */
export const LOAD_TIMEOUT = Number(process.env.PLAYWRIGHT_LOAD_TIMEOUT || 45_000);

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

/**
 * Panels that swap a loading testid for a ready marker after fetch.
 * Under high worker load those fetches routinely exceed Playwright's default expect timeout.
 */
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
 * Protected layout boots via /api/me before any page shell mounts.
 * Under heavy parallelism that call often takes longer than a few seconds.
 */
export async function waitForSessionReady(page: Page, timeout = LOAD_TIMEOUT) {
	try {
		await waitOutOfLoading(page, 'session-loading', page.getByTestId('app-nav'), timeout);
	} catch (err) {
		if (!(await page.getByTestId('session-loading').isVisible().catch(() => false))) throw err;
		await page.reload({ waitUntil: 'domcontentloaded' });
		await waitOutOfLoading(page, 'session-loading', page.getByTestId('app-nav'), timeout);
	}
}

/** After goto/nav into a protected route — session + page shell. */
export async function waitForPageShell(page: Page, testId: string, timeout = LOAD_TIMEOUT) {
	await waitForSessionReady(page, timeout);
	await expect(page.getByTestId(testId)).toBeVisible({ timeout });
}

/** Request-update onMount fetches — groups section reflects API data (not initial empty placeholder). */
export async function waitForRequestUpdateCatalog(page: Page, timeout = LOAD_TIMEOUT) {
	await expect(page.getByTestId('request-update-form')).toBeVisible({ timeout });
	await expect(
		page
			.getByTestId('request-update-groups')
			.or(page.getByTestId('request-update-groups-empty'))
	).toBeVisible({ timeout });
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

/** User detail — email is present once the user payload has loaded. */
export async function waitForUserDetail(page: Page, timeout = LOAD_TIMEOUT) {
	await waitForSessionReady(page, timeout);
	await waitOutOfLoading(
		page,
		'user-detail-loading',
		page.getByTestId('user-detail-email'),
		timeout
	);
}

/**
 * After revoke/lock/delete invalidates a session — reload or navigate and wait for login.
 * Waits for /api/me to settle so we do not assert while "Loading session…" is still up.
 */
export async function waitForSignedOut(
	page: Page,
	opts?: { path?: string; reload?: boolean; timeout?: number }
) {
	const timeout = opts?.timeout ?? LOAD_TIMEOUT;
	const meResponse = page.waitForResponse(
		(res) => res.url().includes('/api/users/me') && res.request().method() === 'GET',
		{ timeout }
	);
	if (opts?.reload) {
		await page.reload();
	} else {
		await page.goto(opts?.path ?? '/dashboard');
	}
	await meResponse.catch(() => undefined);
	await expect(page.getByTestId('login-page')).toBeVisible({ timeout });
	await expect(page.getByTestId('app-nav')).toHaveCount(0);
}
