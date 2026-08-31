import { expect, type Page } from '@playwright/test';

const DEFAULT_TIMEOUT = 20_000;

/**
 * Panels that swap a loading testid for a ready marker after fetch.
 * Under high worker load those fetches routinely exceed Playwright's 5s default.
 */
async function waitOutOfLoading(
	page: Page,
	loadingTestId: string,
	ready: ReturnType<Page['getByTestId']>,
	timeout = DEFAULT_TIMEOUT
) {
	const loading = page.getByTestId(loadingTestId);
	await expect(ready.or(loading)).toBeVisible({ timeout });
	await expect(loading).toHaveCount(0, { timeout });
	await expect(ready).toBeVisible({ timeout });
}

/** UsersListPanel — `users-list` mounts only after the first fetch. */
export async function waitForUsersList(page: Page, timeout = DEFAULT_TIMEOUT) {
	await waitOutOfLoading(
		page,
		'users-list-loading',
		page.getByTestId('users-list'),
		timeout
	);
}

/** Admin permissions/groups catalog table. */
export async function waitForAdminCatalog(page: Page, timeout = DEFAULT_TIMEOUT) {
	await waitOutOfLoading(
		page,
		'admin-catalog-loading',
		page.getByTestId('admin-catalog-table'),
		timeout
	);
}

/** Superuser permissions/groups catalog table. */
export async function waitForSuperuserCatalog(page: Page, timeout = DEFAULT_TIMEOUT) {
	await waitOutOfLoading(
		page,
		'superuser-catalog-loading',
		page.getByTestId('superuser-catalog-table'),
		timeout
	);
}

/** Permission visibility — search (list/matrix) or empty-prereq when catalog is empty. */
export async function waitForVisibilityPanel(page: Page, timeout = DEFAULT_TIMEOUT) {
	const ready = page
		.getByTestId('superuser-visibility-search')
		.or(page.getByTestId('superuser-visibility-empty-prereq'));
	await waitOutOfLoading(page, 'superuser-visibility-loading', ready, timeout);
}

/** Admin-User Management table. */
export async function waitForAdminManagement(page: Page, timeout = DEFAULT_TIMEOUT) {
	await waitOutOfLoading(
		page,
		'admin-mgmt-loading',
		page.getByTestId('admin-mgmt-table'),
		timeout
	);
}

/** User detail — email is present once the user payload has loaded. */
export async function waitForUserDetail(page: Page, timeout = DEFAULT_TIMEOUT) {
	await waitOutOfLoading(
		page,
		'user-detail-loading',
		page.getByTestId('user-detail-email'),
		timeout
	);
}
