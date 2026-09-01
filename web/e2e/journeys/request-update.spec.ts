import { test, expect } from '../helpers/fixtures';
import type { Locator, Page } from '@playwright/test';
import { loginAs, loginViaRequest, startUserSession } from '../helpers/auth';
import {
	createEphemeralUser,
	deleteUserById,
	openUserDetailById,
	openUserDetailFromAdmin,
	openUserDetailFromSuperuser,
	patchUserMaps
} from '../helpers/userApi';
import { waitForPageShell, waitForUserDetail, waitForUsersList, matchUserUpdate, LOAD_TIMEOUT } from '../helpers/waits';
import { describeTags, TAG } from '../helpers/tags';

test.describe.configure({ timeout: 120_000 });

const SCOPE_GROUP = 'asdfasdf';
const VISIBILITY_GROUP = 'group_a';

async function waitForToastGone(page: Page) {
	await expect(page.getByTestId('toast')).toBeHidden({ timeout: 7000 });
}

function groupsMultiselect(page: Page): Locator {
	return page.locator('[data-testid="multiselect"][data-label="Groups"]');
}

function permissionsMultiselect(page: Page): Locator {
	return page.locator('[data-testid="multiselect"][data-label="Permissions"]');
}

async function stageGroupAdd(page: Page): Promise<string> {
	const groupSection = page.getByTestId('request-update-groups');
	await expect(groupSection).toBeVisible();
	const ms = groupsMultiselect(page);
	await ms.getByTestId('multiselect-input').click();
	const option = ms.getByTestId('multiselect-option').first();
	if ((await option.count()) === 0) {
		test.skip(true, 'No addable groups available for request-update');
	}
	const key = await option.getAttribute('data-key');
	expect(key).toBeTruthy();
	await option.click();
	await expect(page.getByTestId('change-summary-added')).toBeVisible();
	await page.keyboard.press('Escape');
	await expect(ms.getByTestId('multiselect-dropdown')).toHaveCount(0);
	return key!;
}

async function stageGroupAddByName(page: Page, groupName: string) {
	const groupSection = page.getByTestId('request-update-groups');
	await expect(groupSection).toBeVisible();
	const ms = groupsMultiselect(page);
	await ms.getByTestId('multiselect-input').fill(groupName);
	const option = ms.locator(`[data-testid="multiselect-option"][data-key="${groupName}"]`);
	await expect(option).toBeVisible();
	await option.click();
	await expect(page.getByTestId('change-summary-added')).toBeVisible();
	await page.keyboard.press('Escape');
}

async function stagePermissionAdd(page: Page, permissionName: string) {
	const permSection = page.getByTestId('request-update-permissions');
	await expect(permSection).toBeVisible();
	const ms = permissionsMultiselect(page);
	await ms.getByTestId('multiselect-input').fill(permissionName);
	await ms.locator(`[data-testid="multiselect-option"][data-key="${permissionName}"]`).click();
	await expect(page.getByTestId('change-summary-added')).toBeVisible();
	await page.keyboard.press('Escape');
	await expect(ms.getByTestId('multiselect-dropdown')).toHaveCount(0);
}

async function stagePermissionAddByName(page: Page, permissionName: string) {
	await stagePermissionAdd(page, permissionName);
}

async function stageGroupRemoveByName(page: Page, groupName: string) {
	const ms = groupsMultiselect(page);
	const chip = ms.locator(`[data-testid="multiselect-chip"][data-key="${groupName}"]`);
	await expect(chip).toBeVisible();
	await chip.click();
	await expect(page.getByTestId('change-summary-removed')).toBeVisible();
}

async function stagePermissionRemoveByName(page: Page, permissionName: string) {
	const ms = permissionsMultiselect(page);
	const chip = ms.locator(`[data-testid="multiselect-chip"][data-key="${permissionName}"]`);
	await expect(chip).toBeVisible();
	await chip.click();
	await expect(page.getByTestId('change-summary-removed')).toBeVisible();
}

async function submitRequestUpdate(page: Page) {
	const submitResponse = page.waitForResponse(
		(res) =>
			res.url().includes('/api/users/request-update-from-admin') &&
			res.request().method() === 'POST'
	);
	await page.getByTestId('request-update-submit').click();
	await submitResponse;
	await expect(page.getByTestId('toast')).toContainText('Request submitted');
	await page.waitForURL(/\/dashboard/, { timeout: 10_000 });
}

async function adminApproveUpdate(adminPage: Page, email: string) {
	await adminPage.goto('/admin');
	await waitForPageShell(adminPage, 'admin-page');
	await openUserDetailFromAdmin(adminPage, email);
	await expect(adminPage.getByTestId('user-detail-pending-update')).toBeVisible();
	const updateResponse = adminPage.waitForResponse(matchUserUpdate, { timeout: LOAD_TIMEOUT });
	await adminPage.getByTestId('user-detail-approve-update').click();
	await adminPage.getByTestId('confirm-modal-confirm').click();
	await updateResponse;
	await expect(adminPage.getByTestId('toast')).toContainText('Update approved', {
		timeout: LOAD_TIMEOUT
	});
}

async function stageAnyGroupChange(page: Page) {
	const groupSection = page.getByTestId('request-update-groups');
	await expect(groupSection).toBeVisible();
	const ms = groupsMultiselect(page);
	await ms.getByTestId('multiselect-input').click();
	const addable = ms.getByTestId('multiselect-option');
	if ((await addable.count()) > 0) {
		await addable.first().click();
		await expect(page.getByTestId('change-summary-added')).toBeVisible();
	} else {
		await page.keyboard.press('Escape');
		const chip = groupSection.getByTestId('multiselect-chip').first();
		await expect(chip).toBeVisible();
		await chip.click();
		await expect(page.getByTestId('change-summary-removed')).toBeVisible();
	}
	await page.keyboard.press('Escape');
	await expect(ms.getByTestId('multiselect-dropdown')).toHaveCount(0);
}

async function submitGroupRequest(page: Page, groupName: string) {
	await page.getByTestId('dashboard-link-request-update').click();
	await waitForPageShell(page, 'request-update-page');
	await expect(page.getByTestId('request-update-groups')).toBeVisible({ timeout: 15_000 });
	await stageGroupAddByName(page, groupName);
	const submitResponse = page.waitForResponse(
		(res) =>
			res.url().includes('/api/users/request-update-from-admin') &&
			res.request().method() === 'POST'
	);
	await page.getByTestId('request-update-submit').click();
	await submitResponse;
	await expect(page.getByTestId('toast')).toContainText('Request submitted');
	await page.waitForURL(/\/dashboard/, { timeout: 10_000 });
}

async function reloadDashboardWithMe(page: Page) {
	const meResponse = page.waitForResponse(
		(res) => res.url().includes('/api/users/me') && res.request().method() === 'GET',
		{ timeout: LOAD_TIMEOUT }
	);
	await page.reload();
	await meResponse;
}

async function adminRejectUpdate(adminPage: Page, email: string, userId?: string) {
	if (userId) {
		await openUserDetailById(adminPage, userId, email);
	} else {
		await adminPage.goto('/admin');
		await waitForPageShell(adminPage, 'admin-page');
		await openUserDetailFromAdmin(adminPage, email);
	}
	await expect(adminPage.getByTestId('user-detail-pending-update')).toBeVisible();
	const updateResponse = adminPage.waitForResponse(matchUserUpdate, { timeout: LOAD_TIMEOUT });
	await adminPage.getByTestId('user-detail-reject-update').click();
	await adminPage.getByTestId('confirm-modal-confirm').click();
	await updateResponse;
	await expect(adminPage.getByTestId('toast')).toContainText('Update rejected', {
		timeout: LOAD_TIMEOUT
	});
	await waitForToastGone(adminPage);
}

async function superuserApproveUpdate(suPage: Page, email: string, userId?: string) {
	if (userId) {
		await openUserDetailById(suPage, userId, email);
	} else {
		await suPage.goto('/superuser');
		await waitForPageShell(suPage, 'superuser-page');
		await openUserDetailFromSuperuser(suPage, email);
	}
	await expect(suPage.getByTestId('user-detail-pending-update')).toBeVisible();
	const updateResponse = suPage.waitForResponse(matchUserUpdate, { timeout: LOAD_TIMEOUT });
	await suPage.getByTestId('user-detail-approve-update').click();
	await suPage.getByTestId('confirm-modal-confirm').click();
	await updateResponse;
	await expect(suPage.getByTestId('toast')).toContainText('Update approved', {
		timeout: LOAD_TIMEOUT
	});
	await waitForToastGone(suPage);
}

/**
 * Request-update journeys: form UX, admin/superuser decisions, user dashboard outcomes,
 * actor handoffs, and users-list integration.
 */
test.describe('Request update', describeTags(TAG.journey, TAG.requestUpdate), () => {
	test.describe('form', () => {
		test('shows the request-update form from the dashboard', async ({ adminPage: page }) => {
			await page.goto('/dashboard');
			await page.getByTestId('dashboard-link-request-update').click();
			await expect(page).toHaveURL(/\/request-update/);
			await expect(page.getByTestId('request-update-page')).toBeVisible();
			await expect(page.getByTestId('request-update-submit')).toBeDisabled();
		});

		test('back link returns to dashboard without submitting', async ({ adminPage: page }) => {
			await page.goto('/request-update');
			await waitForPageShell(page, 'request-update-page');
			await page.getByTestId('request-update-back').click();
			await expect(page).toHaveURL(/\/dashboard/);
		});

		test('reverts a staged group change via change summary', async ({ browser, ephemeralUser }) => {
			const context = await browser.newContext();
			const page = await context.newPage();
			await startUserSession(page, ephemeralUser);
			await page.getByTestId('dashboard-link-request-update').click();
			await waitForPageShell(page, 'request-update-page');

			await expect(
				page.getByTestId('multiselect-chip').or(page.getByTestId('request-update-groups-empty')).first()
			).toBeVisible({ timeout: 15_000 });

			await stageAnyGroupChange(page);
			await expect(
				page.getByTestId('change-summary-added').or(page.getByTestId('change-summary-removed'))
			).toBeVisible();

			await page.locator('[data-testid="change-summary-item"]').first().click();
			await expect(page.getByTestId('change-summary-empty')).toBeVisible();
			await expect(page.getByTestId('request-update-submit')).toBeDisabled();
			await context.close();
		});
	});

	test.describe('admin and superuser decisions', () => {
		test('user submits a request and superuser rejects it', async ({
			browser,
			superuserPage: suPage,
			ephemeralUser
		}) => {
			const userContext = await browser.newContext();
			const userPage = await userContext.newPage();
			await startUserSession(userPage, ephemeralUser);
			await userPage.getByTestId('dashboard-link-request-update').click();
			await expect(
				userPage
					.getByTestId('multiselect-chip')
					.or(userPage.getByTestId('request-update-groups-empty'))
					.first()
			).toBeVisible({ timeout: 15_000 });
			await stageAnyGroupChange(userPage);
			await userPage.getByTestId('request-update-submit').click();
			await expect(userPage.getByTestId('toast')).toContainText('Request submitted');
			await userPage.waitForURL(/\/dashboard/, { timeout: 10_000 });
			await userContext.close();

			await suPage.goto('/superuser');
			await openUserDetailFromSuperuser(suPage, ephemeralUser.email);
			await expect(suPage.getByTestId('user-detail-pending-update')).toBeVisible();
			await suPage.getByTestId('user-detail-reject-update').click();
			await suPage.getByTestId('confirm-modal-confirm').click();
			await expect(suPage.getByTestId('toast')).toContainText('Update rejected');
			await waitForToastGone(suPage);
			await expect(suPage.getByTestId('user-detail-pending-update')).toHaveCount(0);
		});

		test('user submits a group add and superuser approves it', async ({
			browser,
			superuserPage: suPage,
			suRequest,
			ephemeralUser
		}) => {
			const userContext = await browser.newContext();
			const userPage = await userContext.newPage();
			await startUserSession(userPage, ephemeralUser);
			await userPage.getByTestId('dashboard-link-request-update').click();
			await expect(
				userPage
					.getByTestId('multiselect-chip')
					.or(userPage.getByTestId('request-update-groups-empty'))
					.first()
			).toBeVisible({ timeout: 15_000 });

			const addedGroup = await stageGroupAdd(userPage);
			await userPage.getByTestId('request-update-submit').click();
			await expect(userPage.getByTestId('toast')).toContainText('Request submitted');
			await userPage.waitForURL(/\/dashboard/, { timeout: 10_000 });
			await userContext.close();

			await suPage.goto('/superuser');
			await openUserDetailFromSuperuser(suPage, ephemeralUser.email);
			await expect(
				suPage.locator(
					`[data-testid="user-detail-pending-group"][data-key="${addedGroup}"][data-kind="add"]`
				)
			).toBeVisible();
			await suPage.getByTestId('user-detail-approve-update').click();
			await suPage.getByTestId('confirm-modal-confirm').click();
			await expect(suPage.getByTestId('toast')).toContainText('Update approved');
			await waitForToastGone(suPage);
			await expect(suPage.getByTestId('user-detail-pending-update')).toHaveCount(0);

			await patchUserMaps(suRequest, ephemeralUser.id, { groups: { [addedGroup]: false } }).catch(
				() => undefined
			);
		});

		test('user submits a permission add and admin approves it', async ({
			browser,
			adminPage: adminPage,
			suRequest,
			ephemeralUser,
			uniqueSuffix
		}) => {
			const permissionName = `e2e_req_perm_${uniqueSuffix}`;

			try {
				const createRes = await suRequest.post('/api/admin/permissions', {
					data: { name: permissionName, definition: 'E2E request-update permission' }
				});
				expect(createRes.ok()).toBeTruthy();

				const visRes = await suRequest.post('/api/admin/permissions/visibility', {
					data: { permission_name: permissionName, group_name: VISIBILITY_GROUP }
				});
				expect(visRes.ok()).toBeTruthy();

				const userContext = await browser.newContext();
				const userPage = await userContext.newPage();
				await loginViaRequest(userPage.request, ephemeralUser);
				await userPage.goto('/dashboard');
				await expect(userPage.getByTestId('dashboard-page')).toBeVisible({ timeout: LOAD_TIMEOUT });
				await userPage.getByTestId('dashboard-link-request-update').click();
				await expect(userPage.getByTestId('request-update-page')).toBeVisible();
				await expect(
					userPage
						.getByTestId('multiselect-chip')
						.or(userPage.getByTestId('request-update-permissions-empty'))
						.first()
				).toBeVisible({ timeout: 15_000 });

				await stagePermissionAdd(userPage, permissionName);
				await userPage.getByTestId('request-update-submit').click();
				await expect(userPage.getByTestId('toast')).toContainText('Request submitted');
				await userPage.waitForURL(/\/dashboard/, { timeout: 10_000 });
				await userContext.close();

				await adminPage.goto('/admin');
				await openUserDetailFromAdmin(adminPage, ephemeralUser.email);
				await expect(
					adminPage.locator(
						`[data-testid="user-detail-pending-perm"][data-key="${permissionName}"][data-kind="add"]`
					)
				).toBeVisible();
				await adminPage.getByTestId('user-detail-approve-update').click();
				await adminPage.getByTestId('confirm-modal-confirm').click();
				await expect(adminPage.getByTestId('toast')).toContainText('Update approved');
				await waitForToastGone(adminPage);
				await expect(adminPage.getByTestId('user-detail-pending-update')).toHaveCount(0);
			} finally {
				await suRequest
					.delete('/api/admin/permissions/visibility', {
						data: { permission_name: permissionName, group_name: VISIBILITY_GROUP }
					})
					.catch(() => undefined);
				await patchUserMaps(suRequest, ephemeralUser.id, {
					permissions: { [permissionName]: false }
				}).catch(() => undefined);
				await suRequest
					.delete(`/api/admin/permissions/${encodeURIComponent(permissionName)}`)
					.catch(() => undefined);
			}
		});

		test('lists users with a pending-update badge after a request is filed', async ({
			browser,
			superuserPage: page,
			ephemeralUser
		}) => {
			const userContext = await browser.newContext();
			const userPage = await userContext.newPage();
			await startUserSession(userPage, ephemeralUser);
			await userPage.getByTestId('dashboard-link-request-update').click();
			await waitForPageShell(userPage, 'request-update-page');
			await stageAnyGroupChange(userPage);
			await userPage.getByTestId('request-update-submit').click();
			await expect(userPage.getByTestId('toast')).toContainText('Request submitted');
			await userContext.close();

			await page.goto('/superuser');
			await waitForPageShell(page, 'superuser-page');
			await waitForUsersList(page);

			const usersResponse = page.waitForResponse(
				(res) =>
					res.url().includes('/api/users') &&
					res.url().includes('q=') &&
					res.request().method() === 'GET'
			);
			await page.getByTestId('users-list-search').fill(ephemeralUser.email);
			await usersResponse;

			const row = page.locator(
				`[data-testid="users-list-row"][data-user-email="${ephemeralUser.email}"]`
			);
			await expect(row).toBeVisible();
			await expect(row.getByText('Update requested')).toBeVisible();

			await row.getByTestId('users-list-edit').click();
			await waitForUserDetail(page);
			await expect(page.getByTestId('user-detail-pending-update')).toBeVisible();
			await page.getByTestId('user-detail-reject-update').click();
			await page.getByTestId('confirm-modal-confirm').click();
			await expect(page.getByTestId('toast')).toContainText('Update rejected');
		});
	});

	test.describe('user dashboard outcomes', () => {
		test('pending banner clears after admin rejects the request', async ({
			regularUserPage: page,
			adminPage: adminPage
		}) => {
			await submitGroupRequest(page, SCOPE_GROUP);
			await reloadDashboardWithMe(page);
			await expect(page.getByTestId('dashboard-pending-update')).toBeVisible();

			await adminPage.goto('/admin');
			await openUserDetailFromAdmin(
				adminPage,
				(await page.getByTestId('dashboard-email').innerText()).trim()
			);
			await adminPage.getByTestId('user-detail-reject-update').click();
			await adminPage.getByTestId('confirm-modal-confirm').click();
			await expect(adminPage.getByTestId('toast')).toContainText('Update rejected');

			await reloadDashboardWithMe(page);
			await expect(page.getByTestId('dashboard-pending-update')).toHaveCount(0);
			await expect(
				page.locator(`[data-testid="dashboard-group-chip"][data-key="${SCOPE_GROUP}"]`)
			).toHaveCount(0);
		});

		test('approved group request appears on dashboard after reload', async ({
			regularUserPage: page,
			adminPage: adminPage
		}) => {
			const email = await page.getByTestId('dashboard-email').innerText();
			await submitGroupRequest(page, SCOPE_GROUP);

			await adminPage.goto('/admin');
			await openUserDetailFromAdmin(adminPage, email.trim());
			await expect(adminPage.getByTestId('user-detail-pending-update')).toBeVisible();
			await adminPage.getByTestId('user-detail-approve-update').click();
			await adminPage.getByTestId('confirm-modal-confirm').click();
			await expect(adminPage.getByTestId('toast')).toContainText('Update approved');

			await reloadDashboardWithMe(page);
			await expect(page.getByTestId('dashboard-pending-update')).toHaveCount(0);
			await expect(
				page.locator(`[data-testid="dashboard-group-chip"][data-key="${SCOPE_GROUP}"]`)
			).toBeVisible();
		});

		test('second request replaces the first pending update', async ({
			regularUserPage: page,
			adminPage: adminPage,
			suRequest,
			ephemeralUser,
			uniqueSuffix
		}) => {
			const permissionName = `e2e_overwrite_${uniqueSuffix}`;

			try {
				const createRes = await suRequest.post('/api/admin/permissions', {
					data: { name: permissionName, definition: 'E2E overwrite pending update permission' }
				});
				expect(createRes.ok()).toBeTruthy();

				const visRes = await suRequest.post('/api/admin/permissions/visibility', {
					data: { permission_name: permissionName, group_name: VISIBILITY_GROUP }
				});
				expect(visRes.ok()).toBeTruthy();

				await submitGroupRequest(page, SCOPE_GROUP);
				await reloadDashboardWithMe(page);
				await expect(page.getByTestId('dashboard-pending-update')).toBeVisible();

				await page.getByTestId('dashboard-link-request-update').click();
				await waitForPageShell(page, 'request-update-page');
				await expect(page.getByTestId('request-update-permissions')).toBeVisible({
					timeout: 15_000
				});
				await stagePermissionAddByName(page, permissionName);

				const submitResponse = page.waitForResponse(
					(res) =>
						res.url().includes('/api/users/request-update-from-admin') &&
						res.request().method() === 'POST'
				);
				await page.getByTestId('request-update-submit').click();
				await submitResponse;
				await expect(page.getByTestId('toast')).toContainText('Request submitted');
				await page.waitForURL(/\/dashboard/, { timeout: 10_000 });

				await adminPage.goto('/admin');
				await openUserDetailFromAdmin(adminPage, ephemeralUser.email);
				await expect(adminPage.getByTestId('user-detail-pending-update')).toBeVisible();
				await expect(adminPage.getByTestId('user-detail-pending-permissions')).toBeVisible();
				await expect(
					adminPage.locator(
						`[data-testid="user-detail-pending-perm"][data-key="${permissionName}"]`
					)
				).toBeVisible();
				await expect(adminPage.getByTestId('user-detail-pending-groups')).toHaveCount(0);
			} finally {
				await suRequest
					.delete('/api/admin/permissions/visibility', {
						data: { permission_name: permissionName, group_name: VISIBILITY_GROUP }
					})
					.catch(() => undefined);
				await suRequest
					.delete(`/api/admin/permissions/${encodeURIComponent(permissionName)}`)
					.catch(() => undefined);
			}
		});

		test('permission add approved appears on user dashboard after reload', async ({
			browser,
			adminPage,
			suRequest,
			ephemeralUser,
			uniqueSuffix
		}) => {
			const permissionName = `e2e_perm_chip_${uniqueSuffix}`;

			try {
				const createRes = await suRequest.post('/api/admin/permissions', {
					data: { name: permissionName, definition: 'E2E permission chip after approve' }
				});
				expect(createRes.ok()).toBeTruthy();
				await suRequest.post('/api/admin/permissions/visibility', {
					data: { permission_name: permissionName, group_name: VISIBILITY_GROUP }
				});

				const userContext = await browser.newContext();
				const userPage = await userContext.newPage();
				await startUserSession(userPage, ephemeralUser);
				await userPage.getByTestId('dashboard-link-request-update').click();
				await waitForPageShell(userPage, 'request-update-page');
				await stagePermissionAdd(userPage, permissionName);
				await submitRequestUpdate(userPage);
				await userContext.close();

				await adminApproveUpdate(adminPage, ephemeralUser.email);

				const verifyContext = await browser.newContext();
				const verifyPage = await verifyContext.newPage();
				await startUserSession(verifyPage, ephemeralUser);
				await reloadDashboardWithMe(verifyPage);
				await expect(
					verifyPage.locator(`[data-testid="dashboard-permission-chip"][data-key="${permissionName}"]`)
				).toBeVisible();
				await verifyContext.close();
			} finally {
				await suRequest
					.delete('/api/admin/permissions/visibility', {
						data: { permission_name: permissionName, group_name: VISIBILITY_GROUP }
					})
					.catch(() => undefined);
				await patchUserMaps(suRequest, ephemeralUser.id, {
					permissions: { [permissionName]: false }
				}).catch(() => undefined);
				await suRequest
					.delete(`/api/admin/permissions/${encodeURIComponent(permissionName)}`)
					.catch(() => undefined);
			}
		});
	});

	test.describe('actor handoffs', () => {
		test('admin rejects group request, user re-requests, superuser approves', async ({
			regularUserPage: page,
			adminPage,
			superuserPage: suPage,
			ephemeralUser
		}) => {
			await submitGroupRequest(page, SCOPE_GROUP);
			await reloadDashboardWithMe(page);
			await expect(page.getByTestId('dashboard-pending-update')).toBeVisible();

			await adminRejectUpdate(adminPage, ephemeralUser.email, ephemeralUser.id);

			await reloadDashboardWithMe(page);
			await expect(page.getByTestId('dashboard-pending-update')).toHaveCount(0);
			await expect(
				page.locator(`[data-testid="dashboard-group-chip"][data-key="${SCOPE_GROUP}"]`)
			).toHaveCount(0);

			await submitGroupRequest(page, SCOPE_GROUP);
			await reloadDashboardWithMe(page);
			await expect(page.getByTestId('dashboard-pending-update')).toBeVisible();

			await superuserApproveUpdate(suPage, ephemeralUser.email, ephemeralUser.id);

			await reloadDashboardWithMe(page);
			await expect(page.getByTestId('dashboard-pending-update')).toHaveCount(0);
			await expect(
				page.locator(`[data-testid="dashboard-group-chip"][data-key="${SCOPE_GROUP}"]`)
			).toBeVisible();
		});

		test('admin rejects permission request, user dashboard stays unchanged', async ({
			regularUserPage: page,
			adminPage,
			suRequest,
			ephemeralUser,
			uniqueSuffix
		}) => {
			const permissionName = `e2e_reject_perm_${uniqueSuffix}`;

			try {
				const createRes = await suRequest.post('/api/admin/permissions', {
					data: { name: permissionName, definition: 'E2E permission reject journey' }
				});
				expect(createRes.ok()).toBeTruthy();

				const visRes = await suRequest.post('/api/admin/permissions/visibility', {
					data: { permission_name: permissionName, group_name: VISIBILITY_GROUP }
				});
				expect(visRes.ok()).toBeTruthy();

				await page.getByTestId('dashboard-link-request-update').click();
				await waitForPageShell(page, 'request-update-page');
				await expect(page.getByTestId('request-update-permissions')).toBeVisible({
					timeout: 15_000
				});
				await stagePermissionAddByName(page, permissionName);
				const submitResponse = page.waitForResponse(
					(res) =>
						res.url().includes('/api/users/request-update-from-admin') &&
						res.request().method() === 'POST'
				);
				await page.getByTestId('request-update-submit').click();
				await submitResponse;
				await page.waitForURL(/\/dashboard/, { timeout: 10_000 });

				await reloadDashboardWithMe(page);
				await expect(page.getByTestId('dashboard-pending-update')).toBeVisible();
				await expect(
					page.locator(`[data-testid="dashboard-permission-chip"][data-key="${permissionName}"]`)
				).toHaveCount(0);

				await adminRejectUpdate(adminPage, ephemeralUser.email);

				await reloadDashboardWithMe(page);
				await expect(page.getByTestId('dashboard-pending-update')).toHaveCount(0);
				await expect(
					page.locator(`[data-testid="dashboard-permission-chip"][data-key="${permissionName}"]`)
				).toHaveCount(0);
			} finally {
				await suRequest
					.delete('/api/admin/permissions/visibility', {
						data: { permission_name: permissionName, group_name: VISIBILITY_GROUP }
					})
					.catch(() => undefined);
				await suRequest
					.delete(`/api/admin/permissions/${encodeURIComponent(permissionName)}`)
					.catch(() => undefined);
			}
		});

		test('admin rejects update request, superuser sees no pending update', async ({
			browser,
			adminPage,
			superuserPage: suPage,
			ephemeralUser
		}) => {
			const userContext = await browser.newContext();
			const userPage = await userContext.newPage();
			await startUserSession(userPage, ephemeralUser);
			await submitGroupRequest(userPage, SCOPE_GROUP);
			await userContext.close();

			await adminRejectUpdate(adminPage, ephemeralUser.email);

			await suPage.goto('/superuser');
			await openUserDetailFromSuperuser(suPage, ephemeralUser.email);
			await expect(suPage.getByTestId('user-detail-pending-update')).toHaveCount(0);
		});
	});

	test.describe('remove requests', () => {
		test('approved group remove request clears chip on user dashboard', async ({
			browser,
			adminPage,
			suRequest,
			ephemeralUser
		}) => {
			await patchUserMaps(suRequest, ephemeralUser.id, { groups: { [SCOPE_GROUP]: true } });

			const userContext = await browser.newContext();
			const userPage = await userContext.newPage();
			await startUserSession(userPage, ephemeralUser);
			await expect(
				userPage.locator(`[data-testid="dashboard-group-chip"][data-key="${SCOPE_GROUP}"]`)
			).toBeVisible();

			await userPage.getByTestId('dashboard-link-request-update').click();
			await waitForPageShell(userPage, 'request-update-page');
			await stageGroupRemoveByName(userPage, SCOPE_GROUP);
			await submitRequestUpdate(userPage);
			await userContext.close();

			await adminApproveUpdate(adminPage, ephemeralUser.email);

			const verifyContext = await browser.newContext();
			const verifyPage = await verifyContext.newPage();
			await startUserSession(verifyPage, ephemeralUser);
			await reloadDashboardWithMe(verifyPage);
			await expect(
				verifyPage.locator(`[data-testid="dashboard-group-chip"][data-key="${SCOPE_GROUP}"]`)
			).toHaveCount(0);
			await expect(
				verifyPage.locator(`[data-testid="dashboard-group-chip"][data-key="${VISIBILITY_GROUP}"]`)
			).toBeVisible();
			await verifyContext.close();
		});

		test('approved permission remove request clears chip on user dashboard', async ({
			browser,
			adminPage,
			suRequest,
			ephemeralUser,
			uniqueSuffix
		}) => {
			const permissionName = `e2e_rm_perm_${uniqueSuffix}`;
			const keepPermission = `e2e_keep_perm_${uniqueSuffix}`;

			try {
				for (const [name, definition] of [
					[permissionName, 'E2E permission remove journey'],
					[keepPermission, 'E2E permission kept after remove']
				] as const) {
					const createRes = await suRequest.post('/api/admin/permissions', {
						data: { name, definition }
					});
					expect(createRes.ok()).toBeTruthy();
					await suRequest.post('/api/admin/permissions/visibility', {
						data: { permission_name: name, group_name: VISIBILITY_GROUP }
					});
				}
				await patchUserMaps(suRequest, ephemeralUser.id, {
					permissions: { [permissionName]: true, [keepPermission]: true }
				});

				const userContext = await browser.newContext();
				const userPage = await userContext.newPage();
				await startUserSession(userPage, ephemeralUser);
				await expect(
					userPage.locator(`[data-testid="dashboard-permission-chip"][data-key="${permissionName}"]`)
				).toBeVisible();

				await userPage.getByTestId('dashboard-link-request-update').click();
				await waitForPageShell(userPage, 'request-update-page');
				await expect(userPage.getByTestId('request-update-permissions')).toBeVisible({
					timeout: 15_000
				});
				await stagePermissionRemoveByName(userPage, permissionName);
				await submitRequestUpdate(userPage);
				await userContext.close();

				await adminApproveUpdate(adminPage, ephemeralUser.email);

				const verifyContext = await browser.newContext();
				const verifyPage = await verifyContext.newPage();
				await startUserSession(verifyPage, ephemeralUser);
				await reloadDashboardWithMe(verifyPage);
				await expect(
					verifyPage.locator(`[data-testid="dashboard-permission-chip"][data-key="${permissionName}"]`)
				).toHaveCount(0);
				await expect(
					verifyPage.locator(`[data-testid="dashboard-permission-chip"][data-key="${keepPermission}"]`)
				).toBeVisible();
				await verifyContext.close();
			} finally {
				for (const name of [permissionName, keepPermission]) {
					await suRequest
						.delete('/api/admin/permissions/visibility', {
							data: { permission_name: name, group_name: VISIBILITY_GROUP }
						})
						.catch(() => undefined);
					await suRequest
						.delete(`/api/admin/permissions/${encodeURIComponent(name)}`)
						.catch(() => undefined);
				}
			}
		});

		test('rejected permission remove request leaves chip on user dashboard', async ({
			regularUserPage: page,
			adminPage,
			suRequest,
			ephemeralUser,
			uniqueSuffix
		}) => {
			const permissionName = `e2e_rej_rm_${uniqueSuffix}`;

			try {
				const createRes = await suRequest.post('/api/admin/permissions', {
					data: { name: permissionName, definition: 'E2E permission remove reject' }
				});
				expect(createRes.ok()).toBeTruthy();
				await suRequest.post('/api/admin/permissions/visibility', {
					data: { permission_name: permissionName, group_name: VISIBILITY_GROUP }
				});
				await patchUserMaps(suRequest, ephemeralUser.id, {
					permissions: { [permissionName]: true }
				});

				await page.reload();
				await expect(
					page.locator(`[data-testid="dashboard-permission-chip"][data-key="${permissionName}"]`)
				).toBeVisible();

				await page.getByTestId('dashboard-link-request-update').click();
				await waitForPageShell(page, 'request-update-page');
				await stagePermissionRemoveByName(page, permissionName);
				await submitRequestUpdate(page);

				await adminRejectUpdate(adminPage, ephemeralUser.email);

				await reloadDashboardWithMe(page);
				await expect(page.getByTestId('dashboard-pending-update')).toHaveCount(0);
				await expect(
					page.locator(`[data-testid="dashboard-permission-chip"][data-key="${permissionName}"]`)
				).toBeVisible();
			} finally {
				await suRequest
					.delete('/api/admin/permissions/visibility', {
						data: { permission_name: permissionName, group_name: VISIBILITY_GROUP }
					})
					.catch(() => undefined);
				await suRequest
					.delete(`/api/admin/permissions/${encodeURIComponent(permissionName)}`)
					.catch(() => undefined);
			}
		});

		test('admin cannot approve a request that would remove the users only group', async ({
			browser,
			adminPage,
			ephemeralUser
		}) => {
			const userContext = await browser.newContext();
			const userPage = await userContext.newPage();
			await startUserSession(userPage, ephemeralUser);
			await userPage.getByTestId('dashboard-link-request-update').click();
			await waitForPageShell(userPage, 'request-update-page');
			await stageGroupRemoveByName(userPage, VISIBILITY_GROUP);
			await submitRequestUpdate(userPage);
			await userContext.close();

			await adminPage.goto('/admin');
			await openUserDetailFromAdmin(adminPage, ephemeralUser.email);
			await expect(adminPage.getByTestId('user-detail-pending-update')).toBeVisible();
			await adminPage.getByTestId('user-detail-approve-update').click();
			await adminPage.getByTestId('confirm-modal-confirm').click();
			await expect(adminPage.getByTestId('toast')).toContainText(
				/cannot approve update request that would remove all groups/i
			);
			await expect(adminPage.getByTestId('user-detail-pending-update')).toBeVisible();
		});

		test('admin cannot approve a request that would remove the users only permission', async ({
			browser,
			adminPage,
			suRequest,
			ephemeralUser,
			uniqueSuffix
		}) => {
			const permissionName = `e2e_last_perm_${uniqueSuffix}`;

			try {
				const createRes = await suRequest.post('/api/admin/permissions', {
					data: { name: permissionName, definition: 'E2E sole permission safeguard' }
				});
				expect(createRes.ok()).toBeTruthy();
				await suRequest.post('/api/admin/permissions/visibility', {
					data: { permission_name: permissionName, group_name: VISIBILITY_GROUP }
				});
				await patchUserMaps(suRequest, ephemeralUser.id, {
					permissions: { [permissionName]: true }
				});

				const userContext = await browser.newContext();
				const userPage = await userContext.newPage();
				await startUserSession(userPage, ephemeralUser);
				await userPage.getByTestId('dashboard-link-request-update').click();
				await waitForPageShell(userPage, 'request-update-page');
				await stagePermissionRemoveByName(userPage, permissionName);
				await submitRequestUpdate(userPage);
				await userContext.close();

				await adminPage.goto('/admin');
				await openUserDetailFromAdmin(adminPage, ephemeralUser.email);
				await adminPage.getByTestId('user-detail-approve-update').click();
				await adminPage.getByTestId('confirm-modal-confirm').click();
				await expect(adminPage.getByTestId('toast')).toContainText(
					/cannot approve update request that would remove all permissions/i
				);
				await expect(adminPage.getByTestId('user-detail-pending-update')).toBeVisible();
			} finally {
				await suRequest
					.delete('/api/admin/permissions/visibility', {
						data: { permission_name: permissionName, group_name: VISIBILITY_GROUP }
					})
					.catch(() => undefined);
				await suRequest
					.delete(`/api/admin/permissions/${encodeURIComponent(permissionName)}`)
					.catch(() => undefined);
			}
		});
	});

	test.describe('after account approval', () => {
		test('approved registration then request-update approve shows group on dashboard', async ({
			browser,
			adminPage,
			suRequest,
			uniqueSuffix
		}) => {
			const user = await createEphemeralUser(suRequest, `chain_${uniqueSuffix}`, {
				approve: false,
				groups: ['group_a']
			});
			const userContext = await browser.newContext();
			const userPage = await userContext.newPage();
			try {
				await adminPage.goto('/admin');
				await openUserDetailFromAdmin(adminPage, user.email);
				await adminPage.getByTestId('user-detail-approve-account').click();
				await adminPage.getByTestId('confirm-modal-confirm').click();
				await expect(adminPage.getByTestId('toast')).toContainText('Account approved');
				await waitForToastGone(adminPage);

				await startUserSession(userPage, user);
				await submitGroupRequest(userPage, SCOPE_GROUP);
				await reloadDashboardWithMe(userPage);
				await expect(userPage.getByTestId('dashboard-pending-update')).toBeVisible();

				await adminPage.goto('/admin');
				await openUserDetailFromAdmin(adminPage, user.email);
				await adminPage.getByTestId('user-detail-approve-update').click();
				await adminPage.getByTestId('confirm-modal-confirm').click();
				await expect(adminPage.getByTestId('toast')).toContainText('Update approved');
				await waitForToastGone(adminPage);

				await reloadDashboardWithMe(userPage);
				await expect(userPage.getByTestId('dashboard-pending-update')).toHaveCount(0);
				await expect(
					userPage.locator(`[data-testid="dashboard-group-chip"][data-key="${SCOPE_GROUP}"]`)
				).toBeVisible();
			} finally {
				await userContext.close();
				await deleteUserById(suRequest, user.id).catch(() => undefined);
			}
		});
	});
});
