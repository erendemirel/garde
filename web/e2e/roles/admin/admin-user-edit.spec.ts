import { test, expect } from '../../helpers/fixtures';
import { loginAs, startUserSession } from '../../helpers/auth';
import { openUserDetailFromAdmin } from '../../helpers/userApi';

const VISIBILITY_GROUP = 'group_a';
/** Seed group shared by admin and manageable users — safe for admin approve of group add. */
const SCOPE_GROUP = 'asdfasdf';

async function waitForToastGone(page: import('@playwright/test').Page) {
	await expect(page.getByTestId('toast')).toBeHidden({ timeout: 7000 });
}

async function stageGroupAddByName(page: import('@playwright/test').Page, groupName: string) {
	const groupSection = page.getByTestId('request-update-groups');
	await expect(groupSection).toBeVisible();
	const ms = page.locator('[data-testid="multiselect"][data-label="Groups"]');
	await ms.getByTestId('multiselect-input').fill(groupName);
	const option = ms.locator(`[data-testid="multiselect-option"][data-key="${groupName}"]`);
	await expect(option).toBeVisible();
	await option.click();
	await expect(page.getByTestId('change-summary-added')).toBeVisible();
	await page.keyboard.press('Escape');
	await expect(ms.getByTestId('multiselect-dropdown')).toHaveCount(0);
}

/**
 * Admin user detail writes — scoped to shared groups + visibility rules.
 */
test.describe('Admin user detail edits', () => {
	test('grants then revokes a visibility-scoped permission', async ({
		adminPage: page,
		ephemeralUser,
		suRequest,
		uniqueSuffix
	}) => {
		const permissionName = `e2e_adm_edit_${uniqueSuffix}`;

		try {
			const createRes = await suRequest.post('/api/admin/permissions', {
				data: { name: permissionName, definition: 'E2E admin user detail permission' }
			});
			expect(createRes.ok()).toBeTruthy();

			const visRes = await suRequest.post('/api/admin/permissions/visibility', {
				data: { permission_name: permissionName, group_name: VISIBILITY_GROUP }
			});
			expect(visRes.ok()).toBeTruthy();

			await page.goto('/admin');
			await openUserDetailFromAdmin(page, ephemeralUser.email);

			const ms = page.locator('[data-testid="multiselect"][data-label="Permissions"]');
			await ms.getByTestId('multiselect-input').fill(permissionName);
			await ms
				.locator(`[data-testid="multiselect-option"][data-key="${permissionName}"]`)
				.click();
			await expect(
				ms.locator(`[data-testid="multiselect-chip"][data-key="${permissionName}"]`)
			).toHaveAttribute('data-state', 'added');
			await page.getByTestId('user-detail-permissions').locator('h3').click();

			await page.getByTestId('user-detail-save').click();
			await page.getByTestId('confirm-modal-confirm').click();
			await expect(page.getByTestId('toast')).toContainText('Updated');
			await waitForToastGone(page);

			await ms
				.locator(
					`[data-testid="multiselect-chip"][data-key="${permissionName}"][data-state="selected"]`
				)
				.click();
			await expect(page.getByTestId('change-summary-removed')).toBeVisible();
			await page.getByTestId('user-detail-save').click();
			await page.getByTestId('confirm-modal-confirm').click();
			await expect(page.getByTestId('toast')).toContainText('Updated');
			await waitForToastGone(page);
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

	test('approves a pending group update from admin user detail', async ({
		browser,
		adminPage: page,
		ephemeralUser
	}) => {
		const userContext = await browser.newContext();
		const userPage = await userContext.newPage();
		await startUserSession(userPage, ephemeralUser);
		await userPage.getByTestId('dashboard-link-request-update').click();
		await expect(userPage.getByTestId('request-update-page')).toBeVisible();
		await expect(userPage.getByTestId('request-update-groups')).toBeVisible({ timeout: 15_000 });

		// Request adding a group the seed admin belongs to (required for admin pending visibility).
		await stageGroupAddByName(userPage, SCOPE_GROUP);
		const submitResponse = userPage.waitForResponse(
			(res) =>
				res.url().includes('/api/users/request-update-from-admin') &&
				res.request().method() === 'POST'
		);
		await userPage.getByTestId('request-update-submit').click();
		await submitResponse;
		await expect(userPage.getByTestId('toast')).toContainText('Request submitted');
		await userPage.waitForURL(/\/dashboard/, { timeout: 10_000 });
		await userContext.close();

		await page.goto('/admin');
		await openUserDetailFromAdmin(page, ephemeralUser.email);
		await expect(page.getByTestId('user-detail-pending-update')).toBeVisible();
		await expect(
			page.locator(
				`[data-testid="user-detail-pending-group"][data-key="${SCOPE_GROUP}"][data-kind="add"]`
			)
		).toBeVisible();
		await page.getByTestId('user-detail-approve-update').click();
		await page.getByTestId('confirm-modal-confirm').click();
		await expect(page.getByTestId('toast')).toContainText('Update approved');
		await waitForToastGone(page);
		await expect(page.getByTestId('user-detail-pending-update')).toHaveCount(0);
	});

	test('rejects a pending group update from admin user detail', async ({
		browser,
		adminPage: page,
		ephemeralUser
	}) => {
		const userContext = await browser.newContext();
		const userPage = await userContext.newPage();
		await startUserSession(userPage, ephemeralUser);
		await userPage.getByTestId('dashboard-link-request-update').click();
		await expect(userPage.getByTestId('request-update-page')).toBeVisible();
		await expect(userPage.getByTestId('request-update-groups')).toBeVisible({ timeout: 15_000 });

		await stageGroupAddByName(userPage, SCOPE_GROUP);
		const submitResponse = userPage.waitForResponse(
			(res) =>
				res.url().includes('/api/users/request-update-from-admin') &&
				res.request().method() === 'POST'
		);
		await userPage.getByTestId('request-update-submit').click();
		await submitResponse;
		await expect(userPage.getByTestId('toast')).toContainText('Request submitted');
		await userPage.waitForURL(/\/dashboard/, { timeout: 10_000 });
		await userContext.close();

		await page.goto('/admin');
		await openUserDetailFromAdmin(page, ephemeralUser.email);
		await expect(page.getByTestId('user-detail-pending-update')).toBeVisible();
		await page.getByTestId('user-detail-reject-update').click();
		await page.getByTestId('confirm-modal-confirm').click();
		await expect(page.getByTestId('toast')).toContainText('Update rejected');
		await waitForToastGone(page);
		await expect(page.getByTestId('user-detail-pending-update')).toHaveCount(0);
	});

	test('approve update confirmation cancel keeps pending request visible', async ({
		browser,
		adminPage: page,
		ephemeralUser
	}) => {
		const userContext = await browser.newContext();
		const userPage = await userContext.newPage();
		await startUserSession(userPage, ephemeralUser);
		await userPage.getByTestId('dashboard-link-request-update').click();
		await expect(userPage.getByTestId('request-update-groups')).toBeVisible({ timeout: 15_000 });
		await stageGroupAddByName(userPage, SCOPE_GROUP);
		await userPage.getByTestId('request-update-submit').click();
		await expect(userPage.getByTestId('toast')).toContainText('Request submitted');
		await userContext.close();

		await page.goto('/admin');
		await openUserDetailFromAdmin(page, ephemeralUser.email);
		await expect(page.getByTestId('user-detail-pending-update')).toBeVisible();
		await page.getByTestId('user-detail-approve-update').click();
		await expect(page.getByTestId('confirm-modal-message')).toBeVisible();
		await page.getByTestId('confirm-modal-cancel').click();

		await expect(page.getByTestId('confirm-modal-message')).toHaveCount(0);
		await expect(page.getByTestId('user-detail-pending-update')).toBeVisible();
	});

	test('reject update confirmation cancel keeps pending request visible', async ({
		browser,
		adminPage: page,
		ephemeralUser
	}) => {
		const userContext = await browser.newContext();
		const userPage = await userContext.newPage();
		await startUserSession(userPage, ephemeralUser);
		await userPage.getByTestId('dashboard-link-request-update').click();
		await expect(userPage.getByTestId('request-update-groups')).toBeVisible({ timeout: 15_000 });
		await stageGroupAddByName(userPage, SCOPE_GROUP);
		await userPage.getByTestId('request-update-submit').click();
		await expect(userPage.getByTestId('toast')).toContainText('Request submitted');
		await userContext.close();

		await page.goto('/admin');
		await openUserDetailFromAdmin(page, ephemeralUser.email);
		await expect(page.getByTestId('user-detail-pending-update')).toBeVisible();
		await page.getByTestId('user-detail-reject-update').click();
		await expect(page.getByTestId('confirm-modal-message')).toBeVisible();
		await page.getByTestId('confirm-modal-cancel').click();

		await expect(page.getByTestId('confirm-modal-message')).toHaveCount(0);
		await expect(page.getByTestId('user-detail-pending-update')).toBeVisible();
	});
});
