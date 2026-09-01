import { test, expect } from '../../helpers/fixtures';
import { describeTags, TAG } from '../../helpers/tags';
import { startUserSession } from '../../helpers/auth';
import { openUserDetailFromAdmin } from '../../helpers/userApi';
import {
	openRequestUpdate,
	stageGroupAddByName,
	submitRequestUpdate,
	waitForToastGone,
	VISIBILITY_GROUP,
	SCOPE_GROUP
} from '../../helpers/journeys';

/** Seed group shared by admin and manageable users — safe for admin approve of group add. */

async function submitGroupAddRequest(page: import('@playwright/test').Page, groupName: string) {
	await openRequestUpdate(page, { requireGroups: true });
	await stageGroupAddByName(page, groupName);
	await submitRequestUpdate(page);
}

/**
 * Admin user detail writes — scoped to shared groups + visibility rules.
 */
test.describe('Admin user detail edits', describeTags(TAG.admin, TAG.userDetail, TAG.focused), () => {
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
		await submitGroupAddRequest(userPage, SCOPE_GROUP);
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
		await submitGroupAddRequest(userPage, SCOPE_GROUP);
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
		await submitGroupAddRequest(userPage, SCOPE_GROUP);
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
		await submitGroupAddRequest(userPage, SCOPE_GROUP);
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
