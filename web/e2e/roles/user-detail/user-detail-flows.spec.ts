import { test, expect } from '../../helpers/fixtures';
import { describeTags, TAG } from '../../helpers/tags';
import { openUserDetailFromSuperuser } from '../../helpers/userApi';
import { waitForPageShell, waitForUserDetail } from '../../helpers/waits';

async function waitForToastGone(page: import('@playwright/test').Page) {
	await expect(page.getByTestId('toast')).toBeHidden({ timeout: 7000 });
}

test.describe('User detail edit flows', describeTags(TAG.userDetail, TAG.focused), () => {
	test('blocks navigation with unsaved changes until confirmed', async ({
		superuserPage: page,
		ephemeralUser,
		uniqueSuffix,
		suRequest
	}) => {
		const permissionName = `e2e_unsaved_${uniqueSuffix}`;

		try {
			const createPerm = await suRequest.post('/api/admin/permissions', {
				data: { name: permissionName, definition: 'E2E unsaved guard' }
			});
			expect(createPerm.ok()).toBeTruthy();

			await page.goto('/superuser');
			await waitForPageShell(page, 'superuser-page');
			await openUserDetailFromSuperuser(page, ephemeralUser.email);

			const ms = page.locator('[data-testid="multiselect"][data-label="Permissions"]');
			await ms.getByTestId('multiselect-input').fill(permissionName);
			await ms.locator(`[data-testid="multiselect-option"][data-key="${permissionName}"]`).click();
			await expect(page.getByTestId('change-summary-added')).toBeVisible();
			await expect(page.getByTestId('user-detail-save')).toBeEnabled();

			await page.getByTestId('user-detail-back').click();
			await expect(page.getByTestId('confirm-modal-message')).toContainText('unsaved');
			await page.getByTestId('confirm-modal-cancel').click();

			await expect(page.getByTestId('user-detail-page')).toBeVisible();
			await expect(page.getByTestId('change-summary-added')).toBeVisible();

			await page.getByTestId('user-detail-back').click();
			await page.getByTestId('confirm-modal-confirm').click();
			await expect(page).toHaveURL(/\/superuser/);
		} finally {
			await suRequest
				.delete(`/api/admin/permissions/${encodeURIComponent(permissionName)}`)
				.catch(() => undefined);
		}
	});

	test('reverts a staged permission via change summary without saving', async ({
		superuserPage: page,
		ephemeralUser,
		uniqueSuffix,
		suRequest
	}) => {
		const permissionName = `e2e_revert_${uniqueSuffix}`;

		try {
			const createPerm = await suRequest.post('/api/admin/permissions', {
				data: { name: permissionName, definition: 'E2E revert chip' }
			});
			expect(createPerm.ok()).toBeTruthy();

			await page.goto('/superuser');
			await openUserDetailFromSuperuser(page, ephemeralUser.email);

			const ms = page.locator('[data-testid="multiselect"][data-label="Permissions"]');
			await ms.getByTestId('multiselect-input').fill(permissionName);
			await ms.locator(`[data-testid="multiselect-option"][data-key="${permissionName}"]`).click();
			await expect(page.getByTestId('change-summary-added')).toBeVisible();

			await page
				.locator('[data-testid="change-summary-item"][data-kind="add"]')
				.first()
				.click();
			await expect(page.getByTestId('change-summary-empty')).toBeVisible();
			await expect(page.getByTestId('user-detail-save')).toBeDisabled();
		} finally {
			await suRequest
				.delete(`/api/admin/permissions/${encodeURIComponent(permissionName)}`)
				.catch(() => undefined);
		}
	});

	test('cancels save confirmation without applying changes', async ({
		superuserPage: page,
		ephemeralUser,
		uniqueSuffix,
		suRequest
	}) => {
		const permissionName = `e2e_cancel_${uniqueSuffix}`;

		try {
			const createPerm = await suRequest.post('/api/admin/permissions', {
				data: { name: permissionName, definition: 'E2E cancel save' }
			});
			expect(createPerm.ok()).toBeTruthy();

			await page.goto('/superuser');
			await openUserDetailFromSuperuser(page, ephemeralUser.email);

			const ms = page.locator('[data-testid="multiselect"][data-label="Permissions"]');
			await ms.getByTestId('multiselect-input').fill(permissionName);
			await ms.locator(`[data-testid="multiselect-option"][data-key="${permissionName}"]`).click();

			await page.getByTestId('user-detail-save').click();
			await expect(page.getByTestId('confirm-modal-message')).toContainText(permissionName);
			await page.getByTestId('confirm-modal-cancel').click();

			await expect(page.getByTestId('user-detail-page')).toBeVisible();
			await expect(page.getByTestId('change-summary-added')).toBeVisible();
			await expect(page.getByTestId('user-detail-save')).toBeEnabled();
		} finally {
			await suRequest
				.delete(`/api/admin/permissions/${encodeURIComponent(permissionName)}`)
				.catch(() => undefined);
		}
	});

	test('superuser saves access changes from user detail', async ({
		superuserPage: page,
		ephemeralUser,
		uniqueSuffix,
		suRequest
	}) => {
		const permissionName = `e2e_save_${uniqueSuffix}`;

		try {
			const createPerm = await suRequest.post('/api/admin/permissions', {
				data: { name: permissionName, definition: 'E2E save access' }
			});
			expect(createPerm.ok()).toBeTruthy();

			await page.goto('/superuser');
			await openUserDetailFromSuperuser(page, ephemeralUser.email);

			const ms = page.locator('[data-testid="multiselect"][data-label="Permissions"]');
			await ms.getByTestId('multiselect-input').fill(permissionName);
			await ms.locator(`[data-testid="multiselect-option"][data-key="${permissionName}"]`).click();

			await page.getByTestId('user-detail-save').click();
			await page.getByTestId('confirm-modal-confirm').click();
			await expect(page.getByTestId('toast')).toContainText('Updated');
			await waitForToastGone(page);
			await waitForUserDetail(page);
			await expect(page.getByTestId('user-detail-save')).toBeDisabled();
			await expect(
				ms.locator(
					`[data-testid="multiselect-chip"][data-key="${permissionName}"][data-state="selected"]`
				)
			).toBeVisible();
		} finally {
			await suRequest
				.delete(`/api/admin/permissions/${encodeURIComponent(permissionName)}`)
				.catch(() => undefined);
		}
	});

	test('shows an error toast when save fails on the server', async ({
		superuserPage: page,
		ephemeralUser,
		uniqueSuffix,
		suRequest
	}) => {
		const permissionName = `e2e_save_err_${uniqueSuffix}`;

		try {
			const createPerm = await suRequest.post('/api/admin/permissions', {
				data: { name: permissionName, definition: 'E2E save error' }
			});
			expect(createPerm.ok()).toBeTruthy();

			await page.goto('/superuser');
			await openUserDetailFromSuperuser(page, ephemeralUser.email);

			const ms = page.locator('[data-testid="multiselect"][data-label="Permissions"]');
			await ms.getByTestId('multiselect-input').fill(permissionName);
			await ms.locator(`[data-testid="multiselect-option"][data-key="${permissionName}"]`).click();

			await page.route(`**/api/users/${ephemeralUser.id}`, async (route) => {
				if (route.request().method() === 'PUT') {
					await route.fulfill({
						status: 500,
						contentType: 'application/json',
						body: JSON.stringify({ error: { message: 'Server error saving user' } })
					});
					return;
				}
				await route.continue();
			});

			await page.getByTestId('user-detail-save').click();
			await page.getByTestId('confirm-modal-confirm').click();
			await expect(page.getByTestId('toast')).toContainText(/error|failed/i);
			await expect(page.getByTestId('user-detail-page')).toBeVisible();
			await expect(page.getByTestId('user-detail-save')).toBeEnabled();
		} finally {
			await suRequest
				.delete(`/api/admin/permissions/${encodeURIComponent(permissionName)}`)
				.catch(() => undefined);
		}
	});
});
