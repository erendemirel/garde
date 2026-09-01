import { test, expect } from '../../helpers/fixtures';
import { describeTags, TAG } from '../../helpers/tags';
import type { Page } from '@playwright/test';
import { waitForAdminCatalog } from '../../helpers/waits';

/** Seed group the admin already belongs to; ephemeral users start in group_a only. */
const SCOPE_GROUP = 'asdfasdf';
/** Shared with seed admin + ephemeral users — used for permission visibility. */
const VISIBILITY_GROUP = 'group_a';

async function waitForToastGone(page: Page) {
	await expect(page.getByTestId('toast')).toBeHidden({ timeout: 7000 });
}

async function addUserInManagePicker(page: Page, userId: string, email: string) {
	const ms = page.locator('[data-testid="multiselect"][data-label="Users"]');
	const searchResponse = page.waitForResponse(
		(res) =>
			res.url().includes('/api/users') &&
			res.url().includes('q=') &&
			res.request().method() === 'GET'
	);
	await ms.getByTestId('multiselect-input').fill(email);
	await searchResponse;
	await ms.locator(`[data-testid="multiselect-option"][data-key="${userId}"]`).click();
	await expect(
		ms.locator(`[data-testid="multiselect-chip"][data-key="${userId}"]`)
	).toHaveAttribute('data-state', 'added');
}

async function removeUserChip(page: Page, userId: string) {
	const ms = page.locator('[data-testid="multiselect"][data-label="Users"]');
	await ms
		.locator(`[data-testid="multiselect-chip"][data-key="${userId}"][data-state="selected"]`)
		.click();
	await expect(page.getByTestId('change-summary-removed')).toBeVisible();
}

/**
 * Admin catalog Manage Users — grant/revoke within admin scope.
 * Ephemeral user shares group_a with seed admin, so they appear as manageable.
 */
test.describe('Admin catalog members', describeTags(TAG.admin, TAG.catalog, TAG.focused), () => {
	test('adds then removes a manageable user on a seed group', async ({
		adminPage: page,
		ephemeralUser
	}) => {
		await page.goto('/admin');
		await page.getByTestId('admin-tab-groups').click();
		await expect(page.getByTestId('admin-catalog')).toHaveAttribute('data-mode', 'groups');
		await waitForAdminCatalog(page);

		await page.getByTestId('admin-catalog-search').fill(SCOPE_GROUP);
		const row = page.locator(
			`[data-testid="admin-catalog-row"][data-item-name="${SCOPE_GROUP}"]`
		);
		await expect(row).toBeVisible();

		await row.getByTestId('admin-catalog-manage').click();
		await expect(page.getByTestId('admin-catalog-manage-modal')).toBeVisible();

		await addUserInManagePicker(page, ephemeralUser.id, ephemeralUser.email);
		await page.getByTestId('admin-catalog-manage-save').click();
		await expect(page.getByTestId('confirm-modal-message')).toBeVisible();
		await page.getByTestId('confirm-modal-confirm').click();
		await expect(page.getByTestId('toast')).toContainText(
			`Updated group "${SCOPE_GROUP}" members`
		);
		await waitForToastGone(page);
		await expect(page.getByTestId('admin-catalog-manage-modal')).toHaveCount(0);

		await row.getByTestId('admin-catalog-manage').click();
		await expect(
			page.locator(
				`[data-testid="multiselect-chip"][data-key="${ephemeralUser.id}"][data-state="selected"]`
			)
		).toBeVisible();
		await removeUserChip(page, ephemeralUser.id);
		await page.getByTestId('admin-catalog-manage-save').click();
		await page.getByTestId('confirm-modal-confirm').click();
		await expect(page.getByTestId('toast')).toContainText(
			`Updated group "${SCOPE_GROUP}" members`
		);
		await waitForToastGone(page);
	});

	test('grants then revokes a visibility-scoped permission on a manageable user', async ({
		adminPage: page,
		ephemeralUser,
		suRequest,
		uniqueSuffix
	}) => {
		const permissionName = `e2e_adm_perm_${uniqueSuffix}`;

		try {
			const createRes = await suRequest.post('/api/admin/permissions', {
				data: { name: permissionName, definition: 'E2E admin catalog permission' }
			});
			expect(createRes.ok()).toBeTruthy();

			const visRes = await suRequest.post('/api/admin/permissions/visibility', {
				data: { permission_name: permissionName, group_name: VISIBILITY_GROUP }
			});
			expect(visRes.ok()).toBeTruthy();

			await page.goto('/admin');
			await page.getByTestId('admin-tab-permissions').click();
			await expect(page.getByTestId('admin-catalog')).toHaveAttribute(
				'data-mode',
				'permissions'
			);
			await waitForAdminCatalog(page);

			await page.getByTestId('admin-catalog-search').fill(permissionName);
			const row = page.locator(
				`[data-testid="admin-catalog-row"][data-item-name="${permissionName}"]`
			);
			await expect(row).toBeVisible();

			await row.getByTestId('admin-catalog-manage').click();
			await expect(page.getByTestId('admin-catalog-manage-modal')).toBeVisible();

			await addUserInManagePicker(page, ephemeralUser.id, ephemeralUser.email);
			await page.getByTestId('admin-catalog-manage-save').click();
			await expect(page.getByTestId('confirm-modal-message')).toBeVisible();
			await page.getByTestId('confirm-modal-confirm').click();
			await expect(page.getByTestId('toast')).toContainText(
				`Updated permission "${permissionName}" members`
			);
			await waitForToastGone(page);

			await row.getByTestId('admin-catalog-manage').click();
			await expect(
				page.locator(
					`[data-testid="multiselect-chip"][data-key="${ephemeralUser.id}"][data-state="selected"]`
				)
			).toBeVisible();
			await removeUserChip(page, ephemeralUser.id);
			await page.getByTestId('admin-catalog-manage-save').click();
			await page.getByTestId('confirm-modal-confirm').click();
			await expect(page.getByTestId('toast')).toContainText(
				`Updated permission "${permissionName}" members`
			);
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
});
