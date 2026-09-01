import { test, expect } from '../../helpers/fixtures';
import { openUserDetailFromSuperuser } from '../../helpers/userApi';
import { waitForSuperuserCatalog } from '../../helpers/waits';

async function waitForToastGone(page: import('@playwright/test').Page) {
	await expect(page.getByTestId('toast')).toBeHidden({ timeout: 7000 });
}

/**
 * Grant/revoke access on an ephemeral user (never mutates seed admin).
 */
test.describe('User access mutate and revert', () => {
	test('grants a permission then revokes it', async ({
		superuserPage: page,
		suRequest,
		ephemeralUser,
		uniqueSuffix
	}) => {
		const permissionName = `e2e_access_${uniqueSuffix}`;

		try {
			await page.goto('/superuser');
			await page.getByTestId('superuser-tab-permissions').click();
			await waitForSuperuserCatalog(page);
			await page.getByTestId('superuser-catalog-create').click();
			await page.getByTestId('superuser-catalog-item-name').fill(permissionName);
			await page.getByTestId('superuser-catalog-item-definition').fill('E2E access grant fixture');
			await page.getByTestId('superuser-catalog-item-save').click();
			await expect(page.getByTestId('toast')).toContainText(permissionName);
			await waitForToastGone(page);

			await openUserDetailFromSuperuser(page, ephemeralUser.email);

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
			await page.goto('/superuser?tab=permissions').catch(() => undefined);
			try {
				await page.getByTestId('superuser-tab-permissions').click();
				await waitForSuperuserCatalog(page);
				await page.getByTestId('superuser-catalog-search').fill(permissionName);
				const row = page.locator(
					`[data-testid="superuser-catalog-row"][data-item-name="${permissionName}"]`
				);
				if ((await row.count()) > 0) {
					await row.getByTestId('superuser-catalog-delete').click();
					await page.getByTestId('confirm-modal-confirm').click();
				}
			} catch {
				await suRequest
					.delete(`/api/admin/permissions/${encodeURIComponent(permissionName)}`)
					.catch(() => undefined);
			}
		}
	});

	test('grants a group then revokes it', async ({
		superuserPage: page,
		suRequest,
		ephemeralUser,
		uniqueSuffix
	}) => {
		const groupName = `e2e_ugroup_${uniqueSuffix}`;

		try {
			await page.goto('/superuser');
			await page.getByTestId('superuser-tab-groups').click();
			await waitForSuperuserCatalog(page);
			await page.getByTestId('superuser-catalog-create').click();
			await page.getByTestId('superuser-catalog-item-name').fill(groupName);
			await page.getByTestId('superuser-catalog-item-definition').fill('E2E group grant fixture');
			await page.getByTestId('superuser-catalog-item-save').click();
			await expect(page.getByTestId('toast')).toContainText(groupName);
			await waitForToastGone(page);

			await openUserDetailFromSuperuser(page, ephemeralUser.email);

			const ms = page.locator('[data-testid="multiselect"][data-label="Groups"]');
			await ms.getByTestId('multiselect-input').fill(groupName);
			await ms.locator(`[data-testid="multiselect-option"][data-key="${groupName}"]`).click();
			await expect(
				ms.locator(`[data-testid="multiselect-chip"][data-key="${groupName}"]`)
			).toHaveAttribute('data-state', 'added');
			await page.getByTestId('user-detail-groups').locator('h3').click();

			await page.getByTestId('user-detail-save').click();
			await page.getByTestId('confirm-modal-confirm').click();
			await expect(page.getByTestId('toast')).toContainText('Updated');
			await waitForToastGone(page);

			await ms
				.locator(
					`[data-testid="multiselect-chip"][data-key="${groupName}"][data-state="selected"]`
				)
				.click();
			await expect(page.getByTestId('change-summary-removed')).toBeVisible();
			await page.getByTestId('user-detail-save').click();
			await page.getByTestId('confirm-modal-confirm').click();
			await expect(page.getByTestId('toast')).toContainText('Updated');
			await waitForToastGone(page);
		} finally {
			await page.goto('/superuser?tab=groups').catch(() => undefined);
			try {
				await page.getByTestId('superuser-tab-groups').click();
				await waitForSuperuserCatalog(page);
				await page.getByTestId('superuser-catalog-search').fill(groupName);
				const row = page.locator(
					`[data-testid="superuser-catalog-row"][data-item-name="${groupName}"]`
				);
				if ((await row.count()) > 0) {
					await row.getByTestId('superuser-catalog-delete').click();
					await page.getByTestId('confirm-modal-confirm').click();
				}
			} catch {
				await suRequest
					.delete(`/api/admin/groups/${encodeURIComponent(groupName)}`)
					.catch(() => undefined);
			}
		}
	});
});
