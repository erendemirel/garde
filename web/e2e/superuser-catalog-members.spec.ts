import { test, expect } from './helpers/fixtures';
import type { Page } from '@playwright/test';
import { waitForSuperuserCatalog } from './helpers/waits';

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

async function saveMembership(page: Page, saveTestId: string, toastMatch: string | RegExp) {
	await page.getByTestId(saveTestId).click();
	await expect(page.getByTestId('confirm-modal-message')).toBeVisible();
	await page.getByTestId('confirm-modal-confirm').click();
	await expect(page.getByTestId('toast')).toContainText(toastMatch);
	await waitForToastGone(page);
}

/**
 * Superuser catalog Manage Users — assign/remove membership on a temporary group.
 */
test.describe('Superuser catalog members', () => {
	test('assigns a user to a group then removes them', async ({
		superuserPage: page,
		ephemeralUser,
		uniqueSuffix,
		suRequest
	}) => {
		const groupName = `e2e_cmembers_${uniqueSuffix}`;

		try {
			await page.goto('/superuser');
			await page.getByTestId('superuser-tab-groups').click();
			await waitForSuperuserCatalog(page);
			await page.getByTestId('superuser-catalog-create').click();
			await page.getByTestId('superuser-catalog-item-name').fill(groupName);
			await page.getByTestId('superuser-catalog-item-definition').fill('E2E catalog members');
			await page.getByTestId('superuser-catalog-item-save').click();
			await expect(page.getByTestId('toast')).toContainText(groupName);
			await waitForToastGone(page);

			await page.getByTestId('superuser-catalog-search').fill(groupName);
			const row = page.locator(
				`[data-testid="superuser-catalog-row"][data-item-name="${groupName}"]`
			);
			await expect(row).toBeVisible();
			await row.getByTestId('superuser-catalog-manage').click();
			await expect(page.getByTestId('superuser-catalog-manage-modal')).toBeVisible();

			await addUserInManagePicker(page, ephemeralUser.id, ephemeralUser.email);
			await saveMembership(
				page,
				'superuser-catalog-manage-save',
				`Updated group "${groupName}" members`
			);
			await expect(page.getByTestId('superuser-catalog-manage-modal')).toHaveCount(0);

			await row.getByTestId('superuser-catalog-manage').click();
			await expect(
				page.locator(
					`[data-testid="multiselect-chip"][data-key="${ephemeralUser.id}"][data-state="selected"]`
				)
			).toBeVisible();
			await removeUserChip(page, ephemeralUser.id);
			await saveMembership(
				page,
				'superuser-catalog-manage-save',
				`Updated group "${groupName}" members`
			);
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

	test('assigns a user to a permission then removes them', async ({
		superuserPage: page,
		ephemeralUser,
		uniqueSuffix,
		suRequest
	}) => {
		const permissionName = `e2e_pmembers_${uniqueSuffix}`;

		try {
			await page.goto('/superuser');
			await page.getByTestId('superuser-tab-permissions').click();
			await waitForSuperuserCatalog(page);
			await page.getByTestId('superuser-catalog-create').click();
			await page.getByTestId('superuser-catalog-item-name').fill(permissionName);
			await page.getByTestId('superuser-catalog-item-definition').fill('E2E permission members');
			await page.getByTestId('superuser-catalog-item-save').click();
			await expect(page.getByTestId('toast')).toContainText(permissionName);
			await waitForToastGone(page);

			await page.getByTestId('superuser-catalog-search').fill(permissionName);
			const row = page.locator(
				`[data-testid="superuser-catalog-row"][data-item-name="${permissionName}"]`
			);
			await expect(row).toBeVisible();
			await row.getByTestId('superuser-catalog-manage').click();
			await expect(page.getByTestId('superuser-catalog-manage-modal')).toBeVisible();

			await addUserInManagePicker(page, ephemeralUser.id, ephemeralUser.email);
			await saveMembership(
				page,
				'superuser-catalog-manage-save',
				`Updated permission "${permissionName}" members`
			);

			await row.getByTestId('superuser-catalog-manage').click();
			await removeUserChip(page, ephemeralUser.id);
			await saveMembership(
				page,
				'superuser-catalog-manage-save',
				`Updated permission "${permissionName}" members`
			);
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
});
