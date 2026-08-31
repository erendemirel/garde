import { test, expect } from './helpers/fixtures';
import { waitForSuperuserCatalog } from './helpers/waits';

async function waitForToastGone(page: import('@playwright/test').Page) {
	await expect(page.getByTestId('toast')).toBeHidden({ timeout: 7000 });
}

test.describe('Superuser permission CRUD', () => {
	test('creates a permission then deletes it', async ({ superuserPage: page, uniqueSuffix }) => {
		const permissionName = `e2e_perm_${uniqueSuffix}`;

		await page.goto('/superuser');
		await page.getByTestId('superuser-tab-permissions').click();
		await expect(page.getByTestId('superuser-catalog')).toHaveAttribute('data-mode', 'permissions');
		await waitForSuperuserCatalog(page);

		await page.getByTestId('superuser-catalog-create').click();
		await page.getByTestId('superuser-catalog-item-name').fill(permissionName);
		await page.getByTestId('superuser-catalog-item-definition').fill('E2E temporary permission');
		await page.getByTestId('superuser-catalog-item-save').click();
		await expect(page.getByTestId('toast')).toContainText(permissionName);
		await waitForToastGone(page);

		await page.getByTestId('superuser-catalog-search').fill(permissionName);
		const row = page.locator(
			`[data-testid="superuser-catalog-row"][data-item-name="${permissionName}"]`
		);
		await expect(row).toBeVisible();

		await row.getByTestId('superuser-catalog-delete').click();
		await page.getByTestId('confirm-modal-confirm').click();
		await expect(page.getByTestId('toast')).toContainText(/Deleted permission/i);
		await expect(row).toHaveCount(0);
	});

	test('edits a permission definition', async ({ superuserPage: page, uniqueSuffix }) => {
		const permissionName = `e2e_pedit_${uniqueSuffix}`;
		const updatedDefinition = `Updated permission definition ${uniqueSuffix}`;

		await page.goto('/superuser');
		await page.getByTestId('superuser-tab-permissions').click();
		await waitForSuperuserCatalog(page);

		await page.getByTestId('superuser-catalog-create').click();
		await page.getByTestId('superuser-catalog-item-name').fill(permissionName);
		await page.getByTestId('superuser-catalog-item-definition').fill('Initial permission definition');
		await page.getByTestId('superuser-catalog-item-save').click();
		await expect(page.getByTestId('toast')).toContainText(permissionName);
		await waitForToastGone(page);

		try {
			await page.getByTestId('superuser-catalog-search').fill(permissionName);
			const row = page.locator(
				`[data-testid="superuser-catalog-row"][data-item-name="${permissionName}"]`
			);
			await expect(row).toBeVisible();

			await row.getByTestId('superuser-catalog-edit').click();
			await expect(page.getByTestId('superuser-catalog-item-modal')).toBeVisible();
			await expect(page.getByTestId('superuser-catalog-item-name')).toBeDisabled();
			await expect(page.getByTestId('superuser-catalog-item-name')).toHaveValue(permissionName);
			await expect(page.getByTestId('superuser-catalog-item-save')).toBeDisabled();

			await page.getByTestId('superuser-catalog-item-definition').fill(updatedDefinition);
			await expect(page.getByTestId('superuser-catalog-item-save')).toBeEnabled();
			await page.getByTestId('superuser-catalog-item-save').click();
			await expect(page.getByTestId('toast')).toContainText(`Updated permission "${permissionName}"`);
			await waitForToastGone(page);

			await row.getByTestId('superuser-catalog-edit').click();
			await expect(page.getByTestId('superuser-catalog-item-definition')).toHaveValue(
				updatedDefinition
			);
			await page.getByTestId('superuser-catalog-item-cancel').click();
		} finally {
			await page.getByTestId('superuser-catalog-search').fill(permissionName);
			const row = page.locator(
				`[data-testid="superuser-catalog-row"][data-item-name="${permissionName}"]`
			);
			if ((await row.count()) > 0) {
				await row.getByTestId('superuser-catalog-delete').click();
				await page.getByTestId('confirm-modal-confirm').click();
				await waitForToastGone(page).catch(() => undefined);
			}
		}
	});
});
