import { test, expect } from './helpers/fixtures';
import { waitForAdminCatalog, waitForPageShell } from './helpers/waits';

/**
 * Admin permissions / groups catalog tabs (read-only against seed admin).
 */
test.describe('Admin catalog tabs', () => {
	test.beforeEach(async ({ adminPage: page }) => {
		await page.goto('/admin');
		await waitForPageShell(page, 'admin-page');
	});

	test('switches to Permissions and shows the catalog', async ({ adminPage: page }) => {
		await page.getByTestId('admin-tab-permissions').click();

		await expect(page.getByTestId('admin-tab-permissions')).toHaveAttribute('aria-selected', 'true');
		await expect(page.getByTestId('admin-tab-users')).toHaveAttribute('aria-selected', 'false');
		await expect(page.getByTestId('users-list')).toHaveCount(0);

		const catalog = page.getByTestId('admin-catalog');
		await expect(catalog).toBeVisible();
		await expect(catalog).toHaveAttribute('data-mode', 'permissions');
		await expect(page.getByTestId('admin-catalog-title')).toHaveText('Permissions');
		await waitForAdminCatalog(page);
		await expect(page.getByTestId('admin-catalog-search')).toBeVisible();
	});

	test('switches to Groups and shows the catalog', async ({ adminPage: page }) => {
		await page.getByTestId('admin-tab-groups').click();

		await expect(page.getByTestId('admin-tab-groups')).toHaveAttribute('aria-selected', 'true');
		const catalog = page.getByTestId('admin-catalog');
		await expect(catalog).toBeVisible();
		await expect(catalog).toHaveAttribute('data-mode', 'groups');
		await expect(page.getByTestId('admin-catalog-title')).toHaveText('Groups');
		await waitForAdminCatalog(page);
	});
});
