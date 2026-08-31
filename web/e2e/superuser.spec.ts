import { test, expect } from './helpers/fixtures';

test.describe('Superuser console', () => {
	test('opens Superuser from nav and shows users by default', async ({ superuserPage: page }) => {
		await page.goto('/dashboard');
		await page.getByTestId('nav-superuser').click();
		await expect(page).toHaveURL(/\/superuser/);
		await expect(page.getByTestId('superuser-page')).toBeVisible();
		await expect(page.getByTestId('superuser-tab-users')).toHaveAttribute('aria-selected', 'true');
		await expect(page.getByTestId('users-list')).toBeVisible();
	});

	test('switches through catalog and management tabs', async ({ superuserPage: page }) => {
		await page.goto('/superuser');
		await page.getByTestId('superuser-tab-permissions').click();
		await expect(page.getByTestId('superuser-catalog')).toHaveAttribute('data-mode', 'permissions');

		await page.getByTestId('superuser-tab-groups').click();
		await expect(page.getByTestId('superuser-catalog')).toHaveAttribute('data-mode', 'groups');

		await page.getByTestId('superuser-tab-visibility').click();
		await expect(page.getByTestId('superuser-visibility-panel')).toBeVisible();

		await page.getByTestId('superuser-tab-admin-management').click();
		await expect(page.getByTestId('superuser-admin-management-panel')).toBeVisible();
	});
});
