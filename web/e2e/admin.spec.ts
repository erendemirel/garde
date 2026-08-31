import { test, expect } from './helpers/fixtures';
import { e2eAdmin } from './helpers/auth';
import { waitForUsersList } from './helpers/waits';

test.describe('Admin users list', () => {
	test('opens Admin from nav and shows the users list', async ({ adminPage: page }) => {
		await page.goto('/dashboard');
		await page.getByTestId('nav-admin').click();
		await expect(page).toHaveURL(/\/admin/);
		await expect(page.getByTestId('admin-page')).toBeVisible();
		await expect(page.getByTestId('admin-tab-users')).toHaveAttribute('aria-selected', 'true');
		await waitForUsersList(page);
		await expect(page.getByTestId('users-list-table')).toBeVisible();
		await expect(page.getByTestId('users-list-row').first()).toBeVisible();
	});

	test('search filters users by email', async ({ adminPage: page }) => {
		await page.goto('/admin');
		await waitForUsersList(page);

		const usersResponse = page.waitForResponse(
			(res) =>
				res.url().includes('/api/users') &&
				res.url().includes('q=') &&
				res.request().method() === 'GET'
		);
		await page.getByTestId('users-list-search').fill(e2eAdmin.email);
		await usersResponse;

		const row = page.locator(
			`[data-testid="users-list-row"][data-user-email="${e2eAdmin.email}"]`
		);
		await expect(row).toBeVisible();
		await expect(row.getByTestId('users-list-row-email')).toHaveText(e2eAdmin.email);
	});
});
