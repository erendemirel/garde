import { test, expect } from './helpers/fixtures';
import { e2eAdmin } from './helpers/auth';
import { waitForUsersList } from './helpers/waits';

test.describe('Admin user detail', () => {
	test.beforeEach(async ({ adminPage: page }) => {
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
		await row.getByTestId('users-list-edit').click();
	});

	test('shows the selected user details', async ({ adminPage: page }) => {
		await expect(page).toHaveURL(/\/admin\/users\/[^/]+/);
		await expect(page.getByTestId('user-detail-page')).toBeVisible();
		await expect(page.getByTestId('user-detail-email')).toHaveText(e2eAdmin.email);
		await expect(page.getByTestId('user-detail-id')).not.toBeEmpty();
		await expect(page.getByTestId('user-detail-status')).toBeVisible();
		await expect(page.getByTestId('user-detail-access-form')).toBeVisible();
		await expect(page.getByTestId('user-detail-save')).toBeDisabled();
	});

	test('back link returns to the admin users list', async ({ adminPage: page }) => {
		await expect(page.getByTestId('user-detail-page')).toBeVisible();
		await page.getByTestId('user-detail-back').click();
		await expect(page).toHaveURL(/\/admin/);
		await expect(page.getByTestId('admin-page')).toBeVisible();
		await waitForUsersList(page);
	});
});
