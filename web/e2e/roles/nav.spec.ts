import { test, expect } from '../helpers/fixtures';
import { e2eAdmin, e2eSuperuser } from '../helpers/auth';
import { waitForPageShell, waitForUsersList } from '../helpers/waits';

test.describe('Navigation by role', () => {
	test('admin nav shows Admin but not Superuser', async ({ adminPage: page }) => {
		await page.goto('/dashboard');
		await waitForPageShell(page, 'dashboard-page');

		await expect(page.getByTestId('nav-admin')).toBeVisible();
		await expect(page.getByTestId('nav-superuser')).toHaveCount(0);
		await expect(page.getByTestId('dashboard-link-request-update')).toBeVisible();
	});

	test('superuser nav shows Superuser but not Admin', async ({ superuserPage: page }) => {
		await page.goto('/dashboard');
		await waitForPageShell(page, 'dashboard-page');

		await expect(page.getByTestId('nav-superuser')).toBeVisible();
		await expect(page.getByTestId('nav-admin')).toHaveCount(0);
		await expect(page.getByTestId('dashboard-link-request-update')).toHaveCount(0);
	});

	test('superuser visiting admin redirects to the superuser console', async ({
		superuserPage: page
	}) => {
		await page.goto('/admin');
		await expect(page).toHaveURL(/\/superuser/);
		await waitForPageShell(page, 'superuser-page');
		await expect(page.getByTestId('superuser-users-panel')).toBeVisible();
	});

	test('regular user nav shows neither Admin nor Superuser', async ({ regularUserPage: page }) => {
		await page.goto('/dashboard');
		await waitForPageShell(page, 'dashboard-page');

		await expect(page.getByTestId('nav-dashboard')).toBeVisible();
		await expect(page.getByTestId('nav-admin')).toHaveCount(0);
		await expect(page.getByTestId('nav-superuser')).toHaveCount(0);
		await expect(page.getByTestId('dashboard-link-request-update')).toBeVisible();
	});

	test('nav brand returns to dashboard', async ({ adminPage: page }) => {
		await page.goto('/admin');
		await waitForPageShell(page, 'admin-page');
		await page.getByTestId('nav-brand').click();
		await expect(page).toHaveURL(/\/dashboard/);
		await expect(page.getByTestId('dashboard-email')).toHaveText(e2eAdmin.email);
	});

	test('superuser opens user detail from users tab', async ({ superuserPage: page }) => {
		await page.goto('/superuser');
		await waitForPageShell(page, 'superuser-page');
		await waitForUsersList(page);
		await expect(page.getByTestId('superuser-users-panel')).toBeVisible();

		const usersResponse = page.waitForResponse(
			(res) =>
				res.url().includes('/api/users') &&
				res.url().includes('q=') &&
				res.request().method() === 'GET'
		);
		await page.getByTestId('users-list-search').fill(e2eSuperuser.email);
		await usersResponse;
		const row = page.locator(
			`[data-testid="users-list-row"][data-user-email="${e2eSuperuser.email}"]`
		);
		await expect(row).toBeVisible();
		await row.getByTestId('users-list-edit').click();

		await expect(page).toHaveURL(/\/admin\/users\//);
		await expect(page.getByTestId('user-detail-email')).toHaveText(e2eSuperuser.email);
	});
});
