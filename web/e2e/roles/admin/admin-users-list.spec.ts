import { test, expect } from '../../helpers/fixtures';
import { describeTags, TAG } from '../../helpers/tags';
import { openUserDetailFromAdmin } from '../../helpers/userApi';
import { waitForPageShell, waitForUserDetail, waitForUsersList } from '../../helpers/waits';

test.describe('Admin users list interactions', describeTags(TAG.admin, TAG.focused), () => {
	test('column sort toggles active sort button state', async ({ adminPage: page }) => {
		await page.goto('/admin');
		await waitForPageShell(page, 'admin-page');
		await waitForUsersList(page);

		const emailSort = page.getByTestId('users-list-sort-email');
		await expect(emailSort).toHaveAttribute('data-sort-active', 'true');

		const statusResponse = page.waitForResponse(
			(res) =>
				res.url().includes('/api/users') &&
				res.url().includes('sort=status') &&
				res.request().method() === 'GET'
		);
		await page.getByTestId('users-list-sort-status').click();
		await statusResponse;
		await expect(page.getByTestId('users-list-sort-status')).toHaveAttribute(
			'data-sort-active',
			'true'
		);
	});

	test('pagination controls expose stable test ids', async ({ adminPage: page }) => {
		await page.goto('/admin');
		await waitForPageShell(page, 'admin-page');
		await waitForUsersList(page);

		await expect(page.getByTestId('users-list-pagination')).toBeVisible();
		await expect(page.getByTestId('users-list-pagination-summary')).toBeVisible();
		await expect(page.getByTestId('users-list-pagination-per-page')).toBeVisible();
	});

	test('opens an in-scope user from the list', async ({ adminPage: page, ephemeralUser }) => {
		await page.goto('/admin');
		await waitForPageShell(page, 'admin-page');
		await waitForUsersList(page);

		const usersResponse = page.waitForResponse(
			(res) =>
				res.url().includes('/api/users') &&
				res.url().includes('q=') &&
				res.request().method() === 'GET'
		);
		await page.getByTestId('users-list-search').fill(ephemeralUser.email);
		await usersResponse;

		const row = page.locator(
			`[data-testid="users-list-row"][data-user-email="${ephemeralUser.email}"]`
		);
		await expect(row).toBeVisible();
		await row.getByTestId('users-list-edit').click();
		await waitForUserDetail(page);
		await expect(page.getByTestId('user-detail-email')).toHaveText(ephemeralUser.email);
		await expect(page.getByTestId('user-detail-back')).toHaveAttribute('href', '/admin');
	});

	test('search with no matches shows empty state', async ({ adminPage: page }) => {
		await page.goto('/admin');
		await waitForPageShell(page, 'admin-page');
		await waitForUsersList(page);

		const usersResponse = page.waitForResponse(
			(res) =>
				res.url().includes('/api/users') &&
				res.url().includes('q=') &&
				res.request().method() === 'GET'
		);
		await page.getByTestId('users-list-search').fill('e2e.no.such.user@example.com');
		await usersResponse;

		await expect(page.getByTestId('users-list-table').getByTestId('users-list-empty')).toBeVisible();
	});

	test('mobile viewport shows card list instead of table', async ({
		adminPage: page,
		ephemeralUser
	}) => {
		await page.setViewportSize({ width: 375, height: 667 });
		await page.goto('/admin');
		await waitForPageShell(page, 'admin-page');
		await waitForUsersList(page);

		await expect(page.getByTestId('users-list-cards')).toBeVisible();
		await expect(page.getByTestId('users-list-table-wrap')).toBeHidden();

		const usersResponse = page.waitForResponse(
			(res) =>
				res.url().includes('/api/users') &&
				res.url().includes('q=') &&
				res.request().method() === 'GET'
		);
		await page.getByTestId('users-list-search').fill(ephemeralUser.email);
		await usersResponse;

		const card = page.locator(
			`[data-testid="users-list-card"][data-user-email="${ephemeralUser.email}"]`
		);
		await expect(card).toBeVisible();
		await card.click();
		await waitForUserDetail(page);
		await expect(page.getByTestId('user-detail-email')).toHaveText(ephemeralUser.email);
	});
});

test.describe('Admin console navigation', describeTags(TAG.admin, TAG.nav, TAG.focused), () => {
	test('switches between users, permissions, and groups tabs', async ({ adminPage: page }) => {
		await page.goto('/admin');
		await waitForPageShell(page, 'admin-page');
		await waitForUsersList(page);

		await page.getByTestId('admin-tab-permissions').click();
		await expect(page.getByTestId('admin-catalog')).toHaveAttribute('data-mode', 'permissions');

		await page.getByTestId('admin-tab-groups').click();
		await expect(page.getByTestId('admin-catalog')).toHaveAttribute('data-mode', 'groups');

		await page.getByTestId('admin-tab-users').click();
		await waitForUsersList(page);
		await expect(page.getByTestId('users-list-table')).toBeVisible();
	});

	test('opens in-scope user detail from the users list', async ({ adminPage: page, ephemeralUser }) => {
		await openUserDetailFromAdmin(page, ephemeralUser.email);
		await expect(page.getByTestId('user-detail-access-form')).toBeVisible();
		await expect(page.getByTestId('user-detail-security')).toBeVisible();
	});
});
