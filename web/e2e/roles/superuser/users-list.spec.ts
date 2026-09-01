import { test, expect } from '../../helpers/fixtures';
import {
	matchUsersListRequest,
	waitForPageShell,
	waitForUserDetail,
	waitForUsersList
} from '../../helpers/waits';

test.describe('Users list interactions', () => {
	test('search with no matches shows empty state', async ({ superuserPage: page }) => {
		await page.goto('/superuser');
		await waitForPageShell(page, 'superuser-page');
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
		await expect(page.getByTestId('users-list-row')).toHaveCount(0);
	});

	test('changing page size refetches the list', async ({ superuserPage: page }) => {
		await page.goto('/superuser');
		await waitForPageShell(page, 'superuser-page');
		await waitForUsersList(page);

		const perPage = page.getByTestId('users-list-pagination-per-page');
		await expect(perPage).toBeVisible();

		const refetch = page.waitForResponse((res) => matchUsersListRequest(res, { limit: 10 }));
		await perPage.selectOption('10');
		await refetch;

		await expect(page.getByTestId('users-list-table')).toBeVisible();
	});

	test('column sort toggles active sort button state', async ({ superuserPage: page }) => {
		await page.goto('/superuser');
		await waitForPageShell(page, 'superuser-page');
		await waitForUsersList(page);

		const emailSort = page.getByTestId('users-list-sort-email');
		await expect(emailSort).toHaveAttribute('data-sort-active', 'true');
		await expect(emailSort).toHaveAttribute('data-sort-direction', 'asc');

		const statusResponse = page.waitForResponse(
			(res) =>
				res.url().includes('/api/users') &&
				res.url().includes('sort=status') &&
				res.request().method() === 'GET'
		);
		await page.getByTestId('users-list-sort-status').click();
		await statusResponse;

		const statusSort = page.getByTestId('users-list-sort-status');
		await expect(statusSort).toHaveAttribute('data-sort-active', 'true');
		await expect(statusSort).toHaveAttribute('data-sort-direction', 'asc');
		await expect(emailSort).toHaveAttribute('data-sort-active', 'false');

		const toggleResponse = page.waitForResponse(
			(res) =>
				res.url().includes('/api/users') &&
				res.url().includes('sort=status') &&
				res.url().includes('order=desc') &&
				res.request().method() === 'GET'
		);
		await statusSort.click();
		await toggleResponse;
		await expect(statusSort).toHaveAttribute('data-sort-direction', 'desc');
		await expect(page.getByTestId('users-list-sort-indicator')).toBeVisible();
	});

	test('pagination controls expose stable test ids', async ({ superuserPage: page }) => {
		await page.goto('/superuser');
		await waitForPageShell(page, 'superuser-page');
		await waitForUsersList(page);

		await expect(page.getByTestId('users-list-pagination')).toBeVisible();
		await expect(page.getByTestId('users-list-pagination-summary')).toBeVisible();
		await expect(page.getByTestId('users-list-pagination-per-page')).toBeVisible();

		const pageTwo = page.locator('[data-testid="users-list-pagination-page"][data-page="2"]');
		if (await pageTwo.isVisible()) {
			const pageTwoResponse = page.waitForResponse((res) =>
				matchUsersListRequest(res, { page: 2 })
			);
			await pageTwo.click();
			await pageTwoResponse;
			await expect(pageTwo).toHaveAttribute('aria-current', 'page');
		}
	});

	test('mobile viewport shows card list instead of table', async ({
		superuserPage: page,
		ephemeralUser
	}) => {
		await page.setViewportSize({ width: 375, height: 667 });
		await page.goto('/superuser');
		await waitForPageShell(page, 'superuser-page');
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
