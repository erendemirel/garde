import { test, expect } from '../../helpers/fixtures';
import { openUserDetailFromSuperuser } from '../../helpers/userApi';
import { waitForUsersList } from '../../helpers/waits';

async function waitForToastGone(page: import('@playwright/test').Page) {
	await expect(page.getByTestId('toast')).toBeHidden({ timeout: 7000 });
}

/**
 * Delete ephemeral user from the UI (fixture cleanup is a no-op after delete).
 */
test.describe('Delete user', () => {
	test('deletes an ephemeral user from user detail', async ({
		superuserPage: page,
		ephemeralUser
	}) => {
		await page.goto('/superuser');
		await openUserDetailFromSuperuser(page, ephemeralUser.email);

		await page.getByTestId('user-detail-delete-btn').click();
		await expect(page.getByTestId('confirm-modal-message')).toBeVisible();
		await page.getByTestId('confirm-modal-confirm').click();
		await expect(page.getByTestId('toast')).toContainText('User deleted');
		await waitForToastGone(page);

		await expect(page).toHaveURL(/\/superuser/, { timeout: 10_000 });
		await waitForUsersList(page);

		const usersResponse = page.waitForResponse(
			(res) =>
				res.url().includes('/api/users') &&
				res.url().includes('q=') &&
				res.request().method() === 'GET'
		);
		await page.getByTestId('users-list-search').fill(ephemeralUser.email);
		await usersResponse;
		await expect(
			page.locator(`[data-testid="users-list-row"][data-user-email="${ephemeralUser.email}"]`)
		).toHaveCount(0);
	});

	test('delete confirmation cancel keeps the user', async ({
		superuserPage: page,
		ephemeralUser
	}) => {
		await page.goto('/superuser');
		await openUserDetailFromSuperuser(page, ephemeralUser.email);

		await page.getByTestId('user-detail-delete-btn').click();
		await expect(page.getByTestId('confirm-modal-message')).toBeVisible();
		await page.getByTestId('confirm-modal-cancel').click();

		await expect(page.getByTestId('confirm-modal-message')).toHaveCount(0);
		await expect(page.getByTestId('user-detail-email')).toHaveText(ephemeralUser.email);
	});
});
