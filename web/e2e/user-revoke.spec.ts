import { test, expect } from './helpers/fixtures';
import { loginAs } from './helpers/auth';
import { openUserDetailFromSuperuser } from './helpers/userApi';

async function waitForToastGone(page: import('@playwright/test').Page) {
	await expect(page.getByTestId('toast')).toBeHidden({ timeout: 7000 });
}

/**
 * Revoke sessions on an ephemeral user — does not kill seed admin sessions used by other workers.
 */
test.describe('Revoke user sessions', () => {
	test('shows revoke and delete controls on user detail', async ({
		superuserPage: page,
		ephemeralUser
	}) => {
		await page.goto('/superuser');
		await openUserDetailFromSuperuser(page, ephemeralUser.email);
		await expect(page.getByTestId('user-detail-revoke-btn')).toBeEnabled();
		await expect(page.getByTestId('user-detail-delete-btn')).toBeEnabled();
	});

	test('revoking sessions signs the target user out', async ({
		browser,
		superuserPage: suPage,
		ephemeralUser
	}) => {
		const targetContext = await browser.newContext();
		const targetPage = await targetContext.newPage();
		await loginAs(targetPage, ephemeralUser);
		await expect(targetPage.getByTestId('dashboard-page')).toBeVisible();

		await suPage.goto('/superuser');
		await openUserDetailFromSuperuser(suPage, ephemeralUser.email);
		await suPage.getByTestId('user-detail-revoke-btn').click();
		await expect(suPage.getByTestId('confirm-modal-message')).toBeVisible();
		await suPage.getByTestId('confirm-modal-confirm').click();
		await expect(suPage.getByTestId('toast')).toContainText('Sessions revoked');
		await waitForToastGone(suPage);

		await expect(suPage.getByTestId('user-detail-page')).toBeVisible();

		await targetPage.goto('/dashboard');
		await expect(targetPage.getByTestId('login-page')).toBeVisible({ timeout: 15_000 });
		await expect(targetPage.getByTestId('app-nav')).toHaveCount(0);

		await targetContext.close();
	});
});
