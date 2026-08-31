import { test, expect } from './helpers/fixtures';
import { expectLoginRejected, loginAs } from './helpers/auth';

/**
 * Full password change on an ephemeral user (never touch seed admin password).
 */
test.describe('Change password success', () => {
	test('changes password, logs out, and signs in with the new password', async ({
		browser,
		ephemeralUser
	}) => {
		const newPassword = 'DevAdminTest456!';
		const context = await browser.newContext();
		const page = await context.newPage();

		await loginAs(page, ephemeralUser);
		await page.getByTestId('dashboard-link-password').click();
		await expect(page.getByTestId('password-page')).toBeVisible();

		await page.getByTestId('password-current').fill(ephemeralUser.password);
		await page.getByTestId('password-new').fill(newPassword);
		await page.getByTestId('password-confirm').fill(newPassword);
		await expect(page.getByTestId('password-current')).toHaveValue(ephemeralUser.password);
		await expect(page.getByTestId('password-new')).toHaveValue(newPassword);

		await page.getByTestId('password-submit').click();
		await expect(page.getByTestId('confirm-modal-message')).toBeVisible();

		const changeResponse = page.waitForResponse(
			(res) =>
				res.url().includes('/api/users/password/change') &&
				res.request().method() === 'POST'
		);
		await page.getByTestId('confirm-modal-confirm').click();
		const res = await changeResponse;
		expect(res.ok()).toBeTruthy();

		await expect(page.getByTestId('password-success')).toContainText('Password changed');
		await expect(page.getByTestId('login-page')).toBeVisible({ timeout: 15_000 });

		await loginAs(page, { email: ephemeralUser.email, password: newPassword });
		await expect(page.getByTestId('dashboard-email')).toHaveText(ephemeralUser.email);

		await context.close();
	});
});
