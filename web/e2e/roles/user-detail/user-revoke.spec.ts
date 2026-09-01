import { test, expect } from '../../helpers/fixtures';
import { describeTags, TAG } from '../../helpers/tags';
import { startUserSession } from '../../helpers/auth';
import { openUserDetailFromSuperuser } from '../../helpers/userApi';

async function waitForToastGone(page: import('@playwright/test').Page) {
	await expect(page.getByTestId('toast')).toBeHidden({ timeout: 7000 });
}

/**
 * Revoke sessions on an ephemeral user — does not kill seed admin sessions used by other workers.
 */
test.describe('Revoke user sessions', describeTags(TAG.userDetail, TAG.activeSession, TAG.focused), () => {
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
		await startUserSession(targetPage, ephemeralUser);
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

	test('revoke confirmation cancel keeps sessions active', async ({
		browser,
		superuserPage: suPage,
		ephemeralUser
	}) => {
		const targetContext = await browser.newContext();
		const targetPage = await targetContext.newPage();
		await startUserSession(targetPage, ephemeralUser);
		await expect(targetPage.getByTestId('dashboard-page')).toBeVisible();

		await suPage.goto('/superuser');
		await openUserDetailFromSuperuser(suPage, ephemeralUser.email);
		await suPage.getByTestId('user-detail-revoke-btn').click();
		await expect(suPage.getByTestId('confirm-modal-message')).toBeVisible();
		await suPage.getByTestId('confirm-modal-cancel').click();

		await expect(suPage.getByTestId('confirm-modal-message')).toHaveCount(0);
		await targetPage.goto('/dashboard');
		await expect(targetPage.getByTestId('dashboard-page')).toBeVisible();

		await targetContext.close();
	});

	test('requires MFA code before opening revoke confirmation when MFA is enabled', async ({
		superuserPage: page,
		ephemeralUser
	}) => {
		await page.route('**/api/users/me', async (route) => {
			const response = await route.fetch();
			const body = await response.json();
			if (body?.data) body.data.mfa_enabled = true;
			await route.fulfill({
				status: response.status(),
				contentType: 'application/json',
				body: JSON.stringify(body)
			});
		});

		await page.goto('/superuser');
		await openUserDetailFromSuperuser(page, ephemeralUser.email);
		await expect(page.getByTestId('user-detail-mfa-code')).toBeVisible();

		await page.getByTestId('user-detail-revoke-btn').click();
		await expect(page.getByTestId('toast')).toContainText('Enter your MFA code');
		await expect(page.getByTestId('confirm-modal-message')).toHaveCount(0);
	});
});
