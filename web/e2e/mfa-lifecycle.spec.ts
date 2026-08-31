import { test, expect } from './helpers/fixtures';
import { loginAs } from './helpers/auth';
import { totpCode } from './helpers/totp';

/**
 * Full MFA lifecycle on an ephemeral user (never touch seed admin MFA).
 */
test.describe('MFA enable disable', () => {
	test('enables MFA, signs in with TOTP, then disables', async ({ browser, ephemeralUser }) => {
		const context = await browser.newContext();
		const page = await context.newPage();
		await loginAs(page, ephemeralUser);

		await page.getByTestId('dashboard-link-mfa').click();
		await expect(page.getByTestId('mfa-page')).toHaveAttribute('data-step', 'choice');

		const setupResponse = page.waitForResponse(
			(res) =>
				res.url().includes('/api/users/mfa/setup') && res.request().method() === 'POST'
		);
		await page.getByTestId('mfa-setup').click();
		await setupResponse;
		await expect(page.getByTestId('mfa-page')).toHaveAttribute('data-step', 'verify');

		const secret = (await page.getByTestId('mfa-secret').innerText()).trim();
		expect(secret.length).toBeGreaterThan(10);

		const verifyCode = totpCode(secret);
		await page.getByTestId('mfa-code').fill(verifyCode);
		const verifyResponse = page.waitForResponse(
			(res) =>
				res.url().includes('/api/users/mfa/verify') && res.request().method() === 'POST'
		);
		await page.getByTestId('mfa-verify-submit').click();
		const verifyRes = await verifyResponse;
		expect(verifyRes.ok()).toBeTruthy();
		await expect(page.getByTestId('mfa-success')).toContainText('MFA enabled');
		await expect(page.getByTestId('dashboard-page')).toBeVisible({ timeout: 15_000 });

		await page.getByTestId('nav-logout').click();
		await expect(page.getByTestId('login-page')).toBeVisible();

		await loginAs(page, {
			email: ephemeralUser.email,
			password: ephemeralUser.password,
			mfaCode: totpCode(secret)
		});
		await expect(page.getByTestId('dashboard-mfa')).toContainText(/Set up/i);

		await page.getByTestId('dashboard-link-mfa').click();
		await expect(page.getByTestId('mfa-status')).toContainText('enabled');
		await page.getByTestId('mfa-disable-start').click();
		await expect(page.getByTestId('mfa-page')).toHaveAttribute('data-step', 'disable');

		await page.getByTestId('mfa-code').fill(totpCode(secret));
		await page.getByTestId('mfa-disable-submit').click();
		await expect(page.getByTestId('confirm-modal-message')).toBeVisible();
		const disableResponse = page.waitForResponse(
			(res) =>
				res.url().includes('/api/users/mfa/disable') &&
				res.request().method() === 'POST'
		);
		await page.getByTestId('confirm-modal-confirm').click();
		const disableRes = await disableResponse;
		expect(disableRes.ok()).toBeTruthy();
		await expect(page.getByTestId('mfa-success')).toContainText('MFA disabled');
		await expect(page.getByTestId('dashboard-page')).toBeVisible({ timeout: 15_000 });

		await context.close();
	});
});
