import { expect, type Page } from '@playwright/test';
import { totpCode } from './totp';
import { waitForPageShell } from './waits';

/** Enable MFA through the UI; returns the TOTP secret shown on the verify step. */
export async function enableMfaViaUi(page: Page): Promise<string> {
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

	await page.getByTestId('mfa-code').fill(totpCode(secret));
	const verifyResponse = page.waitForResponse(
		(res) =>
			res.url().includes('/api/users/mfa/verify') && res.request().method() === 'POST'
	);
	await page.getByTestId('mfa-verify-submit').click();
	const verifyRes = await verifyResponse;
	expect(verifyRes.ok()).toBeTruthy();
	await waitForPageShell(page, 'dashboard-page');
	return secret;
}

/** Start MFA setup and return the secret without completing verification. */
export async function startMfaSetup(page: Page): Promise<string> {
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
	return secret;
}
