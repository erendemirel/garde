import { expect, type Page } from '@playwright/test';

/** Dev bootstrap accounts from README / docker compose seed. Override via env. */
export const e2eAdmin = {
	email: process.env.E2E_ADMIN_EMAIL || 'test.admin@test.com',
	password: process.env.E2E_ADMIN_PASSWORD || 'DevAdminTest123!'
};

export const e2eSuperuser = {
	email: process.env.E2E_SUPERUSER_EMAIL || 'test.superuser@test.com',
	password: process.env.E2E_SUPERUSER_PASSWORD || 'DevAdminTest123!'
};

/** Wait until the login form is interactive (Svelte handlers attached). */
export async function openLogin(page: Page) {
	await page.goto('/');
	await page.waitForLoadState('networkidle');
	await expect(page.getByTestId('login-page')).toBeVisible();
	await expect(page.getByTestId('login-submit')).toBeEnabled();
}

export async function loginAs(
	page: Page,
	creds: { email: string; password: string; mfaCode?: string },
	opts?: { expectSuccess?: boolean }
) {
	const expectSuccess = opts?.expectSuccess !== false;
	await openLogin(page);
	await page.getByTestId('login-email').fill(creds.email);
	await page.getByTestId('login-password').fill(creds.password);
	// Guard against SvelteKit hydration remount clearing inputs under load.
	await expect(page.getByTestId('login-email')).toHaveValue(creds.email);
	await expect(page.getByTestId('login-password')).toHaveValue(creds.password);

	const loginResponse = page.waitForResponse(
		(res) => res.url().includes('/api/login') && res.request().method() === 'POST'
	);
	await page.getByTestId('login-submit').click();
	await loginResponse;

	if (creds.mfaCode) {
		await expect(page.getByTestId('login-mfa')).toBeVisible();
		await page.getByTestId('login-mfa').fill(creds.mfaCode);
		const mfaLogin = page.waitForResponse(
			(res) => res.url().includes('/api/login') && res.request().method() === 'POST'
		);
		await page.getByTestId('login-submit').click();
		await mfaLogin;
	}

	if (expectSuccess) {
		await expect(page).toHaveURL(/\/dashboard/);
		await expect(page.getByTestId('dashboard-page')).toBeVisible();
	}
}

/** Attempt login and expect the UI error (e.g. pending/rejected account). */
export async function expectLoginRejected(
	page: Page,
	creds: { email: string; password: string }
) {
	await loginAs(page, creds, { expectSuccess: false });
	await expect(page.getByTestId('login-error')).toBeVisible();
}
