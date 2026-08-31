import { test, expect } from '@playwright/test';
import { e2eAdmin, loginAs, openLogin } from './helpers/auth';

/**
 * Step 2 — API-backed auth (requires garde API on :8443; Vite proxies /api).
 */
test.describe('Login against API', () => {
	test('shows an error for invalid credentials', async ({ page }) => {
		await openLogin(page);
		await page.getByTestId('login-email').fill('nobody@example.com');
		await page.getByTestId('login-password').fill('WrongPassword123!');

		const loginResponse = page.waitForResponse(
			(res) => res.url().includes('/api/login') && res.request().method() === 'POST'
		);
		await page.getByTestId('login-submit').click();
		await loginResponse;

		await expect(page.getByTestId('login-error')).toBeVisible();
		await expect(page).toHaveURL('/');
		await expect(page.getByTestId('login-page')).toBeVisible();
	});

	test('signs in as admin and lands on dashboard', async ({ page }) => {
		await loginAs(page, e2eAdmin);

		await expect(page.getByTestId('app-nav')).toBeVisible();
		await expect(page.getByTestId('nav-logout')).toBeVisible();
		await expect(page.getByTestId('nav-admin')).toBeVisible();
		await expect(page.getByTestId('nav-superuser')).toHaveCount(0);
		await expect(page.getByTestId('dashboard-email')).toHaveText(e2eAdmin.email);
		await expect(page.getByTestId('dashboard-link-mfa')).toBeVisible();
		await expect(page.getByTestId('dashboard-link-password')).toBeVisible();
	});

	test('logs out back to the login page', async ({ page }) => {
		await loginAs(page, e2eAdmin);
		await page.getByTestId('nav-logout').click();

		await expect(page).toHaveURL('/');
		await expect(page.getByTestId('login-page')).toBeVisible();
		await expect(page.getByTestId('app-nav')).toHaveCount(0);
	});
});
