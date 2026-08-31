import { test, expect } from '@playwright/test';

/**
 * Step 1 — Login page smoke (no API required).
 * Locators: data-testid on login surface only.
 */
test.describe('Login page', () => {
	test('shows the login form with stable locators', async ({ page }) => {
		await page.goto('/');
		await page.waitForLoadState('networkidle');

		await expect(page.getByTestId('login-page')).toBeVisible();
		await expect(page.getByTestId('login-form')).toBeVisible();
		await expect(page.getByTestId('login-email')).toBeVisible();
		await expect(page.getByTestId('login-password')).toBeVisible();
		await expect(page.getByTestId('login-submit')).toBeEnabled();
		await expect(page.getByTestId('login-mfa')).toHaveCount(0);
		await expect(page.getByTestId('login-error')).toHaveCount(0);

		await expect(page.getByTestId('login-register-link')).toHaveAttribute('href', '/register');
		await expect(page.getByTestId('login-forgot-link')).toHaveAttribute('href', '/forgot-password');
	});

	test('client-side required validation blocks empty submit', async ({ page }) => {
		await page.goto('/');
		await page.waitForLoadState('networkidle');

		await page.getByTestId('login-submit').click();

		// Native HTML5 validation — still on login page, no navigation
		await expect(page).toHaveURL('/');
		await expect(page.getByTestId('login-page')).toBeVisible();
		await expect(page.getByTestId('login-error')).toHaveCount(0);
	});
});
