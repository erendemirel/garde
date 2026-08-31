import { test, expect } from '@playwright/test';

/**
 * Step 11 — Register + forgot-password public page smoke (UI + light client checks).
 */
test.describe('Register page', () => {
	test('shows the register form with stable locators', async ({ page }) => {
		await page.goto('/register');
		await page.waitForLoadState('networkidle');

		await expect(page.getByTestId('register-page')).toBeVisible();
		await expect(page.getByTestId('register-form')).toBeVisible();
		await expect(page.getByTestId('register-email')).toBeVisible();
		await expect(page.getByTestId('register-password')).toBeVisible();
		await expect(page.getByTestId('register-confirm')).toBeVisible();
		await expect(page.getByTestId('register-submit')).toBeEnabled();
		await expect(page.getByTestId('register-error')).toHaveCount(0);
		await expect(page.getByTestId('register-login-link')).toHaveAttribute('href', '/');
	});

	test('reachable from the login page', async ({ page }) => {
		await page.goto('/');
		await page.waitForLoadState('networkidle');
		await page.getByTestId('login-register-link').click();
		await expect(page).toHaveURL(/\/register/);
		await expect(page.getByTestId('register-page')).toBeVisible();
	});

	test('client-side mismatch shows an error without calling the API', async ({ page }) => {
		await page.goto('/register');
		await page.waitForLoadState('networkidle');

		await page.getByTestId('register-email').fill('e2e.register@example.com');
		await page.getByTestId('register-password').fill('DevAdminTest123!');
		await page.getByTestId('register-confirm').fill('DifferentPass123!');

		await page.getByTestId('register-submit').click();

		await expect(page.getByTestId('register-error')).toHaveText('Passwords do not match');
		await expect(page).toHaveURL(/\/register/);
		await expect(page.getByTestId('register-form')).toBeVisible();
	});
});

test.describe('Forgot password page', () => {
	test('shows the email step with stable locators', async ({ page }) => {
		await page.goto('/forgot-password');
		await page.waitForLoadState('networkidle');

		await expect(page.getByTestId('forgot-password-page')).toBeVisible();
		await expect(page.getByTestId('forgot-password-page')).toHaveAttribute('data-step', 'email');
		await expect(page.getByTestId('forgot-email-form')).toBeVisible();
		await expect(page.getByTestId('forgot-email')).toBeVisible();
		await expect(page.getByTestId('forgot-send-otp')).toBeEnabled();
		await expect(page.getByTestId('forgot-login-link')).toHaveAttribute('href', '/');
	});

	test('reachable from the login page', async ({ page }) => {
		await page.goto('/');
		await page.waitForLoadState('networkidle');
		await page.getByTestId('login-forgot-link').click();
		await expect(page).toHaveURL(/\/forgot-password/);
		await expect(page.getByTestId('forgot-password-page')).toBeVisible();
	});

	test('requesting OTP advances to the reset step', async ({ page }) => {
		// Local env often has no mailer; stub the OTP endpoint so this stays a UI smoke test.
		await page.route('**/api/users/password/otp', async (route) => {
			await route.fulfill({
				status: 200,
				contentType: 'application/json',
				body: JSON.stringify({
					data: { message: 'If the email exists, an OTP has been sent' }
				})
			});
		});

		await page.goto('/forgot-password');
		await page.waitForLoadState('networkidle');

		await page.getByTestId('forgot-email').fill('test.admin@test.com');
		await page.getByTestId('forgot-send-otp').click();

		await expect(page.getByTestId('forgot-password-page')).toHaveAttribute('data-step', 'reset');
		await expect(page.getByTestId('forgot-reset-form')).toBeVisible();
		await expect(page.getByTestId('forgot-otp')).toBeVisible();
		await expect(page.getByTestId('forgot-password')).toBeVisible();
		await expect(page.getByTestId('forgot-confirm')).toBeVisible();
		await expect(page.getByTestId('forgot-success')).toContainText('OTP');
	});

	test('reset step client-side mismatch shows an error', async ({ page }) => {
		await page.route('**/api/users/password/otp', async (route) => {
			await route.fulfill({
				status: 200,
				contentType: 'application/json',
				body: JSON.stringify({
					data: { message: 'If the email exists, an OTP has been sent' }
				})
			});
		});

		await page.goto('/forgot-password');
		await page.waitForLoadState('networkidle');
		await page.getByTestId('forgot-email').fill('test.admin@test.com');
		await page.getByTestId('forgot-send-otp').click();
		await expect(page.getByTestId('forgot-reset-form')).toBeVisible();

		await page.getByTestId('forgot-otp').fill('ABCD1234');
		await page.getByTestId('forgot-password').fill('NewPassword123!');
		await page.getByTestId('forgot-confirm').fill('MismatchPass123!');
		await page.getByTestId('forgot-reset-submit').click();

		await expect(page.getByTestId('forgot-error')).toHaveText('Passwords do not match');
		await expect(page.getByTestId('forgot-password-page')).toHaveAttribute('data-step', 'reset');
	});
});
