import { test, expect } from '../helpers/fixtures';
import { openForgotPassword, openLogin } from '../helpers/auth';
import { describeTags, TAG } from '../helpers/tags';
import { REDIRECT_TIMEOUT } from '../helpers/waits';

async function stubOtpRoute(page: import('@playwright/test').Page) {
	await page.route('**/api/users/password/otp', async (route) => {
		await route.fulfill({
			status: 200,
			contentType: 'application/json',
			body: JSON.stringify({
				data: { message: 'If the email exists, an OTP has been sent' }
			})
		});
	});
}

test.describe('Forgot password page', describeTags(TAG.auth, TAG.focused), () => {
	test.describe('happy path', () => {
		test('shows the email step with stable locators', async ({ page }) => {
			await openForgotPassword(page);

			await expect(page.getByTestId('forgot-email-form')).toBeVisible();
			await expect(page.getByTestId('forgot-email')).toBeVisible();
			await expect(page.getByTestId('forgot-login-link')).toHaveAttribute('href', '/');
		});

		test('reachable from the login page', async ({ page }) => {
			await openLogin(page);
			await page.getByTestId('login-forgot-link').click();
			await expect(page).toHaveURL(/\/forgot-password/);
			await expect(page.getByTestId('forgot-password-page')).toBeVisible();
		});

		test('requesting OTP advances to the reset step', async ({ page }) => {
			await stubOtpRoute(page);
			await openForgotPassword(page);

			await page.getByTestId('forgot-email').fill('test.admin@test.com');
			await page.getByTestId('forgot-send-otp').click();

			await expect(page.getByTestId('forgot-password-page')).toHaveAttribute('data-step', 'reset');
			await expect(page.getByTestId('forgot-reset-form')).toBeVisible();
			await expect(page.getByTestId('forgot-otp')).toBeVisible();
			await expect(page.getByTestId('forgot-password')).toBeVisible();
			await expect(page.getByTestId('forgot-confirm')).toBeVisible();
			await expect(page.getByTestId('forgot-success')).toContainText('OTP');
		});

		test('reset step back button returns to email step', async ({ page }) => {
			await stubOtpRoute(page);
			await openForgotPassword(page);
			await page.getByTestId('forgot-email').fill('test.admin@test.com');
			await page.getByTestId('forgot-send-otp').click();
			await expect(page.getByTestId('forgot-password-page')).toHaveAttribute('data-step', 'reset');
			await expect(page.getByTestId('forgot-reset-form')).toBeVisible();

			await page.getByTestId('forgot-back-to-email').click();
			await expect(page.getByTestId('forgot-password-page')).toHaveAttribute('data-step', 'email');
			await expect(page.getByTestId('forgot-email-form')).toBeVisible();
			await expect(page.getByTestId('forgot-reset-form')).toHaveCount(0);
		});

		test('successful reset shows confirmation on the reset step', async ({
			page,
			ephemeralUser
		}) => {
			await stubOtpRoute(page);
			await page.route('**/api/users/password/reset', async (route) => {
				await route.fulfill({
					status: 200,
					contentType: 'application/json',
					body: JSON.stringify({
						data: { message: 'Password reset successful' }
					})
				});
			});

			await openForgotPassword(page);
			await page.getByTestId('forgot-email').fill(ephemeralUser.email);
			await page.getByTestId('forgot-send-otp').click();
			await expect(page.getByTestId('forgot-reset-form')).toBeVisible();

			await page.getByTestId('forgot-otp').fill('ABCD1234');
			await page.getByTestId('forgot-password').fill('NewPassword123!');
			await page.getByTestId('forgot-confirm').fill('NewPassword123!');
			await page.getByTestId('forgot-reset-submit').click();

			await expect(page.getByTestId('forgot-success')).toContainText('Password reset successful');
			await expect(page.getByTestId('login-page')).toBeVisible({ timeout: REDIRECT_TIMEOUT });
		});

		test('reset step exposes MFA field for accounts with MFA enabled', async ({ page }) => {
			await stubOtpRoute(page);
			await openForgotPassword(page);
			await page.getByTestId('forgot-email').fill('test.admin@test.com');
			await page.getByTestId('forgot-send-otp').click();
			await expect(page.getByTestId('forgot-reset-form')).toBeVisible();
			await expect(page.getByTestId('forgot-mfa')).toBeVisible();
		});
	});

	test.describe('validation', () => {
		test('reset step client-side mismatch shows an error', async ({ page }) => {
			await stubOtpRoute(page);
			await openForgotPassword(page);
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

	test.describe('API errors', () => {
		test('shows an error for invalid OTP on password reset', async ({ page }) => {
			await stubOtpRoute(page);
			await page.route('**/api/users/password/reset', async (route) => {
				await route.fulfill({
					status: 400,
					contentType: 'application/json',
					body: JSON.stringify({ error: { message: 'Invalid or expired OTP' } })
				});
			});

			await openForgotPassword(page);
			await page.getByTestId('forgot-email').fill('test.admin@test.com');
			await page.getByTestId('forgot-send-otp').click();
			await expect(page.getByTestId('forgot-reset-form')).toBeVisible();

			await page.getByTestId('forgot-otp').fill('WRONGOTP');
			await page.getByTestId('forgot-password').fill('NewPassword123!');
			await page.getByTestId('forgot-confirm').fill('NewPassword123!');
			await page.getByTestId('forgot-reset-submit').click();

			await expect(page.getByTestId('forgot-error')).toBeVisible();
			await expect(page.getByTestId('forgot-password-page')).toHaveAttribute('data-step', 'reset');
		});

		test('shows an error when MFA is required but not provided', async ({
			page,
			ephemeralUser
		}) => {
			await stubOtpRoute(page);
			await page.route('**/api/users/password/reset', async (route) => {
				await route.fulfill({
					status: 400,
					contentType: 'application/json',
					body: JSON.stringify({ error: { message: 'MFA code is required' } })
				});
			});

			await openForgotPassword(page);
			await page.getByTestId('forgot-email').fill(ephemeralUser.email);
			await page.getByTestId('forgot-send-otp').click();
			await expect(page.getByTestId('forgot-reset-form')).toBeVisible();

			await page.getByTestId('forgot-otp').fill('ABCD1234');
			await page.getByTestId('forgot-password').fill('NewPassword123!');
			await page.getByTestId('forgot-confirm').fill('NewPassword123!');
			await page.getByTestId('forgot-reset-submit').click();

			await expect(page.getByTestId('forgot-error')).toContainText('MFA');
			await expect(page.getByTestId('forgot-mfa')).toBeVisible();
		});

		test('shows an error for invalid MFA code on password reset', async ({ page, ephemeralUser }) => {
			await stubOtpRoute(page);
			await page.route('**/api/users/password/reset', async (route) => {
				await route.fulfill({
					status: 400,
					contentType: 'application/json',
					body: JSON.stringify({ error: { message: 'Invalid MFA code' } })
				});
			});

			await openForgotPassword(page);
			await page.getByTestId('forgot-email').fill(ephemeralUser.email);
			await page.getByTestId('forgot-send-otp').click();
			await expect(page.getByTestId('forgot-reset-form')).toBeVisible();

			await page.getByTestId('forgot-otp').fill('ABCD1234');
			await page.getByTestId('forgot-password').fill('NewPassword123!');
			await page.getByTestId('forgot-confirm').fill('NewPassword123!');
			await page.getByTestId('forgot-mfa').fill('000000');
			await page.getByTestId('forgot-reset-submit').click();

			await expect(page.getByTestId('forgot-error')).toContainText('Invalid MFA');
		});
	});
});
