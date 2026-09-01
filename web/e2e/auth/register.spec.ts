import { test, expect } from '../helpers/fixtures';
import { openLogin, openRegister } from '../helpers/auth';
import { deleteUserByEmail } from '../helpers/userApi';
import { describeTags, TAG } from '../helpers/tags';

test.describe('Register page', describeTags(TAG.auth, TAG.registration, TAG.focused), () => {
	test.describe('happy path', () => {
		test('shows the register form with stable locators', async ({ page }) => {
			await openRegister(page);

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
			await openLogin(page);
			await page.getByTestId('login-register-link').click();
			await expect(page).toHaveURL(/\/register/);
			await expect(page.getByTestId('register-page')).toBeVisible();
		});

		test('successful registration shows success panel', async ({ page, uniqueSuffix, suRequest }) => {
			const email = `e2e.register.${uniqueSuffix}@example.com`;
			const password = 'DevAdminTest123!';

			await openRegister(page);
			await page.getByTestId('register-email').fill(email);
			await page.getByTestId('register-password').fill(password);
			await page.getByTestId('register-confirm').fill(password);

			const registerResponse = page.waitForResponse(
				(res) => res.url().includes('/api/users') && res.request().method() === 'POST'
			);
			await page.getByTestId('register-submit').click();
			const res = await registerResponse;
			expect(res.ok()).toBeTruthy();

			await expect(page.getByTestId('register-success-panel')).toBeVisible();
			await expect(page.getByTestId('register-success')).toContainText('admin approval');
			await expect(page.getByTestId('register-form')).toHaveCount(0);

			await deleteUserByEmail(suRequest, email);
		});
	});

	test.describe('validation', () => {
		test('client-side mismatch shows an error without calling the API', async ({ page }) => {
			await openRegister(page);

			await page.getByTestId('register-email').fill('e2e.register@example.com');
			await page.getByTestId('register-password').fill('DevAdminTest123!');
			await page.getByTestId('register-confirm').fill('DifferentPass123!');

			await page.getByTestId('register-submit').click();

			await expect(page.getByTestId('register-error')).toHaveText('Passwords do not match');
			await expect(page).toHaveURL(/\/register/);
			await expect(page.getByTestId('register-form')).toBeVisible();
		});
	});

	test.describe('API errors', () => {
		test('shows an error when registering an email that already exists', async ({
			page,
			ephemeralUser
		}) => {
			await openRegister(page);
			await page.getByTestId('register-email').fill(ephemeralUser.email);
			await page.getByTestId('register-password').fill('DevAdminTest123!');
			await page.getByTestId('register-confirm').fill('DevAdminTest123!');

			const registerResponse = page.waitForResponse(
				(res) => res.url().includes('/api/users') && res.request().method() === 'POST'
			);
			await page.getByTestId('register-submit').click();
			const res = await registerResponse;
			expect(res.ok()).toBeFalsy();

			await expect(page.getByTestId('register-error')).toBeVisible();
			await expect(page.getByTestId('register-form')).toBeVisible();
			await expect(page.getByTestId('register-success-panel')).toHaveCount(0);
		});
	});
});
