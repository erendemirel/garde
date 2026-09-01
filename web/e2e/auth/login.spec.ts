import { test, expect } from '../helpers/fixtures';
import { e2eAdmin, expectLoginRejected, fillLoginForm, loginAs, openLogin, submitLogin } from '../helpers/auth';
import { describeTags, TAG } from '../helpers/tags';
import { LOAD_TIMEOUT } from '../helpers/waits';
import { enableMfaViaUi } from '../helpers/mfa';
import {
	createEphemeralUser,
	deleteUserById,
	openUserDetailFromAdmin,
	patchUserMaps
} from '../helpers/userApi';

test.describe('Login page', describeTags(TAG.auth, TAG.focused), () => {
	test.describe('UI', () => {
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
			await openLogin(page);
			await page.getByTestId('login-submit').click();

			await expect(page).toHaveURL('/');
			await expect(page.getByTestId('login-page')).toBeVisible();
			await expect(page.getByTestId('login-error')).toHaveCount(0);
		});
	});

	test.describe('API', () => {
		test('shows an error for invalid credentials', async ({ page }) => {
			await loginAs(
				page,
				{ email: 'nobody@example.com', password: 'WrongPassword123!' },
				{ expectSuccess: false }
			);

			await expect(page.getByTestId('login-error')).toBeVisible({ timeout: LOAD_TIMEOUT });
			await expect(page.getByTestId('login-error')).toContainText(/authentication failed|invalid credentials/i);
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

	test.describe('MFA', () => {
		test('shows MFA input after password when MFA is enabled', async ({
			browser,
			ephemeralUser
		}) => {
			const context = await browser.newContext();
			const page = await context.newPage();
			await loginAs(page, ephemeralUser);
			await enableMfaViaUi(page);

			await page.getByTestId('nav-logout').click();
			await expect(page.getByTestId('login-page')).toBeVisible();

			await openLogin(page);
			await submitLogin(page, {
				email: ephemeralUser.email,
				password: ephemeralUser.password
			});

			await expect(page.getByTestId('login-mfa')).toBeVisible();
			await expect(page.getByTestId('login-page')).toBeVisible();
			await expect(page.getByTestId('dashboard-page')).toHaveCount(0);

			await context.close();
		});

		test('shows an error for invalid MFA code after password step', async ({
			browser,
			ephemeralUser
		}) => {
			const context = await browser.newContext();
			const page = await context.newPage();
			await loginAs(page, ephemeralUser);
			await enableMfaViaUi(page);
			await page.getByTestId('nav-logout').click();
			await expect(page.getByTestId('login-page')).toBeVisible();

			await openLogin(page);
			await submitLogin(page, {
				email: ephemeralUser.email,
				password: ephemeralUser.password
			});
			await expect(page.getByTestId('login-mfa')).toBeVisible();

			await page.getByTestId('login-mfa').fill('000000');
			const mfaLogin = page.waitForResponse(
				(res) => res.url().includes('/api/login') && res.request().method() === 'POST',
				{ timeout: LOAD_TIMEOUT }
			);
			await page.getByTestId('login-submit').click();
			const mfaRes = await mfaLogin;
			expect(mfaRes.ok()).toBeFalsy();

			await expect(page.getByTestId('login-error')).toBeVisible();
			await expect(page.getByTestId('login-page')).toBeVisible();
			await expect(page.getByTestId('dashboard-page')).toHaveCount(0);

			await context.close();
		});
	});

	test.describe('blocked accounts', () => {
		const restrictedMessage = /access temporarily restricted/i;

		test('pending approval account shows restricted login error', async ({
			page,
			suRequest,
			uniqueSuffix
		}) => {
			const user = await createEphemeralUser(suRequest, `login_pending_${uniqueSuffix}`, {
				approve: false,
				groups: ['group_a']
			});
			try {
				await expectLoginRejected(page, user, { message: restrictedMessage });
			} finally {
				await deleteUserById(suRequest, user.id).catch(() => undefined);
			}
		});

		test('rejected approval account shows restricted login error', async ({
			page,
			adminPage,
			suRequest,
			uniqueSuffix
		}) => {
			const user = await createEphemeralUser(suRequest, `login_rejected_${uniqueSuffix}`, {
				approve: false,
				groups: ['group_a']
			});
			try {
				await adminPage.goto('/admin');
				await openUserDetailFromAdmin(adminPage, user.email);
				await adminPage.getByTestId('user-detail-reject-account').click();
				await adminPage.getByTestId('confirm-modal-confirm').click();
				await expect(adminPage.getByTestId('toast')).toContainText('rejected');

				await expectLoginRejected(page, user, { message: restrictedMessage });
			} finally {
				await deleteUserById(suRequest, user.id).catch(() => undefined);
			}
		});

		test('security-locked account shows restricted login error', async ({
			page,
			suRequest,
			ephemeralUser
		}) => {
			await patchUserMaps(suRequest, ephemeralUser.id, { status: 'locked by security' });
			try {
				await expectLoginRejected(page, ephemeralUser, { message: restrictedMessage });
			} finally {
				await patchUserMaps(suRequest, ephemeralUser.id, { status: 'ok' }).catch(() => undefined);
			}
		});
	});
});
