import { test, expect } from '../helpers/fixtures';
import { loginAs, loginViaRequest, startUserSession, e2eAdmin } from '../helpers/auth';
import { enableMfaViaUi, startMfaSetup } from '../helpers/mfa';
import { totpCode } from '../helpers/totp';
import { createEphemeralUser, deleteUserById } from '../helpers/userApi';
import { waitForPageShell, LOAD_TIMEOUT } from '../helpers/waits';

test.describe('Dashboard account overview', () => {
	test('shows account summary and self-service links', async ({ adminPage: page }) => {
		await page.goto('/dashboard');
		await waitForPageShell(page, 'dashboard-page');
		await expect(page.getByTestId('dashboard-email')).toHaveText(e2eAdmin.email);
		await expect(page.getByTestId('dashboard-status')).toBeVisible();
		await expect(page.getByTestId('dashboard-mfa')).toBeVisible();
		await expect(page.getByTestId('dashboard-permissions')).toBeVisible();
		await expect(page.getByTestId('dashboard-groups')).toBeVisible();
		await expect(page.getByTestId('dashboard-link-mfa')).toBeVisible();
		await expect(page.getByTestId('dashboard-link-password')).toBeVisible();
		await expect(page.getByTestId('dashboard-link-request-update')).toBeVisible();

		const permChips = page.getByTestId('dashboard-permission-chip');
		const permEmpty = page.getByTestId('dashboard-permissions-empty');
		await expect(permChips.or(permEmpty).first()).toBeVisible();

		const groupChips = page.getByTestId('dashboard-group-chip');
		const groupEmpty = page.getByTestId('dashboard-groups-empty');
		await expect(groupChips.or(groupEmpty).first()).toBeVisible();
	});

	test('opens change-password from the dashboard', async ({ adminPage: page }) => {
		await page.goto('/dashboard');
		await waitForPageShell(page, 'dashboard-page');
		await page.getByTestId('dashboard-link-password').click();
		await expect(page).toHaveURL(/\/password/);
		await expect(page.getByTestId('password-page')).toBeVisible();
	});

	test('opens MFA from the dashboard', async ({ adminPage: page }) => {
		await page.goto('/dashboard');
		await waitForPageShell(page, 'dashboard-page');
		await page.getByTestId('dashboard-link-mfa').click();
		await expect(page).toHaveURL(/\/mfa/);
		await expect(page.getByTestId('mfa-page')).toBeVisible();
	});
});

test.describe('Change password page', () => {
	test.describe('happy path', () => {
		test('shows the form with stable locators', async ({ adminPage: page }) => {
			await page.goto('/password');
			await waitForPageShell(page, 'password-page');
			await expect(page.getByTestId('password-current')).toBeVisible();
			await expect(page.getByTestId('password-new')).toBeVisible();
			await expect(page.getByTestId('password-confirm')).toBeVisible();
			await expect(page.getByTestId('password-submit')).toBeEnabled();
			await expect(page.getByTestId('password-back')).toHaveAttribute('href', '/dashboard');
		});

		test('back link returns to the dashboard', async ({ adminPage: page }) => {
			await page.goto('/password');
			await waitForPageShell(page, 'password-page');
			await page.getByTestId('password-back').click();
			await expect(page).toHaveURL(/\/dashboard/);
			await waitForPageShell(page, 'dashboard-page');
		});

		test('changes password, logs out, and signs in with the new password', async ({
			browser,
			ephemeralUser
		}) => {
			const newPassword = 'DevAdminTest456!';
			const context = await browser.newContext();
			const page = await context.newPage();

			await startUserSession(page, ephemeralUser);
			await page.getByTestId('dashboard-link-password').click();
			await expect(page.getByTestId('password-page')).toBeVisible();

			await page.getByTestId('password-current').fill(ephemeralUser.password);
			await page.getByTestId('password-new').fill(newPassword);
			await page.getByTestId('password-confirm').fill(newPassword);

			await page.getByTestId('password-submit').click();
			await expect(page.getByTestId('confirm-modal-message')).toBeVisible();

			const changeResponse = page.waitForResponse(
				(res) =>
					res.url().includes('/api/users/password/change') &&
					res.request().method() === 'POST'
			);
			await page.getByTestId('confirm-modal-confirm').click();
			const res = await changeResponse;
			expect(res.ok()).toBeTruthy();

			await expect(page.getByTestId('password-success')).toContainText('Password changed');
			await expect(page.getByTestId('login-page')).toBeVisible({ timeout: 15_000 });

			await loginAs(page, { email: ephemeralUser.email, password: newPassword });
			await expect(page.getByTestId('dashboard-email')).toHaveText(ephemeralUser.email);

			await context.close();
		});

		test('changes password when MFA is enabled using a TOTP code', async ({
			browser,
			ephemeralUser
		}) => {
			const newPassword = 'MfaChangePass123!';
			const context = await browser.newContext();
			const page = await context.newPage();

			await startUserSession(page, ephemeralUser);
			const secret = await enableMfaViaUi(page);

			await page.getByTestId('dashboard-link-password').click();
			await expect(page.getByTestId('password-page')).toBeVisible();
			await expect(page.getByTestId('password-mfa')).toBeVisible();

			await page.getByTestId('password-current').fill(ephemeralUser.password);
			await page.getByTestId('password-new').fill(newPassword);
			await page.getByTestId('password-confirm').fill(newPassword);
			await page.getByTestId('password-mfa').fill(totpCode(secret));
			await page.getByTestId('password-submit').click();
			await expect(page.getByTestId('confirm-modal-message')).toBeVisible();

			const changeResponse = page.waitForResponse(
				(res) =>
					res.url().includes('/api/users/password/change') &&
					res.request().method() === 'POST'
			);
			await page.getByTestId('confirm-modal-confirm').click();
			const res = await changeResponse;
			expect(res.ok()).toBeTruthy();

			await expect(page.getByTestId('password-success')).toContainText('Password changed');
			await expect(page.getByTestId('login-page')).toBeVisible({ timeout: 15_000 });

			await loginAs(page, {
				email: ephemeralUser.email,
				password: newPassword,
				mfaCode: totpCode(secret)
			});
			await expect(page.getByTestId('dashboard-email')).toHaveText(ephemeralUser.email);

			await context.close();
		});
	});

	test.describe('validation', () => {
		test('client-side mismatch shows an error without confirming', async ({ adminPage: page }) => {
			await page.goto('/password');
			await waitForPageShell(page, 'password-page');
			await page.getByTestId('password-current').fill(e2eAdmin.password);
			await page.getByTestId('password-new').fill('NewPassword123!');
			await page.getByTestId('password-confirm').fill('DifferentPass123!');
			await page.getByTestId('password-submit').click();
			await expect(page.getByTestId('password-error')).toHaveText('Passwords do not match');
			await expect(page.getByTestId('confirm-modal-message')).toHaveCount(0);
		});

		test('confirm modal cancel keeps the form', async ({ regularUserPage: page }) => {
			await page.goto('/password');
			await waitForPageShell(page, 'password-page');
			await page.getByTestId('password-current').fill('DevAdminTest123!');
			await page.getByTestId('password-new').fill('AnotherPass123!');
			await page.getByTestId('password-confirm').fill('AnotherPass123!');
			await page.getByTestId('password-submit').click();
			await expect(page.getByTestId('confirm-modal-message')).toBeVisible();
			await page.getByTestId('confirm-modal-cancel').click();

			await expect(page.getByTestId('confirm-modal-message')).toHaveCount(0);
			await expect(page.getByTestId('password-form')).toBeVisible();
			await expect(page.getByTestId('password-new')).toHaveValue('AnotherPass123!');
		});
	});

	test.describe('API errors', () => {
		test('shows an error for wrong current password', async ({ regularUserPage: page }) => {
			await page.goto('/password');
			await waitForPageShell(page, 'password-page');
			await page.getByTestId('password-current').fill('WrongCurrentPass123!');
			await page.getByTestId('password-new').fill('NewPassword123!');
			await page.getByTestId('password-confirm').fill('NewPassword123!');
			await page.getByTestId('password-submit').click();
			await page.getByTestId('confirm-modal-confirm').click();

			await expect(page.getByTestId('password-error')).toBeVisible();
			await expect(page.getByTestId('password-page')).toBeVisible();
			await expect(page.getByTestId('password-success')).toHaveCount(0);
		});

		test('shows an error for invalid MFA code when MFA is enabled', async ({
			browser,
			ephemeralUser
		}) => {
			const context = await browser.newContext();
			const page = await context.newPage();
			await startUserSession(page, ephemeralUser);
			await enableMfaViaUi(page);

			await page.getByTestId('dashboard-link-password').click();
			await expect(page.getByTestId('password-mfa')).toBeVisible();
			await page.getByTestId('password-current').fill(ephemeralUser.password);
			await page.getByTestId('password-new').fill('AnotherPass123!');
			await page.getByTestId('password-confirm').fill('AnotherPass123!');
			await page.getByTestId('password-mfa').fill('000000');
			await page.getByTestId('password-submit').click();
			await page.getByTestId('confirm-modal-confirm').click();

			await expect(page.getByTestId('password-error')).toBeVisible();
			await expect(page.getByTestId('password-page')).toBeVisible();
			await context.close();
		});
	});
});

test.describe('MFA page', () => {
	test.describe('setup', () => {
		test('shows disabled MFA choice for the seed admin', async ({ adminPage: page }) => {
			await page.goto('/mfa');
			await waitForPageShell(page, 'mfa-page');
			await expect(page.getByTestId('mfa-page')).toHaveAttribute('data-step', 'choice');
			await expect(page.getByTestId('mfa-status')).toContainText('disabled');
			await expect(page.getByTestId('mfa-setup')).toBeEnabled();
		});

		test('setup advances to the verify step with a secret', async ({
			browser,
			ephemeralUser
		}) => {
			const context = await browser.newContext();
			const page = await context.newPage();
			await startUserSession(page, ephemeralUser);
			await waitForPageShell(page, 'dashboard-page');
			await page.getByTestId('dashboard-link-mfa').click();

			const setupResponse = page.waitForResponse(
				(res) =>
					res.url().includes('/api/users/mfa/setup') && res.request().method() === 'POST'
			);
			await page.getByTestId('mfa-setup').click();
			await setupResponse;

			await expect(page.getByTestId('mfa-page')).toHaveAttribute('data-step', 'verify');
			await expect(page.getByTestId('mfa-qr')).toBeVisible();
			await expect(page.getByTestId('mfa-secret')).not.toBeEmpty();
			await context.close();
		});

		test('shows an error for invalid MFA code during setup verify', async ({
			regularUserPage: page
		}) => {
			await page.goto('/dashboard');
			await waitForPageShell(page, 'dashboard-page');
			await startMfaSetup(page);

			await page.getByTestId('mfa-code').fill('000000');
			const verifyResponse = page.waitForResponse(
				(res) =>
					res.url().includes('/api/users/mfa/verify') && res.request().method() === 'POST'
			);
			await page.getByTestId('mfa-verify-submit').click();
			const verifyRes = await verifyResponse;
			expect(verifyRes.ok()).toBeFalsy();

			await expect(page.getByTestId('mfa-error')).toBeVisible();
			await expect(page.getByTestId('mfa-page')).toHaveAttribute('data-step', 'verify');
		});
	});

	test.describe('lifecycle', () => {
		test.describe.configure({ timeout: 120_000 });

		test('enables MFA, signs in with TOTP, then disables', async ({ browser, ephemeralUser }) => {
			const context = await browser.newContext();
			const page = await context.newPage();
			await startUserSession(page, ephemeralUser);

			const secret = await enableMfaViaUi(page);

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

		test('cancelling MFA disable returns to choice step', async ({ browser, ephemeralUser }) => {
			const context = await browser.newContext();
			const page = await context.newPage();
			await startUserSession(page, ephemeralUser);
			await enableMfaViaUi(page);

			await page.getByTestId('dashboard-link-mfa').click();
			await expect(page.getByTestId('mfa-status')).toContainText('enabled');
			await page.getByTestId('mfa-disable-start').click();
			await expect(page.getByTestId('mfa-page')).toHaveAttribute('data-step', 'disable');
			await expect(page.getByTestId('mfa-disable-form')).toBeVisible();

			await page.getByTestId('mfa-disable-cancel').click();
			await expect(page.getByTestId('mfa-page')).toHaveAttribute('data-step', 'choice');
			await expect(page.getByTestId('mfa-disable-form')).toHaveCount(0);

			await context.close();
		});
	});

	test.describe('enforcement', () => {
		test.describe.configure({ timeout: 120_000 });

		test('enforced user without MFA is redirected to setup', async ({
			browser,
			suRequest,
			uniqueSuffix
		}) => {
			const user = await createEphemeralUser(suRequest, `mfa_enf_${uniqueSuffix}`, {
				groups: ['group_a']
			});

			try {
				await suRequest.put(`/api/users/${user.id}`, {
					data: { mfa_enforced: true }
				});

				const context = await browser.newContext();
				const page = await context.newPage();
				await loginViaRequest(page.request, user);
				await page.goto('/dashboard');
				await expect(page).toHaveURL(/\/mfa/, { timeout: LOAD_TIMEOUT });
				await waitForPageShell(page, 'mfa-page');
				await expect(page.getByTestId('mfa-page')).toHaveAttribute('data-step', 'choice');
				await context.close();
			} finally {
				await deleteUserById(suRequest, user.id).catch(() => undefined);
			}
		});

		test('blocks MFA disable when enforcement is active', async ({
			browser,
			suRequest,
			ephemeralUser
		}) => {
			await suRequest.put(`/api/users/${ephemeralUser.id}`, {
				data: { mfa_enforced: true }
			});

			const context = await browser.newContext();
			const page = await context.newPage();
			await loginViaRequest(page.request, ephemeralUser);
			await page.goto('/dashboard');
			await expect(page).toHaveURL(/\/mfa/, { timeout: LOAD_TIMEOUT });
			await waitForPageShell(page, 'mfa-page');

			const setupResponse = page.waitForResponse(
				(res) =>
					res.url().includes('/api/users/mfa/setup') && res.request().method() === 'POST'
			);
			await page.getByTestId('mfa-setup').click();
			await setupResponse;
			const secret = (await page.getByTestId('mfa-secret').innerText()).trim();
			await page.getByTestId('mfa-code').fill(totpCode(secret));
			const verifyResponse = page.waitForResponse(
				(res) =>
					res.url().includes('/api/users/mfa/verify') && res.request().method() === 'POST'
			);
			await page.getByTestId('mfa-verify-submit').click();
			await verifyResponse;
			await expect(page.getByTestId('dashboard-page')).toBeVisible({ timeout: 15_000 });

			await page.goto('/mfa');
			await waitForPageShell(page, 'mfa-page');
			await expect(page.getByTestId('mfa-status')).toContainText('enabled');
			await expect(page.getByTestId('mfa-error')).toContainText('cannot be disabled');
			await expect(page.getByTestId('mfa-disable-start')).toHaveCount(0);

			await context.close();
			await suRequest.put(`/api/users/${ephemeralUser.id}`, { data: { mfa_enforced: false } });
		});
	});
});
