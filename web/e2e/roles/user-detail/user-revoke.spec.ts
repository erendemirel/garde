import { test, expect } from '../../helpers/fixtures';
import { describeTags, TAG } from '../../helpers/tags';
import {
	e2eAdmin2,
	loginViaRequest,
	openDashboardSession,
	startUserSession
} from '../../helpers/auth';
import { openUserDetailFromAdmin, openUserDetailFromSuperuser } from '../../helpers/userApi';
import { disableMfaViaApi, enableMfaViaUi } from '../../helpers/mfa';
import { totpCode } from '../../helpers/totp';
import {
	LOAD_TIMEOUT,
	matchRevokeSessions,
	REDIRECT_TIMEOUT,
	waitForToastGone
} from '../../helpers/waits';

/**
 * Revoke sessions on an ephemeral user — does not kill seed admin sessions used by other workers.
 */
test.describe('Revoke user sessions', describeTags(TAG.userDetail, TAG.activeSession, TAG.focused), () => {
	test.describe.configure({ mode: 'serial' });

	test('shows revoke and delete controls on user detail', async ({
		superuserPage: page,
		ephemeralUser
	}) => {
		await page.goto('/superuser');
		await openUserDetailFromSuperuser(page, ephemeralUser.email);
		await expect(page.getByTestId('user-detail-revoke-btn')).toBeEnabled();
		await expect(page.getByTestId('user-detail-delete-btn')).toBeEnabled();
	});

	test('revoking sessions signs the target user out', async ({
		browser,
		superuserPage: suPage,
		ephemeralUser
	}) => {
		const targetContext = await browser.newContext();
		const targetPage = await targetContext.newPage();
		await startUserSession(targetPage, ephemeralUser);
		await expect(targetPage.getByTestId('dashboard-page')).toBeVisible();

		await suPage.goto('/superuser');
		await openUserDetailFromSuperuser(suPage, ephemeralUser.email);
		await suPage.getByTestId('user-detail-revoke-btn').click();
		await expect(suPage.getByTestId('confirm-modal-message')).toBeVisible();
		await suPage.getByTestId('confirm-modal-confirm').click();
		await expect(suPage.getByTestId('toast')).toContainText('Sessions revoked');
		await waitForToastGone(suPage);

		await expect(suPage.getByTestId('user-detail-page')).toBeVisible();

		await targetPage.goto('/dashboard');
		await expect(targetPage.getByTestId('login-page')).toBeVisible({ timeout: REDIRECT_TIMEOUT });
		await expect(targetPage.getByTestId('app-nav')).toHaveCount(0);

		await targetContext.close();
	});

	test('revoke confirmation cancel keeps sessions active', async ({
		browser,
		superuserPage: suPage,
		ephemeralUser
	}) => {
		const targetContext = await browser.newContext();
		const targetPage = await targetContext.newPage();
		await startUserSession(targetPage, ephemeralUser);
		await expect(targetPage.getByTestId('dashboard-page')).toBeVisible();

		await suPage.goto('/superuser');
		await openUserDetailFromSuperuser(suPage, ephemeralUser.email);
		await suPage.getByTestId('user-detail-revoke-btn').click();
		await expect(suPage.getByTestId('confirm-modal-message')).toBeVisible();
		await suPage.getByTestId('confirm-modal-cancel').click();

		await expect(suPage.getByTestId('confirm-modal-message')).toHaveCount(0);
		await targetPage.goto('/dashboard');
		await expect(targetPage.getByTestId('dashboard-page')).toBeVisible();

		await targetContext.close();
	});

	test.describe('acting admin MFA enabled', () => {
		test('requires MFA code before opening revoke confirmation when MFA is enabled', async ({
			browser,
			ephemeralUser
		}) => {
			const ctx = await browser.newContext();
			const page = await ctx.newPage();
			let secret = '';
			try {
				await loginViaRequest(page.request, e2eAdmin2);
				await openDashboardSession(page);
				secret = await enableMfaViaUi(page);

				await page.goto('/admin');
				await openUserDetailFromAdmin(page, ephemeralUser.email);
				await expect(page.getByTestId('user-detail-mfa-code')).toBeVisible();

				await page.getByTestId('user-detail-revoke-btn').click();
				await expect(page.getByTestId('toast')).toContainText('Enter your MFA code');
				await expect(page.getByTestId('confirm-modal-message')).toHaveCount(0);
			} finally {
				if (secret) await disableMfaViaApi(page.request, secret);
				await ctx.close();
			}
		});

		test('revoking sessions with valid MFA code signs the target user out', async ({
			browser,
			ephemeralUser
		}) => {
			const adminContext = await browser.newContext();
			const adminPage = await adminContext.newPage();
			const targetContext = await browser.newContext();
			const targetPage = await targetContext.newPage();
			let secret = '';
			try {
				await startUserSession(targetPage, ephemeralUser);
				await expect(targetPage.getByTestId('dashboard-page')).toBeVisible();

				await loginViaRequest(adminPage.request, e2eAdmin2);
				await openDashboardSession(adminPage);
				secret = await enableMfaViaUi(adminPage);

				await adminPage.goto('/admin');
				await openUserDetailFromAdmin(adminPage, ephemeralUser.email);
				await adminPage.getByTestId('user-detail-mfa-code').fill(totpCode(secret));

				const revokeResponse = adminPage.waitForResponse(matchRevokeSessions, {
					timeout: LOAD_TIMEOUT
				});
				await adminPage.getByTestId('user-detail-revoke-btn').click();
				await adminPage.getByTestId('confirm-modal-confirm').click();
				const res = await revokeResponse;
				expect(res.ok()).toBeTruthy();
				await expect(adminPage.getByTestId('toast')).toContainText('Sessions revoked');
				await waitForToastGone(adminPage);

				await targetPage.goto('/dashboard');
				await expect(targetPage.getByTestId('login-page')).toBeVisible({
					timeout: REDIRECT_TIMEOUT
				});
			} finally {
				if (secret) await disableMfaViaApi(adminPage.request, secret);
				await targetContext.close();
				await adminContext.close();
			}
		});

		test('API rejects revoke without valid MFA when acting admin has MFA enabled', async ({
			browser,
			ephemeralUser
		}) => {
			const ctx = await browser.newContext();
			const page = await ctx.newPage();
			let secret = '';
			try {
				await loginViaRequest(page.request, e2eAdmin2);
				await openDashboardSession(page);
				secret = await enableMfaViaUi(page);

				const missing = await page.request.post('/api/sessions/revoke', {
					data: { user_id: ephemeralUser.id }
				});
				expect(missing.status()).toBe(400);
				expect(String((await missing.json())?.error?.message ?? '')).toMatch(/MFA code required/i);

				const invalid = await page.request.post('/api/sessions/revoke', {
					data: { user_id: ephemeralUser.id, mfa_code: '000000' }
				});
				expect(invalid.status()).toBe(400);
				expect(String((await invalid.json())?.error?.message ?? '')).toMatch(/invalid MFA code/i);

				const ok = await page.request.post('/api/sessions/revoke', {
					data: { user_id: ephemeralUser.id, mfa_code: totpCode(secret) }
				});
				expect(ok.ok()).toBeTruthy();
			} finally {
				if (secret) await disableMfaViaApi(page.request, secret);
				await ctx.close();
			}
		});

		test('shows an error when revoke is submitted with invalid MFA code', async ({
			browser,
			ephemeralUser
		}) => {
			const ctx = await browser.newContext();
			const page = await ctx.newPage();
			let secret = '';
			try {
				await loginViaRequest(page.request, e2eAdmin2);
				await openDashboardSession(page);
				secret = await enableMfaViaUi(page);

				await page.goto('/admin');
				await openUserDetailFromAdmin(page, ephemeralUser.email);
				await page.getByTestId('user-detail-mfa-code').fill('000000');

				const revokeResponse = page.waitForResponse(matchRevokeSessions, {
					timeout: LOAD_TIMEOUT
				});
				await page.getByTestId('user-detail-revoke-btn').click();
				await page.getByTestId('confirm-modal-confirm').click();
				const res = await revokeResponse;
				expect(res.ok()).toBeFalsy();
				expect(res.status()).toBe(400);
				await expect(page.getByTestId('toast')).toContainText(/invalid MFA code/i);
				await expect(page.getByTestId('user-detail-page')).toBeVisible();
			} finally {
				if (secret) await disableMfaViaApi(page.request, secret);
				await ctx.close();
			}
		});
	});
});
