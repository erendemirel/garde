import { test, expect } from '../helpers/fixtures';
import { loginAs, startUserSession, startUserSessionAt, submitLogin } from '../helpers/auth';
import { totpCode } from '../helpers/totp';
import {
	createEphemeralUser,
	openUserDetailFromAdmin,
	openUserDetailFromSuperuser
} from '../helpers/userApi';
import { waitForPageShell, waitForSignedOut, matchUserUpdate, LOAD_TIMEOUT, REDIRECT_TIMEOUT, waitForToastGone } from '../helpers/waits';
import { describeTags, TAG } from '../helpers/tags';

test.describe.configure({ timeout: 120_000 });

/**
 * Admin/superuser actions against a user who already has an active session.
 */
test.describe('Active session security', describeTags(TAG.journey, TAG.activeSession, TAG.security), () => {
	test.describe('lock', () => {
		test('locking an in-scope user signs them out on reload', async ({
			browser,
			adminPage,
			ephemeralUser
		}) => {
			const userContext = await browser.newContext();
			const userPage = await userContext.newPage();
			await startUserSession(userPage, ephemeralUser);
			await expect(userPage.getByTestId('dashboard-page')).toBeVisible();

			await adminPage.goto('/admin');
			await openUserDetailFromAdmin(adminPage, ephemeralUser.email);
			const lockResponse = adminPage.waitForResponse(matchUserUpdate, { timeout: LOAD_TIMEOUT });
			await adminPage.getByTestId('user-detail-lock-btn').click();
			await adminPage.getByTestId('confirm-modal-confirm').click();
			await lockResponse;
			await expect(adminPage.getByTestId('toast')).toContainText('Account locked by admin', {
				timeout: LOAD_TIMEOUT
			});
			await waitForToastGone(adminPage);

			await waitForSignedOut(userPage, { reload: true });

			await userContext.close();

			await adminPage.getByTestId('user-detail-lock-btn').click();
			await adminPage.getByTestId('confirm-modal-confirm').click();
			await expect(adminPage.getByTestId('toast')).toContainText('Account unlocked');
			await waitForToastGone(adminPage);
		});
	});

	test.describe('delete', () => {
		test('deleting a logged-in user signs them out on navigation', async ({
			browser,
			superuserPage: suPage,
			suRequest,
			uniqueSuffix
		}) => {
			const user = await createEphemeralUser(suRequest, `del_active_${uniqueSuffix}`);
			const userContext = await browser.newContext();
			const userPage = await userContext.newPage();
			try {
				await startUserSession(userPage, user);
				await expect(userPage.getByTestId('dashboard-page')).toBeVisible();

				await suPage.goto('/superuser');
				await openUserDetailFromSuperuser(suPage, user.email);
				await suPage.getByTestId('user-detail-delete-btn').click();
				await suPage.getByTestId('confirm-modal-confirm').click();
				await expect(suPage.getByTestId('toast')).toContainText('User deleted');
				await waitForToastGone(suPage);

				await userPage.goto('/dashboard');
				await expect(userPage.getByTestId('login-page')).toBeVisible({ timeout: REDIRECT_TIMEOUT });
				await expect(userPage.getByTestId('app-nav')).toHaveCount(0);
			} finally {
				await userContext.close();
			}
		});
	});

	test.describe('MFA enforcement', () => {
		test('redirects to setup on login when enforced before sign-in', async ({
			browser,
			adminPage,
			ephemeralUser,
			suRequest
		}) => {
			await adminPage.goto('/admin');
			await openUserDetailFromAdmin(adminPage, ephemeralUser.email);
			const enforceResponse = adminPage.waitForResponse(matchUserUpdate, { timeout: LOAD_TIMEOUT });
			await adminPage.getByTestId('user-detail-mfa-enforce-btn').click();
			await adminPage.getByTestId('confirm-modal-confirm').click();
			await enforceResponse;
			await expect(adminPage.getByTestId('toast')).toContainText('MFA enforcement enabled', {
				timeout: LOAD_TIMEOUT
			});
			await waitForToastGone(adminPage);

			const context = await browser.newContext();
			const page = await context.newPage();
			try {
				await startUserSessionAt(page, ephemeralUser, '/dashboard');
				await expect(page).toHaveURL(/\/mfa/, { timeout: REDIRECT_TIMEOUT });
				await waitForPageShell(page, 'mfa-page');
				await expect(page.getByTestId('mfa-page')).toHaveAttribute('data-step', 'choice');
			} finally {
				await context.close();
				await suRequest
					.put(`/api/users/${ephemeralUser.id}`, { data: { mfa_enforced: false } })
					.catch(() => undefined);
			}
		});

		test('redirects to setup on reload when enforced during an active session', async ({
			browser,
			adminPage,
			ephemeralUser,
			suRequest
		}) => {
			const userContext = await browser.newContext();
			const userPage = await userContext.newPage();
			try {
				await startUserSession(userPage, ephemeralUser);
				await expect(userPage.getByTestId('dashboard-page')).toBeVisible();

				await adminPage.goto('/admin');
				await openUserDetailFromAdmin(adminPage, ephemeralUser.email);
				await adminPage.getByTestId('user-detail-mfa-enforce-btn').click();
				await adminPage.getByTestId('confirm-modal-confirm').click();
				await expect(adminPage.getByTestId('toast')).toContainText('MFA enforcement enabled');
				await waitForToastGone(adminPage);

				await userPage.reload();
				await expect(userPage).toHaveURL(/\/mfa/, { timeout: REDIRECT_TIMEOUT });
				await waitForPageShell(userPage, 'mfa-page');
				await expect(userPage.getByTestId('mfa-page')).toHaveAttribute('data-step', 'choice');
			} finally {
				await userContext.close();
				await suRequest
					.put(`/api/users/${ephemeralUser.id}`, { data: { mfa_enforced: false } })
					.catch(() => undefined);
			}
		});

		test('user completes MFA setup after enforcement and reaches dashboard', async ({
			browser,
			adminPage,
			ephemeralUser,
			suRequest
		}) => {
			test.setTimeout(90_000);

			const userContext = await browser.newContext();
			const userPage = await userContext.newPage();
			try {
				await startUserSession(userPage, ephemeralUser);
				await expect(userPage.getByTestId('dashboard-page')).toBeVisible();

				await adminPage.goto('/admin');
				await openUserDetailFromAdmin(adminPage, ephemeralUser.email);
				await adminPage.getByTestId('user-detail-mfa-enforce-btn').click();
				await adminPage.getByTestId('confirm-modal-confirm').click();
				await expect(adminPage.getByTestId('toast')).toContainText('MFA enforcement enabled');
				await waitForToastGone(adminPage);

				await userPage.reload();
				await expect(userPage).toHaveURL(/\/mfa/, { timeout: REDIRECT_TIMEOUT });
				await waitForPageShell(userPage, 'mfa-page');
				await expect(userPage.getByTestId('mfa-page')).toHaveAttribute('data-step', 'choice');

				const setupResponse = userPage.waitForResponse(
					(res) =>
						res.url().includes('/api/users/mfa/setup') && res.request().method() === 'POST'
				);
				await userPage.getByTestId('mfa-setup').click();
				await setupResponse;
				await expect(userPage.getByTestId('mfa-page')).toHaveAttribute('data-step', 'verify');

				const secret = (await userPage.getByTestId('mfa-secret').innerText()).trim();
				await userPage.getByTestId('mfa-code').fill(totpCode(secret));
				const verifyResponse = userPage.waitForResponse(
					(res) =>
						res.url().includes('/api/users/mfa/verify') && res.request().method() === 'POST'
				);
				await userPage.getByTestId('mfa-verify-submit').click();
				await verifyResponse;

				await expect(userPage.getByTestId('dashboard-page')).toBeVisible({ timeout: REDIRECT_TIMEOUT });
				await expect(userPage.getByTestId('dashboard-link-request-update')).toBeVisible();
			} finally {
				await userContext.close();
				await suRequest
					.put(`/api/users/${ephemeralUser.id}`, {
						data: { mfa_enforced: false, mfa_enabled: false }
					})
					.catch(() => undefined);
			}
		});
	});
});
