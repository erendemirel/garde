import { test, expect } from '../helpers/fixtures';
import { loginAs, startUserSession } from '../helpers/auth';
import {
	completeMfaSetupFromChoice,
	openRequestUpdate,
	reloadDashboardWithMe,
	SCOPE_GROUP,
	stageGroupAddByName,
	submitRequestUpdate,
	verifyMfaSetup,
	type JourneyActOptions
} from '../helpers/journeys';
import { describeTags, TAG } from '../helpers/tags';
import { openUserDetailFromAdmin, openUserDetailFromSuperuser } from '../helpers/userApi';
import { totpCode } from '../helpers/totp';
import { waitForPageShell, waitForSignedOut, matchUserUpdate, LOAD_TIMEOUT } from '../helpers/waits';

const epic: JourneyActOptions = { outcomesOnly: true };

test.describe(
	'Epic: security hardening',
	describeTags(TAG.epic, TAG.security, TAG.activeSession, TAG.selfService, TAG.requestUpdate),
	() => {
		test.setTimeout(180_000);

		test('MFA enforcement through revoke and recovery', async ({
			adminPage,
			superuserPage: suPage,
			suRequest,
			ephemeralUser,
			browser
		}) => {
			const newPassword = 'EpicMfaSecure789!';
			let mfaSecret = '';

			const userContext = await browser.newContext();
			const userPage = await userContext.newPage();

			try {
				await startUserSession(userPage, ephemeralUser);
				await expect(userPage.getByTestId('dashboard-page')).toBeVisible();

				await adminPage.goto('/admin');
				await openUserDetailFromAdmin(adminPage, ephemeralUser.email);
				const enforceResponse = adminPage.waitForResponse(matchUserUpdate, {
					timeout: LOAD_TIMEOUT
				});
				await adminPage.getByTestId('user-detail-mfa-enforce-btn').click();
				await adminPage.getByTestId('confirm-modal-confirm').click();
				await enforceResponse;

				await userPage.reload();
				await expect(userPage).toHaveURL(/\/mfa/, { timeout: LOAD_TIMEOUT });
				await waitForPageShell(userPage, 'mfa-page');

				await userPage.goto('/dashboard');
				await expect(userPage).toHaveURL(/\/mfa/, { timeout: LOAD_TIMEOUT });
				await waitForPageShell(userPage, 'mfa-page');

				mfaSecret = await completeMfaSetupFromChoice(userPage);
				await verifyMfaSetup(userPage, mfaSecret, false);
				await expect(userPage.getByTestId('mfa-page')).toHaveAttribute('data-step', 'verify');
				await verifyMfaSetup(userPage, mfaSecret, true);

				await openRequestUpdate(userPage);
				await stageGroupAddByName(userPage, SCOPE_GROUP, epic);
				await submitRequestUpdate(userPage, epic);
				await reloadDashboardWithMe(userPage);
				await expect(userPage.getByTestId('dashboard-pending-update')).toBeVisible();

				await userPage.getByTestId('nav-logout').click();
				await expect(userPage.getByTestId('login-page')).toBeVisible();

				await loginAs(userPage, {
					email: ephemeralUser.email,
					password: ephemeralUser.password,
					mfaCode: totpCode(mfaSecret)
				});
				await expect(userPage.getByTestId('dashboard-page')).toBeVisible();

				await userPage.getByTestId('dashboard-link-password').click();
				await waitForPageShell(userPage, 'password-page');
				await userPage.getByTestId('password-current').fill(ephemeralUser.password);
				await userPage.getByTestId('password-new').fill(newPassword);
				await userPage.getByTestId('password-confirm').fill(newPassword);
				await userPage.getByTestId('password-mfa').fill(totpCode(mfaSecret));
				await userPage.getByTestId('password-submit').click();
				await userPage.getByTestId('confirm-modal-confirm').click();
				await expect(userPage.getByTestId('login-page')).toBeVisible({ timeout: LOAD_TIMEOUT });

				await loginAs(userPage, {
					email: ephemeralUser.email,
					password: newPassword,
					mfaCode: totpCode(mfaSecret)
				});
				await userPage.goto('/mfa');
				await expect(userPage.getByTestId('mfa-disable-start')).toHaveCount(0);

				await suPage.goto('/superuser');
				await openUserDetailFromSuperuser(suPage, ephemeralUser.email);
				await suPage.getByTestId('user-detail-revoke-btn').click();
				await suPage.getByTestId('confirm-modal-confirm').click();

				await waitForSignedOut(userPage, { path: '/dashboard' });

				await loginAs(userPage, {
					email: ephemeralUser.email,
					password: newPassword,
					mfaCode: totpCode(mfaSecret)
				});
				await expect(userPage.getByTestId('dashboard-page')).toBeVisible();

				await suPage.goto('/superuser');
				await openUserDetailFromSuperuser(suPage, ephemeralUser.email);
				await suPage.getByTestId('user-detail-mfa-enforce-btn').click();
				await suPage.getByTestId('confirm-modal-confirm').click();
			} finally {
				await userContext.close();
				await suRequest
					.put(`/api/users/${ephemeralUser.id}`, {
						data: { mfa_enforced: false, mfa_enabled: false }
					})
					.catch(() => undefined);
			}
		});
	}
);
