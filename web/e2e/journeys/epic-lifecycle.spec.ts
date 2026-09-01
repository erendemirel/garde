import { test, expect } from '../helpers/fixtures';
import { signInApprovedUser, startUserSession } from '../helpers/auth';
import {
	adminApproveUpdate,
	adminRejectAccount,
	adminRejectUpdate,
	expectStillSignedOut,
	openRequestUpdate,
	reloadDashboardWithMe,
	SCOPE_GROUP,
	stageGroupAddByName,
	submitRegisterForm,
	submitRequestUpdate,
	superuserApproveAccountAnyway,
	type JourneyActOptions
} from '../helpers/journeys';
import { describeTags, TAG } from '../helpers/tags';
import { deleteUserById, findUserByEmail, openUserDetailFromSuperuser } from '../helpers/userApi';
import { waitForPageShell, waitForPasswordChangeSignOut } from '../helpers/waits';

/** Outcome-only acts — toast copy and error messages live in focused specs. */
const epic: JourneyActOptions = { outcomesOnly: true };

/**
 * Epic: register → reject → approve → request-update → password → delete.
 * Asserts chain outcomes only; see @registration, @request-update, @self-service for details.
 */
test.describe(
	'Epic: user lifecycle',
	describeTags(TAG.epic, TAG.registration, TAG.requestUpdate, TAG.selfService),
	() => {
		test.setTimeout(180_000);

		test('full lifecycle with negative branches', async ({
			page,
			adminPage,
			superuserPage: suPage,
			suRequest,
			uniqueSuffix
		}) => {
			const email = `e2e.epic.lifecycle.${uniqueSuffix}@example.com`;
			const password = 'DevAdminTest123!';
			const newPassword = 'EpicLifecycle456!';
			let userId: string | undefined;

			try {
				await submitRegisterForm(page, email, password);
				await expect(page.getByTestId('register-success-panel')).toBeVisible();
				await expectStillSignedOut(page);

				const summary = await findUserByEmail(suRequest, email);
				expect(summary?.id).toBeTruthy();
				userId = summary!.id;

				await suRequest.put(`/api/users/${userId}`, {
					data: { groups: { group_a: true } }
				});

				await adminRejectAccount(adminPage, email, epic);
				await expectStillSignedOut(page);

				await superuserApproveAccountAnyway(suPage, email, epic);
				await signInApprovedUser(page, { email, password });
				await expect(page.getByTestId('dashboard-page')).toBeVisible();

				await openRequestUpdate(page);
				await stageGroupAddByName(page, SCOPE_GROUP, epic);
				await submitRequestUpdate(page, epic);
				await reloadDashboardWithMe(page);
				await expect(page.getByTestId('dashboard-pending-update')).toBeVisible();

				await adminRejectUpdate(adminPage, email, epic);
				await reloadDashboardWithMe(page);
				await expect(page.getByTestId('dashboard-pending-update')).toHaveCount(0);
				await expect(
					page.locator(`[data-testid="dashboard-group-chip"][data-key="${SCOPE_GROUP}"]`)
				).toHaveCount(0);

				await openRequestUpdate(page);
				await stageGroupAddByName(page, SCOPE_GROUP, epic);
				await submitRequestUpdate(page, epic);
				await adminApproveUpdate(adminPage, email, epic);
				await reloadDashboardWithMe(page);
				await expect(
					page.locator(`[data-testid="dashboard-group-chip"][data-key="${SCOPE_GROUP}"]`)
				).toBeVisible();

				await page.getByTestId('dashboard-link-password').click();
				await waitForPageShell(page, 'password-page');
				await page.getByTestId('password-current').fill('WrongCurrentPass!');
				await page.getByTestId('password-new').fill(newPassword);
				await page.getByTestId('password-confirm').fill(newPassword);
				await page.getByTestId('password-submit').click();
				await page.getByTestId('confirm-modal-confirm').click();
				await expect(page.getByTestId('password-page')).toBeVisible();

				await page.getByTestId('password-current').fill(password);
				await page.getByTestId('password-submit').click();
				await waitForPasswordChangeSignOut(page);

				await expectStillSignedOut(page);
				await startUserSession(page, { email, password: newPassword });
				await expect(page.getByTestId('dashboard-page')).toBeVisible();

				await page.getByTestId('nav-logout').click();
				await suPage.goto('/superuser');
				await openUserDetailFromSuperuser(suPage, email);
				await suPage.getByTestId('user-detail-delete-btn').click();
				await suPage.getByTestId('confirm-modal-confirm').click();
				userId = undefined;

				await expectStillSignedOut(page);
			} finally {
				if (userId) await deleteUserById(suRequest, userId).catch(() => undefined);
			}
		});
	}
);
