import { test, expect } from '../helpers/fixtures';
import { e2eAdmin, startUserSession } from '../helpers/auth';
import {
	adminApproveUpdate,
	openRequestUpdate,
	reloadDashboardWithMe,
	SCOPE_GROUP,
	stageGroupAddByName,
	submitRequestUpdate,
	type JourneyActOptions
} from '../helpers/journeys';
import { describeTags, TAG } from '../helpers/tags';
import {
	createEphemeralUser,
	deleteUserById,
	ensureSeedAdminReady,
	openUserDetailFromAdmin,
	restoreSeedAdminAccess
} from '../helpers/userApi';
import { waitForPageShell, waitForSignedOut, matchUserUpdate, LOAD_TIMEOUT, REDIRECT_TIMEOUT } from '../helpers/waits';

const epic: JourneyActOptions = { outcomesOnly: true };

async function openAdminManagement(page: import('@playwright/test').Page) {
	await page.goto('/superuser?tab=admin-management');
	await waitForPageShell(page, 'superuser-admin-management-panel');
}

function adminRow(page: import('@playwright/test').Page, email: string) {
	return page.locator(`[data-testid="admin-mgmt-row"][data-admin-email="${email}"]`);
}

test.describe(
	'Epic: scope alignment',
	describeTags(TAG.epic, TAG.admin, TAG.superuser, TAG.activeSession, TAG.requestUpdate),
	() => {
		test.setTimeout(180_000);

		test('admin gains scope then manages user through lock cycle', async ({
			browser,
			adminPage,
			superuserPage: suPage,
			suRequest,
			uniqueSuffix
		}) => {
			const isolatedGroup = `e2e_epic_scope_${uniqueSuffix}`;
			let userId: string | undefined;

			try {
				await ensureSeedAdminReady(suRequest);

				const createGroup = await suRequest.post('/api/admin/groups', {
					data: { name: isolatedGroup, definition: 'Epic scope alignment group' }
				});
				expect(createGroup.ok()).toBeTruthy();

				const user = await createEphemeralUser(suRequest, `epic_scope_u_${uniqueSuffix}`, {
					groups: [isolatedGroup]
				});
				userId = user.id;

				await adminPage.goto(`/admin/users/${user.id}`);
				await expect(adminPage.getByTestId('login-page')).toBeVisible({ timeout: REDIRECT_TIMEOUT });

				const userContext = await browser.newContext();
				const userPage = await userContext.newPage();
				await startUserSession(userPage, user);
				await openRequestUpdate(userPage);
				await stageGroupAddByName(userPage, SCOPE_GROUP, epic);
				await submitRequestUpdate(userPage, epic);

				const adminProbe = await browser.newContext();
				const probePage = await adminProbe.newPage();
				await startUserSession(probePage, e2eAdmin);
				await probePage.goto(`/admin/users/${user.id}`);
				await expect(probePage.getByTestId('login-page')).toBeVisible({ timeout: REDIRECT_TIMEOUT });
				await adminProbe.close();

				await openAdminManagement(suPage);
				await ensureSeedAdminReady(suRequest);
				await suPage.getByTestId('admin-mgmt-search').fill(e2eAdmin.email);
				await adminRow(suPage, e2eAdmin.email).getByTestId('admin-mgmt-edit-groups').click();
				const ms = suPage.locator('[data-testid="multiselect"][data-label="Groups"]');
				await ms.getByTestId('multiselect-input').fill(isolatedGroup);
				await ms.locator(`[data-testid="multiselect-option"][data-key="${isolatedGroup}"]`).click();
				const adminScopeResponse = suPage.waitForResponse(matchUserUpdate, { timeout: LOAD_TIMEOUT });
				await suPage.getByTestId('admin-mgmt-groups-save').click();
				await suPage.getByTestId('confirm-modal-confirm').click();
				await adminScopeResponse;
				await expect(suPage.getByTestId('admin-mgmt-groups-modal')).toHaveCount(0);

				const adminContext = await browser.newContext();
				const scopedAdmin = await adminContext.newPage();
				await startUserSession(scopedAdmin, e2eAdmin);

				await adminApproveUpdate(scopedAdmin, user.email, epic);
				await reloadDashboardWithMe(userPage);
				await expect(
					userPage.locator(`[data-testid="dashboard-group-chip"][data-key="${SCOPE_GROUP}"]`)
				).toBeVisible();

				await scopedAdmin.goto('/admin');
				await openUserDetailFromAdmin(scopedAdmin, user.email);
				const lockResponse = scopedAdmin.waitForResponse(matchUserUpdate, { timeout: LOAD_TIMEOUT });
				await scopedAdmin.getByTestId('user-detail-lock-btn').click();
				await scopedAdmin.getByTestId('confirm-modal-confirm').click();
				await lockResponse;

				await waitForSignedOut(userPage, { reload: true });

				await scopedAdmin.getByTestId('user-detail-lock-btn').click();
				await scopedAdmin.getByTestId('confirm-modal-confirm').click();

				await startUserSession(userPage, user);
				await expect(
					userPage.locator(`[data-testid="dashboard-group-chip"][data-key="${SCOPE_GROUP}"]`)
				).toBeVisible();

				await userContext.close();
				await adminContext.close();
			} finally {
				await restoreSeedAdminAccess(suRequest).catch(() => undefined);
				if (userId) await deleteUserById(suRequest, userId).catch(() => undefined);
				await suRequest
					.delete(`/api/admin/groups/${encodeURIComponent(isolatedGroup)}`)
					.catch(() => undefined);
			}
		});
	}
);
