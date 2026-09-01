import { test, expect } from '../helpers/fixtures';
import { e2eAdmin, loginViaRequest, startUserSession } from '../helpers/auth';
import {
	addVisibilityInMatrix,
	adminApproveUpdate,
	adminRejectUpdate,
	cleanupCatalog,
	createCatalogItem,
	openRequestUpdate,
	patchUserMaps,
	reloadDashboardWithMe,
	removeVisibilityInMatrix,
	stagePermissionAddByName,
	stagePermissionRemoveByName,
	submitRequestUpdate,
	VISIBILITY_GROUP,
	type JourneyActOptions
} from '../helpers/journeys';
import { describeTags, TAG } from '../helpers/tags';
import { createEphemeralUser, deleteUserById } from '../helpers/userApi';
import {
	waitForPageShell,
	waitForRequestUpdateCatalog,
	waitForOutOfScopeDenied,
	LOAD_TIMEOUT,
	REDIRECT_TIMEOUT
} from '../helpers/waits';

const epic: JourneyActOptions = { outcomesOnly: true };

test.describe(
	'Epic: catalog to access',
	describeTags(TAG.epic, TAG.catalog, TAG.requestUpdate, TAG.admin, TAG.superuser),
	() => {
		test.setTimeout(180_000);

		test('permission visibility journey with negative branches', async ({
			browser,
			adminPage,
			superuserPage: suPage,
			suRequest,
			uniqueSuffix
		}) => {
			const permissionName = `e2e_epic_perm_${uniqueSuffix}`;
			const isolatedGroup = `e2e_epic_iso_${uniqueSuffix}`;
			let mainUserId: string | undefined;
			let isolatedUserId: string | undefined;

			try {
				await suPage.goto('/superuser');
				await waitForPageShell(suPage, 'superuser-page');
				await createCatalogItem(suPage, 'permissions', permissionName, 'Epic catalog permission', epic);
				await addVisibilityInMatrix(suPage, permissionName, VISIBILITY_GROUP, epic);

				const mainUser = await createEphemeralUser(suRequest, `epic_cat_${uniqueSuffix}`, {
					groups: [VISIBILITY_GROUP]
				});
				mainUserId = mainUser.id;

				const userContext = await browser.newContext();
				const userPage = await userContext.newPage();
				await startUserSession(userPage, mainUser);

				await openRequestUpdate(userPage);
				await stagePermissionAddByName(userPage, permissionName, epic);
				await submitRequestUpdate(userPage, epic);
				await reloadDashboardWithMe(userPage);
				await expect(userPage.getByTestId('dashboard-pending-update')).toBeVisible();

				await adminRejectUpdate(adminPage, mainUser.email, epic);
				await reloadDashboardWithMe(userPage);
				await expect(
					userPage.locator(`[data-testid="dashboard-permission-chip"][data-key="${permissionName}"]`)
				).toHaveCount(0);

				await openRequestUpdate(userPage);
				await stagePermissionAddByName(userPage, permissionName, epic);
				await submitRequestUpdate(userPage, epic);
				await adminApproveUpdate(adminPage, mainUser.email, epic);
				await reloadDashboardWithMe(userPage);
				await expect(
					userPage.locator(`[data-testid="dashboard-permission-chip"][data-key="${permissionName}"]`)
				).toBeVisible();

				await patchUserMaps(suRequest, mainUser.id, {
					permissions: { [permissionName]: true }
				});
				await openRequestUpdate(userPage);
				await stagePermissionRemoveByName(userPage, permissionName);
				await submitRequestUpdate(userPage, epic);

				await adminApproveUpdate(adminPage, mainUser.email, epic);

				const createGroup = await suRequest.post('/api/admin/groups', {
					data: { name: isolatedGroup, definition: 'Epic isolated group' }
				});
				expect(createGroup.ok()).toBeTruthy();
				const isolated = await createEphemeralUser(suRequest, `epic_iso_u_${uniqueSuffix}`, {
					groups: [isolatedGroup]
				});
				isolatedUserId = isolated.id;

				const adminProbe = await browser.newContext();
				const probePage = await adminProbe.newPage();
				await loginViaRequest(probePage.request, e2eAdmin);
				await waitForOutOfScopeDenied(probePage, isolated.id);
				await adminProbe.close();

				await removeVisibilityInMatrix(suPage, permissionName, VISIBILITY_GROUP, epic);
				await userPage.getByTestId('dashboard-link-request-update').click();
				await waitForPageShell(userPage, 'request-update-page');
				await waitForRequestUpdateCatalog(userPage);
				const ms = userPage.locator('[data-testid="multiselect"][data-label="Permissions"]');
				await ms.getByTestId('multiselect-input').fill(permissionName);
				await expect(
					ms.locator(`[data-testid="multiselect-option"][data-key="${permissionName}"]`)
				).toHaveCount(0);

				await userContext.close();
			} finally {
				if (mainUserId) await deleteUserById(suRequest, mainUserId).catch(() => undefined);
				if (isolatedUserId) await deleteUserById(suRequest, isolatedUserId).catch(() => undefined);
				await suRequest
					.delete(`/api/admin/groups/${encodeURIComponent(isolatedGroup)}`)
					.catch(() => undefined);
				await cleanupCatalog(suRequest, permissionName);
			}
		});
	}
);
