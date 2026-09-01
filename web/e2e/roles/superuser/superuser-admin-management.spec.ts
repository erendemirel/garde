import { test, expect } from '../../helpers/fixtures';
import { describeTags, TAG } from '../../helpers/tags';
import { e2eAdmin } from '../../helpers/auth';
import {
	createEphemeralUser,
	deleteUserById,
	restoreSeedAdminAccess
} from '../../helpers/userApi';
import { waitForAdminManagement, waitForPageShell } from '../../helpers/waits';

async function waitForToastGone(page: import('@playwright/test').Page) {
	await expect(page.getByTestId('toast')).toBeHidden({ timeout: 7000 });
}

async function openAdminManagement(page: import('@playwright/test').Page) {
	await page.goto('/superuser?tab=admin-management');
	await waitForPageShell(page, 'superuser-admin-management-panel');
	await waitForAdminManagement(page);
}

function adminRow(page: import('@playwright/test').Page, email: string) {
	return page.locator(`[data-testid="admin-mgmt-row"][data-admin-email="${email}"]`);
}

/**
 * Admin-User Management. Admins come from config (seed admin only in e2e).
 * Scope mutation adds/removes a unique group on seed admin, then restores seed groups.
 */
test.describe('Superuser admin-user management', describeTags(TAG.superuser, TAG.admin, TAG.focused), () => {
	// Serial: mutate seed admin group membership; avoid racing other workers on that map.
	test.describe.configure({ mode: 'serial' });

	test('lists the seed admin and opens the manageable-users modal', async ({
		superuserPage: page
	}) => {
		await openAdminManagement(page);

		await page.getByTestId('admin-mgmt-search').fill(e2eAdmin.email);
		const row = adminRow(page, e2eAdmin.email);
		await expect(row).toBeVisible();
		await expect(row.getByTestId('admin-mgmt-row-email')).toHaveText(e2eAdmin.email);
		await expect(row.getByTestId('admin-mgmt-row-count')).toBeVisible();

		await row.getByTestId('admin-mgmt-view-users').click();
		await expect(page.getByTestId('admin-mgmt-users-modal')).toBeVisible();
		await expect(page.getByTestId('admin-mgmt-users-summary')).toBeVisible();

		const list = page.getByTestId('admin-mgmt-users-list');
		const empty = page.getByTestId('admin-mgmt-users-empty');
		await expect(list.or(empty).first()).toBeVisible();

		await page.getByTestId('admin-mgmt-users-close').click();
		await expect(page.getByTestId('admin-mgmt-users-modal')).toHaveCount(0);
	});

	test('editing admin groups expands management scope to a shared-group user', async ({
		superuserPage: page,
		suRequest,
		uniqueSuffix
	}) => {
		const groupName = `e2e_adm_scope_${uniqueSuffix}`;
		let ephemeralId: string | undefined;

		try {
			await restoreSeedAdminAccess(suRequest).catch(() => undefined);

			const createGroup = await suRequest.post('/api/admin/groups', {
				data: { name: groupName, definition: 'E2E admin management scope' }
			});
			expect(createGroup.ok()).toBeTruthy();

			const target = await createEphemeralUser(suRequest, `adm_${uniqueSuffix}`, {
				groups: [groupName]
			});
			ephemeralId = target.id;

			await openAdminManagement(page);
			await page.getByTestId('admin-mgmt-search').fill(e2eAdmin.email);
			const row = adminRow(page, e2eAdmin.email);
			await expect(row).toBeVisible();

			await row.getByTestId('admin-mgmt-edit-groups').click();
			await expect(page.getByTestId('admin-mgmt-groups-modal')).toBeVisible();

			const ms = page.locator('[data-testid="multiselect"][data-label="Groups"]');
			await ms.getByTestId('multiselect-input').fill(groupName);
			await ms.locator(`[data-testid="multiselect-option"][data-key="${groupName}"]`).click();
			await expect(
				ms.locator(`[data-testid="multiselect-chip"][data-key="${groupName}"]`)
			).toHaveAttribute('data-state', 'added');

			await page.getByTestId('admin-mgmt-groups-save').click();
			await expect(page.getByTestId('confirm-modal-message')).toBeVisible();
			await page.getByTestId('confirm-modal-confirm').click();
			await expect(page.getByTestId('toast')).toContainText(e2eAdmin.email);
			await waitForToastGone(page);
			await expect(page.getByTestId('admin-mgmt-groups-modal')).toHaveCount(0);

			await page.getByTestId('admin-mgmt-search').fill(e2eAdmin.email);
			await expect(adminRow(page, e2eAdmin.email)).toBeVisible();
			await adminRow(page, e2eAdmin.email).getByTestId('admin-mgmt-view-users').click();
			await expect(page.getByTestId('admin-mgmt-users-modal')).toBeVisible();
			await page.getByTestId('admin-mgmt-users-search').fill(target.email);
			await expect(
				page.locator(
					`[data-testid="admin-mgmt-users-item"][data-user-email="${target.email}"]`
				)
			).toBeVisible();
			await page.getByTestId('admin-mgmt-users-close').click();

			await adminRow(page, e2eAdmin.email).getByTestId('admin-mgmt-edit-groups').click();
			await expect(page.getByTestId('admin-mgmt-groups-modal')).toBeVisible();
			await ms
				.locator(
					`[data-testid="multiselect-chip"][data-key="${groupName}"][data-state="selected"]`
				)
				.click();
			await expect(page.getByTestId('change-summary-removed')).toBeVisible();
			await page.getByTestId('admin-mgmt-groups-save').click();
			await page.getByTestId('confirm-modal-confirm').click();
			await expect(page.getByTestId('toast')).toContainText(e2eAdmin.email);
			await waitForToastGone(page);
		} finally {
			await restoreSeedAdminAccess(suRequest).catch(() => undefined);
			if (ephemeralId) {
				await deleteUserById(suRequest, ephemeralId).catch(() => undefined);
			}
			await suRequest
				.delete(`/api/admin/groups/${encodeURIComponent(groupName)}`)
				.catch(() => undefined);
		}
	});
});
