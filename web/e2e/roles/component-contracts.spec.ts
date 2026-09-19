import { test, expect } from '../helpers/fixtures';
import { describeTags, TAG } from '../helpers/tags';
import {
	assertToast,
	dismissToast,
	waitForAdminCatalog,
	waitForPageShell,
	waitForSuperuserCatalog,
	waitForUserDetail,
	waitForUsersList
} from '../helpers/waits';
import { SCOPE_GROUP } from '../helpers/catalog';
import { cleanupTenantKeys, selectIssueScope } from '../helpers/apiKeys';
import { openUserDetailFromSuperuser, patchUserMaps } from '../helpers/userApi';

/**
 * Shared UI contracts — Modal/MultiSelect/tabs/icon/event chains.
 */
test.describe(
	'Component contracts (Svelte upgrade locks)',
	describeTags(TAG.focused, TAG.superuser, TAG.admin),
	() => {
		test('user-detail save chain: multiselect → confirm → toast', async ({
			superuserPage: page,
			suRequest,
			ephemeralUser,
			uniqueSuffix
		}) => {
			const permissionName = `e2e_cc_perm_${uniqueSuffix}`;
			try {
				await page.goto('/superuser?tab=permissions');
				await waitForSuperuserCatalog(page);
				await page.getByTestId('superuser-catalog-create').click();
				await page.getByTestId('superuser-catalog-item-name').fill(permissionName);
				await page
					.getByTestId('superuser-catalog-item-definition')
					.fill('E2E component-contract permission');
				await page.getByTestId('superuser-catalog-item-save').click();
				await assertToast(page, permissionName);

				await openUserDetailFromSuperuser(page, ephemeralUser.email);

				const ms = page.locator('[data-testid="multiselect"][data-label="Permissions"]');
				await ms.getByTestId('multiselect-input').fill(permissionName);
				await ms
					.locator(`[data-testid="multiselect-option"][data-key="${permissionName}"]`)
					.click();
				await expect(
					ms.locator(`[data-testid="multiselect-chip"][data-key="${permissionName}"]`)
				).toHaveAttribute('data-state', 'added');

				await page.getByTestId('user-detail-save').click();
				await expect(page.getByTestId('confirm-modal-message')).toBeVisible();
				await page.getByTestId('confirm-modal-confirm').click();
				await expect(page.getByTestId('toast')).toContainText(/Updated/i, { timeout: 5_000 });
				await dismissToast(page);
				await expect(
					ms.locator(
						`[data-testid="multiselect-chip"][data-key="${permissionName}"][data-state="selected"]`
					)
				).toBeVisible();
			} finally {
				await suRequest
					.delete(`/api/admin/permissions/${encodeURIComponent(permissionName)}`)
					.catch(() => undefined);
			}
		});

		test('catalog membership chain: remote search → save → confirm → toast', async ({
			adminPage: page,
			ephemeralUser
		}) => {
			await page.goto('/admin');
			await page.getByTestId('admin-tab-groups').click();
			await waitForAdminCatalog(page);
			await page.getByTestId('admin-catalog-search').fill(SCOPE_GROUP);
			const row = page.locator(
				`[data-testid="admin-catalog-row"][data-item-name="${SCOPE_GROUP}"]`
			);
			await expect(row).toBeVisible();
			await row.getByTestId('admin-catalog-manage').click();
			await expect(page.getByTestId('admin-catalog-manage-modal')).toBeVisible();

			const ms = page.locator('[data-testid="multiselect"][data-label="Users"]');
			const searchResponse = page.waitForResponse(
				(res) =>
					res.url().includes('/api/users') &&
					res.url().includes('q=') &&
					res.request().method() === 'GET'
			);
			await ms.getByTestId('multiselect-input').fill(ephemeralUser.email);
			await searchResponse;
			await ms
				.locator(`[data-testid="multiselect-option"][data-key="${ephemeralUser.id}"]`)
				.click();
			await expect(
				ms.locator(`[data-testid="multiselect-chip"][data-key="${ephemeralUser.id}"]`)
			).toHaveAttribute('data-state', 'added');

			await page.getByTestId('admin-catalog-manage-save').click();
			await expect(page.getByTestId('confirm-modal-message')).toBeVisible();
			await page.getByTestId('confirm-modal-confirm').click();
			await expect(page.getByTestId('toast')).toContainText(
				`Updated group "${SCOPE_GROUP}" members`,
				{ timeout: 5_000 }
			);
			await dismissToast(page);

			await row.getByTestId('admin-catalog-manage').click();
			await expect(
				page.locator(
					`[data-testid="multiselect-chip"][data-key="${ephemeralUser.id}"][data-state="selected"]`
				)
			).toBeVisible();
			await page.getByTestId('admin-catalog-manage-cancel').click();
		});

		test('confirm Escape and overlay cancel without applying', async ({
			superuserPage: page,
			ephemeralUser
		}) => {
			await page.goto('/superuser');
			await openUserDetailFromSuperuser(page, ephemeralUser.email);
			await waitForUserDetail(page);

			await page.getByTestId('user-detail-revoke-btn').click();
			await expect(page.getByTestId('confirm-modal-message')).toBeVisible();
			await page.getByTestId('confirm-modal-message').click();
			await page.keyboard.press('Escape');
			await expect(page.getByTestId('confirm-modal-message')).toHaveCount(0);
			await expect(page.getByTestId('toast')).toBeHidden();

			await page.getByTestId('user-detail-revoke-btn').click();
			await expect(page.getByTestId('confirm-modal-message')).toBeVisible();
			// Overlay sits behind the dialog; force a corner click so content does not intercept.
			await page.getByRole('button', { name: 'Close dialog' }).click({
				force: true,
				position: { x: 2, y: 2 }
			});
			await expect(page.getByTestId('confirm-modal-message')).toHaveCount(0);
			await expect(page.getByTestId('toast')).toBeHidden();
		});

		test('confirm then toast without click hang', async ({
			superuserPage: page,
			ephemeralUser
		}) => {
			await page.goto('/superuser');
			await openUserDetailFromSuperuser(page, ephemeralUser.email);
			await page.getByTestId('user-detail-lock-btn').click();
			await expect(page.getByTestId('confirm-modal-message')).toBeVisible();
			await page.getByTestId('confirm-modal-confirm').click();
			await expect(page.getByTestId('toast')).toContainText(/locked|unlocked|Updated/i, {
				timeout: 5_000
			});
			await dismissToast(page);
		});

		test('manage modal header-end close discards staged members', async ({
			superuserPage: page,
			ephemeralUser,
			suRequest,
			uniqueSuffix
		}) => {
			const groupName = `e2e_cc_grp_${uniqueSuffix}`;
			try {
				const createRes = await suRequest.post('/api/admin/groups', {
					data: { name: groupName, definition: 'E2E contract manage-close' }
				});
				expect(createRes.ok()).toBeTruthy();

				await page.goto('/superuser?tab=groups');
				await waitForSuperuserCatalog(page);
				await page.getByTestId('superuser-catalog-search').fill(groupName);
				const row = page.locator(
					`[data-testid="superuser-catalog-row"][data-item-name="${groupName}"]`
				);
				await expect(row).toBeVisible();
				await row.getByTestId('superuser-catalog-manage').click();
				await expect(page.getByTestId('superuser-catalog-manage-modal')).toBeVisible();

				const ms = page.locator('[data-testid="multiselect"][data-label="Users"]');
				const searchResponse = page.waitForResponse(
					(res) =>
						res.url().includes('/api/users') &&
						res.url().includes('q=') &&
						res.request().method() === 'GET'
				);
				await ms.getByTestId('multiselect-input').fill(ephemeralUser.email);
				await searchResponse;
				await ms
					.locator(`[data-testid="multiselect-option"][data-key="${ephemeralUser.id}"]`)
					.click();
				await expect(
					ms.locator(`[data-testid="multiselect-chip"][data-key="${ephemeralUser.id}"]`)
				).toHaveAttribute('data-state', 'added');

				await page.getByTestId('superuser-catalog-manage-close').click();
				await expect(page.getByTestId('superuser-catalog-manage-modal')).toHaveCount(0);

				await row.getByTestId('superuser-catalog-manage').click();
				await expect(page.getByTestId('superuser-catalog-manage-modal')).toBeVisible();
				await expect(
					page.locator(
						`[data-testid="multiselect-chip"][data-key="${ephemeralUser.id}"]`
					)
				).toHaveCount(0);
				await page.getByTestId('superuser-catalog-manage-close').click();
			} finally {
				await suRequest
					.delete(`/api/admin/groups/${encodeURIComponent(groupName)}`)
					.catch(() => undefined);
			}
		});

		test('multiselect remove then restore via chip and change-summary', async ({
			superuserPage: page,
			ephemeralUser,
			suRequest,
			uniqueSuffix
		}) => {
			const permissionName = `e2e_cc_restore_${uniqueSuffix}`;
			try {
				expect(
					(
						await suRequest.post('/api/admin/permissions', {
							data: { name: permissionName, definition: 'E2E restore contract' }
						})
					).ok()
				).toBeTruthy();
				await patchUserMaps(suRequest, ephemeralUser.id, {
					permissions: { [permissionName]: true }
				});

				await page.goto('/superuser');
				await openUserDetailFromSuperuser(page, ephemeralUser.email);
				const ms = page.locator('[data-testid="multiselect"][data-label="Permissions"]');
				const chip = ms.locator(
					`[data-testid="multiselect-chip"][data-key="${permissionName}"][data-state="selected"]`
				);
				await expect(chip).toBeVisible();
				await chip.click();
				await expect(
					ms.locator(
						`[data-testid="multiselect-chip"][data-key="${permissionName}"][data-state="removed"]`
					)
				).toBeVisible();
				await expect(page.getByTestId('change-summary-removed')).toBeVisible();

				await ms
					.locator(
						`[data-testid="multiselect-chip"][data-key="${permissionName}"][data-state="removed"]`
					)
					.click();
				await expect(
					ms.locator(
						`[data-testid="multiselect-chip"][data-key="${permissionName}"][data-state="selected"]`
					)
				).toBeVisible();
			} finally {
				await suRequest
					.delete(`/api/admin/permissions/${encodeURIComponent(permissionName)}`)
					.catch(() => undefined);
			}
		});

		test('multiselect keyboard add and Escape closes dropdown', async ({
			superuserPage: page,
			ephemeralUser,
			suRequest,
			uniqueSuffix
		}) => {
			const permissionName = `e2e_cc_kb_${uniqueSuffix}`;
			try {
				expect(
					(
						await suRequest.post('/api/admin/permissions', {
							data: { name: permissionName, definition: 'E2E keyboard contract' }
						})
					).ok()
				).toBeTruthy();

				await page.goto('/superuser');
				await openUserDetailFromSuperuser(page, ephemeralUser.email);
				const ms = page.locator('[data-testid="multiselect"][data-label="Permissions"]');
				const input = ms.getByTestId('multiselect-input');
				await input.fill(permissionName);
				await expect(
					ms.locator(`[data-testid="multiselect-option"][data-key="${permissionName}"]`)
				).toBeVisible();
				await input.press('ArrowDown');
				await input.press('Enter');
				await expect(
					ms.locator(`[data-testid="multiselect-chip"][data-key="${permissionName}"]`)
				).toHaveAttribute('data-state', 'added');
				await input.press('Escape');
				await expect(ms.getByTestId('multiselect-dropdown')).toHaveCount(0);
			} finally {
				await suRequest
					.delete(`/api/admin/permissions/${encodeURIComponent(permissionName)}`)
					.catch(() => undefined);
			}
		});

		test('superuser and admin tablist arrow keys update panel and URL', async ({
			superuserPage: suPage,
			adminPage
		}) => {
			await suPage.goto('/superuser?tab=users');
			await waitForPageShell(suPage, 'superuser-page');
			await waitForUsersList(suPage);
			await suPage.getByTestId('superuser-tab-users').focus();
			await suPage.keyboard.press('ArrowRight');
			await expect(suPage.getByTestId('superuser-tab-permissions')).toHaveAttribute(
				'aria-selected',
				'true'
			);
			await expect(suPage).toHaveURL(/tab=permissions/);
			await expect(suPage.getByTestId('superuser-panel-permissions')).toBeVisible();

			await suPage.getByTestId('superuser-tab-permissions').focus();
			await suPage.keyboard.press('ArrowLeft');
			await expect(suPage.getByTestId('superuser-tab-users')).toHaveAttribute(
				'aria-selected',
				'true'
			);
			await expect(suPage).toHaveURL(/tab=users/);

			await suPage.getByTestId('superuser-tab-users').focus();
			await suPage.keyboard.press('End');
			await expect(suPage.getByTestId('superuser-tab-api-keys')).toHaveAttribute(
				'aria-selected',
				'true'
			);
			await expect(suPage).toHaveURL(/tab=api-keys/);
			await expect(suPage.getByTestId('superuser-panel-api-keys')).toBeVisible();

			await suPage.getByTestId('superuser-tab-api-keys').focus();
			await suPage.keyboard.press('Home');
			await expect(suPage.getByTestId('superuser-tab-users')).toHaveAttribute(
				'aria-selected',
				'true'
			);
			await expect(suPage).toHaveURL(/tab=users/);

			await adminPage.goto('/admin');
			await waitForPageShell(adminPage, 'admin-page');
			await waitForUsersList(adminPage);
			await adminPage.getByTestId('admin-tab-users').focus();
			await adminPage.keyboard.press('ArrowRight');
			await expect(adminPage.getByTestId('admin-tab-permissions')).toHaveAttribute(
				'aria-selected',
				'true'
			);
			await expect(adminPage.getByTestId('admin-panel-permissions')).toBeVisible();

			await adminPage.getByTestId('admin-tab-users').focus();
			await adminPage.keyboard.press('End');
			await expect(adminPage.getByTestId('admin-tab-groups')).toHaveAttribute(
				'aria-selected',
				'true'
			);
			await expect(adminPage.getByTestId('admin-panel-groups')).toBeVisible();
			await adminPage.getByTestId('admin-tab-groups').focus();
			await adminPage.keyboard.press('Home');
			await expect(adminPage.getByTestId('admin-tab-users')).toHaveAttribute(
				'aria-selected',
				'true'
			);
			await expect(adminPage.getByTestId('admin-panel-users')).toBeVisible();
		});

		test('icon-backed controls remain operable', async ({
			superuserPage: page,
			regularUserPage
		}) => {
			await page.goto('/superuser');
			await waitForPageShell(page, 'superuser-page');
			await page.getByTestId('superuser-tab-admin-management').click();
			await expect(page.getByTestId('superuser-tab-admin-management')).toHaveAttribute(
				'aria-selected',
				'true'
			);
			await expect(page.getByTestId('superuser-admin-management-panel')).toBeVisible();

			await page.getByTestId('superuser-tab-api-keys').click();
			await expect(page.getByTestId('superuser-api-keys-panel')).toBeVisible();
			await page.getByTestId('api-keys-issue').click();
			await page.getByTestId('api-keys-issue-cancel').click();

			await expect(regularUserPage.getByTestId('nav-logout')).toBeVisible();
			await regularUserPage.getByTestId('nav-logout').click();
			await expect(regularUserPage.getByTestId('login-form')).toBeVisible();
		});

		test('api-key reveal stays open on Escape (non-dismissible)', async ({
			superuserPage: page,
			suRequest,
			uniqueSuffix
		}) => {
			const tenantId = `e2e_cc_reveal_${uniqueSuffix}`;
			try {
				await page.goto('/superuser?tab=api-keys');
				await expect(page.getByTestId('superuser-api-keys-panel')).toBeVisible();
				await page.getByTestId('api-keys-issue').click();
				await page.getByTestId('api-keys-issue-tenant').fill(tenantId);
				await page.getByTestId('api-keys-issue-name').fill('cc_reveal');
				await selectIssueScope(page, 'validate');
				await page.getByTestId('api-keys-issue-submit').click();
				await assertToast(page, 'cc_reveal');
				await expect(page.getByTestId('api-keys-reveal-modal')).toBeVisible();
				await page.keyboard.press('Escape');
				await expect(page.getByTestId('api-keys-reveal-modal')).toBeVisible();
				await page.getByTestId('api-keys-reveal-ack').check();
				await page.getByTestId('api-keys-reveal-done').click();
			} finally {
				await cleanupTenantKeys(suRequest, tenantId);
			}
		});

		test('toast dismiss clears without waiting auto-hide', async ({
			superuserPage: page,
			uniqueSuffix,
			suRequest
		}) => {
			const permissionName = `e2e_cc_toast_${uniqueSuffix}`;
			try {
				await page.goto('/superuser?tab=permissions');
				await waitForSuperuserCatalog(page);
				await page.getByTestId('superuser-catalog-create').click();
				await page.getByTestId('superuser-catalog-item-name').fill(permissionName);
				await page.getByTestId('superuser-catalog-item-definition').fill('toast contract');
				await page.getByTestId('superuser-catalog-item-save').click();
				await expect(page.getByTestId('toast')).toBeVisible();
				await expect(page.getByTestId('toast')).toHaveAttribute('data-toast-type', 'success');
				await page.getByTestId('toast-dismiss').click();
				await expect(page.getByTestId('toast')).toBeHidden();
			} finally {
				await suRequest
					.delete(`/api/admin/permissions/${encodeURIComponent(permissionName)}`)
					.catch(() => undefined);
			}
		});
	}
);
