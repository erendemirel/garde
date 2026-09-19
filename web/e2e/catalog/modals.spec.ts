import { test, expect } from '../helpers/fixtures';
import { describeTags, TAG } from '../helpers/tags';
import { waitForAdminCatalog, waitForPageShell, waitForSuperuserCatalog, waitForVisibilityPanel } from '../helpers/waits';
import { SCOPE_GROUP } from '../helpers/catalog';

test.describe('Superuser catalog modals', describeTags(TAG.catalog, TAG.superuser, TAG.focused), () => {
	test('create modal cancel closes without creating', async ({ superuserPage: page, uniqueSuffix }) => {
		const groupName = `e2e_cancel_create_${uniqueSuffix}`;

		await page.goto('/superuser?tab=groups');
		await waitForPageShell(page, 'superuser-page');
		await waitForSuperuserCatalog(page);

		await page.getByTestId('superuser-catalog-create').click();
		await expect(page.getByTestId('superuser-catalog-item-modal')).toBeVisible();
		await page.getByTestId('superuser-catalog-item-name').fill(groupName);
		await page.getByTestId('superuser-catalog-item-definition').fill('Should not be created');
		await page.getByTestId('superuser-catalog-item-cancel').click();
		await expect(page.getByTestId('superuser-catalog-item-modal')).toHaveCount(0);

		await page.getByTestId('superuser-catalog-search').fill(groupName);
		await expect(
			page.locator(`[data-testid="superuser-catalog-row"][data-item-name="${groupName}"]`)
		).toHaveCount(0);
	});

	test('edit modal cancel keeps original definition', async ({
		superuserPage: page,
		uniqueSuffix,
		suRequest
	}) => {
		const groupName = `e2e_cancel_edit_${uniqueSuffix}`;
		const original = 'Original definition for cancel test';

		try {
			const createGroup = await suRequest.post('/api/admin/groups', {
				data: { name: groupName, definition: original }
			});
			expect(createGroup.ok()).toBeTruthy();

			await page.goto('/superuser?tab=groups');
			await waitForPageShell(page, 'superuser-page');
			await waitForSuperuserCatalog(page);
			await page.getByTestId('superuser-catalog-search').fill(groupName);

			const row = page.locator(
				`[data-testid="superuser-catalog-row"][data-item-name="${groupName}"]`
			);
			await expect(row).toBeVisible();
			await row.getByTestId('superuser-catalog-edit').click();
			await expect(page.getByTestId('superuser-catalog-item-modal')).toBeVisible();
			await page.getByTestId('superuser-catalog-item-definition').fill('Changed but cancelled');
			await page.getByTestId('superuser-catalog-item-cancel').click();
			await expect(page.getByTestId('superuser-catalog-item-modal')).toHaveCount(0);

			await row.getByTestId('superuser-catalog-edit').click();
			await expect(page.getByTestId('superuser-catalog-item-definition')).toHaveValue(original);
			await page.getByTestId('superuser-catalog-item-cancel').click();
		} finally {
			await suRequest
				.delete(`/api/admin/groups/${encodeURIComponent(groupName)}`)
				.catch(() => undefined);
		}
	});

	test('manage modal cancel closes without saving membership', async ({
		superuserPage: page,
		ephemeralUser,
		uniqueSuffix,
		suRequest
	}) => {
		const groupName = `e2e_cancel_mgmt_${uniqueSuffix}`;

		try {
			const createGroup = await suRequest.post('/api/admin/groups', {
				data: { name: groupName, definition: 'E2E manage cancel' }
			});
			expect(createGroup.ok()).toBeTruthy();

			await page.goto('/superuser?tab=groups');
			await waitForSuperuserCatalog(page);
			await page.getByTestId('superuser-catalog-search').fill(groupName);

			const row = page.locator(
				`[data-testid="superuser-catalog-row"][data-item-name="${groupName}"]`
			);
			await row.getByTestId('superuser-catalog-manage').click();
			await expect(page.getByTestId('superuser-catalog-manage-modal')).toBeVisible();

			const ms = page.locator('[data-testid="multiselect"][data-label="Users"]');
			await ms.getByTestId('multiselect-input').fill(ephemeralUser.email);
			await ms
				.locator(`[data-testid="multiselect-option"][data-key="${ephemeralUser.id}"]`)
				.click();
			await expect(
				ms.locator(`[data-testid="multiselect-chip"][data-key="${ephemeralUser.id}"]`)
			).toHaveAttribute('data-state', 'added');

			await page.getByTestId('superuser-catalog-manage-cancel').click();
			await expect(page.getByTestId('superuser-catalog-manage-modal')).toHaveCount(0);

			await row.getByTestId('superuser-catalog-manage').click();
			await expect(
				page.locator(
					`[data-testid="multiselect-chip"][data-key="${ephemeralUser.id}"][data-state="selected"]`
				)
			).toHaveCount(0);
			await page.getByTestId('superuser-catalog-manage-cancel').click();
		} finally {
			await suRequest
				.delete(`/api/admin/groups/${encodeURIComponent(groupName)}`)
				.catch(() => undefined);
		}
	});
});

test.describe('Admin catalog modals', describeTags(TAG.catalog, TAG.admin, TAG.focused), () => {
	test('manage modal cancel closes without saving membership', async ({
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
		await ms.getByTestId('multiselect-input').fill(ephemeralUser.email);
		await ms
			.locator(`[data-testid="multiselect-option"][data-key="${ephemeralUser.id}"]`)
			.click();
		await expect(
			ms.locator(`[data-testid="multiselect-chip"][data-key="${ephemeralUser.id}"]`)
		).toHaveAttribute('data-state', 'added');

		await page.getByTestId('admin-catalog-manage-cancel').click();
		await expect(page.getByTestId('admin-catalog-manage-modal')).toHaveCount(0);

		await row.getByTestId('admin-catalog-manage').click();
		await expect(
			page.locator(
				`[data-testid="multiselect-chip"][data-key="${ephemeralUser.id}"][data-state="selected"]`
			)
		).toHaveCount(0);
		await page.getByTestId('admin-catalog-manage-cancel').click();
	});
});

test.describe('Visibility manage modals', describeTags(TAG.catalog, TAG.superuser, TAG.focused), () => {
	test('manage modal cancel closes without saving visibility', async ({
		superuserPage: page,
		suRequest,
		uniqueSuffix
	}) => {
		const permissionName = `e2e_vis_cancel_${uniqueSuffix}`;
		const groupName = `e2e_vis_cg_${uniqueSuffix}`;

		try {
			const createPerm = await suRequest.post('/api/admin/permissions', {
				data: { name: permissionName, definition: 'E2E visibility cancel' }
			});
			expect(createPerm.ok()).toBeTruthy();
			const createGroup = await suRequest.post('/api/admin/groups', {
				data: { name: groupName, definition: 'E2E visibility cancel group' }
			});
			expect(createGroup.ok()).toBeTruthy();

			await page.goto('/superuser?tab=visibility');
			await waitForPageShell(page, 'superuser-visibility-panel');
			await waitForVisibilityPanel(page);
			await page.getByTestId('superuser-visibility-view-list').click();
			await page.getByTestId('superuser-visibility-search').fill(permissionName);

			const row = page.locator(
				`[data-testid="superuser-visibility-list-row"][data-permission-name="${permissionName}"]`
			);
			await expect(row).toBeVisible();
			await row.getByTestId('superuser-visibility-manage').click();
			await expect(page.getByTestId('superuser-visibility-manage-modal')).toBeVisible();

			const ms = page.locator('[data-testid="multiselect"][data-label="Groups"]');
			await ms.getByTestId('multiselect-input').fill(groupName);
			await ms.locator(`[data-testid="multiselect-option"][data-key="${groupName}"]`).click();
			await expect(
				ms.locator(`[data-testid="multiselect-chip"][data-key="${groupName}"]`)
			).toHaveAttribute('data-state', 'added');

			await page.getByTestId('superuser-visibility-manage-cancel').click();
			await expect(page.getByTestId('superuser-visibility-manage-modal')).toHaveCount(0);
			await expect(row.getByTestId('superuser-visibility-count')).toHaveText('0');
		} finally {
			await suRequest
				.delete(`/api/admin/permissions/${encodeURIComponent(permissionName)}`)
				.catch(() => undefined);
			await suRequest
				.delete(`/api/admin/groups/${encodeURIComponent(groupName)}`)
				.catch(() => undefined);
		}
	});
});
