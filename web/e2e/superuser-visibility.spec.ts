import { test, expect } from './helpers/fixtures';

async function waitForToastGone(page: import('@playwright/test').Page) {
	await expect(page.getByTestId('toast')).toBeHidden({ timeout: 7000 });
}

async function createCatalogItem(
	page: import('@playwright/test').Page,
	tab: 'permissions' | 'groups',
	name: string,
	definition: string
) {
	await page.getByTestId(`superuser-tab-${tab}`).click();
	await page.getByTestId('superuser-catalog-create').click();
	await page.getByTestId('superuser-catalog-item-name').fill(name);
	await page.getByTestId('superuser-catalog-item-definition').fill(definition);
	await page.getByTestId('superuser-catalog-item-save').click();
	await expect(page.getByTestId('toast')).toContainText(name);
	await waitForToastGone(page);
	await expect(page.getByTestId('superuser-catalog-item-modal')).toHaveCount(0);
}

async function deleteCatalogItemIfPresent(
	page: import('@playwright/test').Page,
	tab: 'permissions' | 'groups',
	name: string
) {
	await page.getByTestId(`superuser-tab-${tab}`).click();
	await page.getByTestId('superuser-catalog-search').fill(name);
	const row = page.locator(`[data-testid="superuser-catalog-row"][data-item-name="${name}"]`);
	if ((await row.count()) === 0) return;
	await row.getByTestId('superuser-catalog-delete').click();
	await page.getByTestId('confirm-modal-confirm').click();
	await expect(row).toHaveCount(0);
}

/**
 * Permission Visibility tab — matrix + list manage flows with unique catalog fixtures.
 */
test.describe('Superuser permission visibility', () => {
	test('adds then removes a visibility mapping in matrix view', async ({
		superuserPage: page,
		uniqueSuffix
	}) => {
		const permissionName = `e2e_vis_perm_${uniqueSuffix}`;
		const groupName = `e2e_vis_group_${uniqueSuffix}`;

		try {
			await page.goto('/superuser');
			await createCatalogItem(page, 'permissions', permissionName, 'E2E visibility permission');
			await createCatalogItem(page, 'groups', groupName, 'E2E visibility group');

			await page.getByTestId('superuser-tab-visibility').click();
			await expect(page.getByTestId('superuser-visibility-panel')).toBeVisible();
			await page.getByTestId('superuser-visibility-view-matrix').click();
			await expect(page.getByTestId('superuser-visibility-matrix')).toBeVisible();

			await page.getByTestId('superuser-visibility-search').fill(permissionName);
			const cell = page.locator(
				`[data-testid="superuser-visibility-cell"][data-permission-name="${permissionName}"][data-group-name="${groupName}"]`
			);
			await expect(cell).toBeVisible();
			await expect(cell).toHaveAttribute('aria-pressed', 'false');

			await cell.click();
			await expect(page.getByTestId('toast')).toContainText(/Visibility/i);
			await waitForToastGone(page);
			await expect(cell).toHaveAttribute('aria-pressed', 'true');

			await cell.click();
			await expect(page.getByTestId('confirm-modal-message')).toContainText(permissionName);
			await page.getByTestId('confirm-modal-confirm').click();
			await expect(page.getByTestId('toast')).toContainText(/removed/i);
			await waitForToastGone(page);
			await expect(cell).toHaveAttribute('aria-pressed', 'false');
		} finally {
			try {
				await deleteCatalogItemIfPresent(page, 'permissions', permissionName);
				await deleteCatalogItemIfPresent(page, 'groups', groupName);
			} catch {
				/* ignore */
			}
		}
	});

	test('list view manage adds and removes group visibility', async ({
		superuserPage: page,
		uniqueSuffix
	}) => {
		const permissionName = `e2e_vis_list_${uniqueSuffix}`;
		const groupName = `e2e_vis_lg_${uniqueSuffix}`;

		try {
			await page.goto('/superuser');
			await createCatalogItem(page, 'permissions', permissionName, 'E2E list visibility permission');
			await createCatalogItem(page, 'groups', groupName, 'E2E list visibility group');

			await page.getByTestId('superuser-tab-visibility').click();
			await expect(page.getByTestId('superuser-visibility-panel')).toBeVisible();
			await page.getByTestId('superuser-visibility-view-list').click();
			await expect(page.getByTestId('superuser-visibility-list-table')).toBeVisible();

			await page.getByTestId('superuser-visibility-search').fill(permissionName);
			const row = page.locator(
				`[data-testid="superuser-visibility-list-row"][data-permission-name="${permissionName}"]`
			);
			await expect(row).toBeVisible();
			await expect(row.getByTestId('superuser-visibility-count')).toHaveText('0');

			await row.getByTestId('superuser-visibility-manage').click();
			await expect(page.getByTestId('superuser-visibility-manage-modal')).toBeVisible();

			const ms = page.locator('[data-testid="multiselect"][data-label="Groups"]');
			await ms.getByTestId('multiselect-input').fill(groupName);
			await ms.locator(`[data-testid="multiselect-option"][data-key="${groupName}"]`).click();
			await expect(
				ms.locator(`[data-testid="multiselect-chip"][data-key="${groupName}"]`)
			).toHaveAttribute('data-state', 'added');

			await page.getByTestId('superuser-visibility-manage-save').click();
			await expect(page.getByTestId('confirm-modal-message')).toContainText(permissionName);
			await page.getByTestId('confirm-modal-confirm').click();
			await expect(page.getByTestId('toast')).toContainText(
				`Updated visibility of permission "${permissionName}"`
			);
			await waitForToastGone(page);
			await expect(page.getByTestId('superuser-visibility-manage-modal')).toHaveCount(0);
			await expect(row.getByTestId('superuser-visibility-count')).toHaveText('1');

			await row.getByTestId('superuser-visibility-manage').click();
			await expect(page.getByTestId('superuser-visibility-manage-modal')).toBeVisible();
			await ms
				.locator(
					`[data-testid="multiselect-chip"][data-key="${groupName}"][data-state="selected"]`
				)
				.click();
			await expect(page.getByTestId('change-summary-removed')).toBeVisible();
			await page.getByTestId('superuser-visibility-manage-save').click();
			await page.getByTestId('confirm-modal-confirm').click();
			await expect(page.getByTestId('toast')).toContainText(
				`Updated visibility of permission "${permissionName}"`
			);
			await waitForToastGone(page);
			await expect(row.getByTestId('superuser-visibility-count')).toHaveText('0');

			// Matrix reflects the same mapping state after list edits.
			await page.getByTestId('superuser-visibility-view-matrix').click();
			await page.getByTestId('superuser-visibility-search').fill(permissionName);
			const cell = page.locator(
				`[data-testid="superuser-visibility-cell"][data-permission-name="${permissionName}"][data-group-name="${groupName}"]`
			);
			await expect(cell).toHaveAttribute('aria-pressed', 'false');
		} finally {
			try {
				await deleteCatalogItemIfPresent(page, 'permissions', permissionName);
				await deleteCatalogItemIfPresent(page, 'groups', groupName);
			} catch {
				/* ignore */
			}
		}
	});

	test('switches between list and matrix views', async ({ superuserPage: page }) => {
		await page.goto('/superuser?tab=visibility');
		await expect(page.getByTestId('superuser-visibility-panel')).toBeVisible();

		await expect(page.getByTestId('superuser-visibility-view-list')).toHaveAttribute(
			'aria-pressed',
			'true'
		);
		await expect(page.getByTestId('superuser-visibility-list-table')).toBeVisible();

		await page.getByTestId('superuser-visibility-view-matrix').click();
		await expect(page.getByTestId('superuser-visibility-view-matrix')).toHaveAttribute(
			'aria-pressed',
			'true'
		);
		await expect(page.getByTestId('superuser-visibility-matrix')).toBeVisible();
		await expect(page.getByTestId('superuser-visibility-list-table')).toHaveCount(0);

		await page.getByTestId('superuser-visibility-view-list').click();
		await expect(page.getByTestId('superuser-visibility-list-table')).toBeVisible();
	});
});
