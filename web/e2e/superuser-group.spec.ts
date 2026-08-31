import { test, expect } from './helpers/fixtures';

async function waitForToastGone(page: import('@playwright/test').Page) {
	await expect(page.getByTestId('toast')).toBeHidden({ timeout: 7000 });
}

test.describe('Superuser group CRUD', () => {
	test('creates a group then deletes it', async ({ superuserPage: page, uniqueSuffix }) => {
		const groupName = `e2e_group_${uniqueSuffix}`;

		await page.goto('/superuser');
		await page.getByTestId('superuser-tab-groups').click();
		await expect(page.getByTestId('superuser-catalog')).toHaveAttribute('data-mode', 'groups');

		await page.getByTestId('superuser-catalog-create').click();
		await page.getByTestId('superuser-catalog-item-name').fill(groupName);
		await page.getByTestId('superuser-catalog-item-definition').fill('E2E temporary group');
		await page.getByTestId('superuser-catalog-item-save').click();
		await expect(page.getByTestId('toast')).toContainText(groupName);
		await waitForToastGone(page);

		await page.getByTestId('superuser-catalog-search').fill(groupName);
		const row = page.locator(
			`[data-testid="superuser-catalog-row"][data-item-name="${groupName}"]`
		);
		await expect(row).toBeVisible();

		await row.getByTestId('superuser-catalog-delete').click();
		await page.getByTestId('confirm-modal-confirm').click();
		await expect(page.getByTestId('toast')).toContainText(/Deleted group/i);
		await expect(row).toHaveCount(0);
	});

	test('edits a group definition', async ({ superuserPage: page, uniqueSuffix }) => {
		const groupName = `e2e_gedit_${uniqueSuffix}`;
		const updatedDefinition = `Updated group definition ${uniqueSuffix}`;

		await page.goto('/superuser');
		await page.getByTestId('superuser-tab-groups').click();

		await page.getByTestId('superuser-catalog-create').click();
		await page.getByTestId('superuser-catalog-item-name').fill(groupName);
		await page.getByTestId('superuser-catalog-item-definition').fill('Initial group definition');
		await page.getByTestId('superuser-catalog-item-save').click();
		await expect(page.getByTestId('toast')).toContainText(groupName);
		await waitForToastGone(page);

		try {
			await page.getByTestId('superuser-catalog-search').fill(groupName);
			const row = page.locator(
				`[data-testid="superuser-catalog-row"][data-item-name="${groupName}"]`
			);
			await expect(row).toBeVisible();

			await row.getByTestId('superuser-catalog-edit').click();
			await expect(page.getByTestId('superuser-catalog-item-modal')).toBeVisible();
			await expect(page.getByTestId('superuser-catalog-item-name')).toBeDisabled();
			await expect(page.getByTestId('superuser-catalog-item-name')).toHaveValue(groupName);
			await expect(page.getByTestId('superuser-catalog-item-save')).toBeDisabled();

			await page.getByTestId('superuser-catalog-item-definition').fill(updatedDefinition);
			await expect(page.getByTestId('superuser-catalog-item-save')).toBeEnabled();
			await page.getByTestId('superuser-catalog-item-save').click();
			await expect(page.getByTestId('toast')).toContainText(`Updated group "${groupName}"`);
			await waitForToastGone(page);

			await row.getByTestId('superuser-catalog-edit').click();
			await expect(page.getByTestId('superuser-catalog-item-definition')).toHaveValue(
				updatedDefinition
			);
			await page.getByTestId('superuser-catalog-item-cancel').click();
		} finally {
			await page.getByTestId('superuser-catalog-search').fill(groupName);
			const row = page.locator(
				`[data-testid="superuser-catalog-row"][data-item-name="${groupName}"]`
			);
			if ((await row.count()) > 0) {
				await row.getByTestId('superuser-catalog-delete').click();
				await page.getByTestId('confirm-modal-confirm').click();
				await waitForToastGone(page).catch(() => undefined);
			}
		}
	});
});
