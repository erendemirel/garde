import { test, expect } from './helpers/fixtures';
import type { Locator, Page } from '@playwright/test';
import { loginAs } from './helpers/auth';
import { openUserDetailFromSuperuser, patchUserMaps } from './helpers/userApi';

async function waitForToastGone(page: Page) {
	await expect(page.getByTestId('toast')).toBeHidden({ timeout: 7000 });
}

function groupsMultiselect(page: Page): Locator {
	return page.locator('[data-testid="multiselect"][data-label="Groups"]');
}

async function stageGroupAdd(page: Page): Promise<string> {
	const groupSection = page.getByTestId('request-update-groups');
	await expect(groupSection).toBeVisible();
	const ms = groupsMultiselect(page);
	await ms.getByTestId('multiselect-input').click();
	const option = ms.getByTestId('multiselect-option').first();
	if ((await option.count()) === 0) {
		test.skip(true, 'No addable groups available for request-update');
	}
	const key = await option.getAttribute('data-key');
	expect(key).toBeTruthy();
	await option.click();
	await expect(page.getByTestId('change-summary-added')).toBeVisible();
	await page.keyboard.press('Escape');
	await expect(ms.getByTestId('multiselect-dropdown')).toHaveCount(0);
	return key!;
}

async function stageAnyGroupChange(page: Page) {
	const groupSection = page.getByTestId('request-update-groups');
	await expect(groupSection).toBeVisible();
	const ms = groupsMultiselect(page);
	await ms.getByTestId('multiselect-input').click();
	const addable = ms.getByTestId('multiselect-option');
	if ((await addable.count()) > 0) {
		await addable.first().click();
		await expect(page.getByTestId('change-summary-added')).toBeVisible();
	} else {
		await page.keyboard.press('Escape');
		const chip = groupSection.getByTestId('multiselect-chip').first();
		await expect(chip).toBeVisible();
		await chip.click();
		await expect(page.getByTestId('change-summary-removed')).toBeVisible();
	}
	await page.keyboard.press('Escape');
	await expect(ms.getByTestId('multiselect-dropdown')).toHaveCount(0);
}

/**
 * Request-update against ephemeral users (seed admin never gets pending updates).
 */
test.describe('Request update flow', () => {
	test('shows the request-update form from the dashboard', async ({ adminPage: page }) => {
		await page.goto('/dashboard');
		await page.getByTestId('dashboard-link-request-update').click();
		await expect(page).toHaveURL(/\/request-update/);
		await expect(page.getByTestId('request-update-page')).toBeVisible();
		await expect(page.getByTestId('request-update-submit')).toBeDisabled();
	});

	test('user submits a request and superuser rejects it', async ({
		browser,
		superuserPage: suPage,
		ephemeralUser
	}) => {
		const userContext = await browser.newContext();
		const userPage = await userContext.newPage();
		await loginAs(userPage, ephemeralUser);
		await userPage.getByTestId('dashboard-link-request-update').click();
		await expect(
			userPage.getByTestId('multiselect-chip').or(userPage.getByTestId('request-update-groups-empty')).first()
		).toBeVisible({ timeout: 15_000 });
		await stageAnyGroupChange(userPage);
		await userPage.getByTestId('request-update-submit').click();
		await expect(userPage.getByTestId('toast')).toContainText('Request submitted');
		await userPage.waitForURL(/\/dashboard/, { timeout: 10_000 });
		await userContext.close();

		await suPage.goto('/superuser');
		await openUserDetailFromSuperuser(suPage, ephemeralUser.email);
		await expect(suPage.getByTestId('user-detail-pending-update')).toBeVisible();
		await suPage.getByTestId('user-detail-reject-update').click();
		await suPage.getByTestId('confirm-modal-confirm').click();
		await expect(suPage.getByTestId('toast')).toContainText('Update rejected');
		await waitForToastGone(suPage);
		await expect(suPage.getByTestId('user-detail-pending-update')).toHaveCount(0);
	});

	test('user submits a group add and superuser approves it', async ({
		browser,
		superuserPage: suPage,
		suRequest,
		ephemeralUser
	}) => {
		const userContext = await browser.newContext();
		const userPage = await userContext.newPage();
		await loginAs(userPage, ephemeralUser);
		await userPage.getByTestId('dashboard-link-request-update').click();
		await expect(
			userPage.getByTestId('multiselect-chip').or(userPage.getByTestId('request-update-groups-empty')).first()
		).toBeVisible({ timeout: 15_000 });

		const addedGroup = await stageGroupAdd(userPage);
		await userPage.getByTestId('request-update-submit').click();
		await expect(userPage.getByTestId('toast')).toContainText('Request submitted');
		await userPage.waitForURL(/\/dashboard/, { timeout: 10_000 });
		await userContext.close();

		await suPage.goto('/superuser');
		await openUserDetailFromSuperuser(suPage, ephemeralUser.email);
		await expect(
			suPage.locator(
				`[data-testid="user-detail-pending-group"][data-key="${addedGroup}"][data-kind="add"]`
			)
		).toBeVisible();
		await suPage.getByTestId('user-detail-approve-update').click();
		await suPage.getByTestId('confirm-modal-confirm').click();
		await expect(suPage.getByTestId('toast')).toContainText('Update approved');
		await waitForToastGone(suPage);
		await expect(suPage.getByTestId('user-detail-pending-update')).toHaveCount(0);

		// Optional revert on ephemeral user (deleted after test anyway)
		await patchUserMaps(suRequest, ephemeralUser.id, { groups: { [addedGroup]: false } }).catch(
			() => undefined
		);
	});
});
