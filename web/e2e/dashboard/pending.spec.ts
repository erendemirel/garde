import { test, expect } from '../helpers/fixtures';
import { startUserSession } from '../helpers/auth';
import { describeTags, TAG } from '../helpers/tags';
import { REDIRECT_TIMEOUT } from '../helpers/waits';

async function stageAnyGroupChange(page: import('@playwright/test').Page) {
	const groupSection = page.getByTestId('request-update-groups');
	await expect(groupSection).toBeVisible();
	const ms = page.locator('[data-testid="multiselect"][data-label="Groups"]');
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

test.describe('Dashboard pending update', describeTags(TAG.dashboard, TAG.requestUpdate, TAG.focused), () => {
	test('shows pending banner after reload once me is refetched', async ({ browser, ephemeralUser }) => {
		const context = await browser.newContext();
		const page = await context.newPage();
		await startUserSession(page, ephemeralUser);

		await page.getByTestId('dashboard-link-request-update').click();
		await expect(page.getByTestId('request-update-page')).toBeVisible();
		await expect(
			page.getByTestId('multiselect-chip').or(page.getByTestId('request-update-groups-empty')).first()
		).toBeVisible({ timeout: REDIRECT_TIMEOUT });

		await stageAnyGroupChange(page);
		await page.getByTestId('request-update-submit').click();
		await expect(page.getByTestId('toast')).toContainText('Request submitted');
		await page.waitForURL(/\/dashboard/, { timeout: REDIRECT_TIMEOUT });

		const meResponse = page.waitForResponse(
			(res) => res.url().includes('/api/users/me') && res.request().method() === 'GET'
		);
		await page.reload();
		const meRes = await meResponse;
		expect(meRes.ok()).toBeTruthy();
		const meBody = await meRes.json();
		expect(meBody.data?.pending_updates).toBeTruthy();

		await expect(page.getByTestId('dashboard-pending-update')).toBeVisible();
		await context.close();
	});
});
