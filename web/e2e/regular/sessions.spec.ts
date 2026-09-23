import { expect } from '@playwright/test';
import { test } from '../helpers/fixtures';
import { describeTags, TAG } from '../helpers/tags';
import { assertToast, waitForPageShell, LOAD_TIMEOUT } from '../helpers/waits';
import { loginViaRequest } from '../helpers/auth';

test.describe(
	'Active sessions self-service',
	describeTags(TAG.regular, TAG.selfService, TAG.security, TAG.focused, TAG.activeSession),
	() => {
		test('lists current session from dashboard and can revoke another session', async ({
			regularUserPage: page,
			browser,
			ephemeralUser
		}) => {
			const otherCtx = await browser.newContext();
			await loginViaRequest(otherCtx.request, ephemeralUser);

			await page.goto('/dashboard');
			await waitForPageShell(page, 'dashboard-page');
			await expect(page.getByTestId('dashboard-link-sessions')).toBeVisible();
			await page.getByTestId('dashboard-link-sessions').click();
			await waitForPageShell(page, 'sessions-page');

			await expect(page.getByTestId('sessions-list')).toBeVisible({ timeout: LOAD_TIMEOUT });
			const rows = page.getByTestId('sessions-row');
			await expect(rows).toHaveCount(2, { timeout: LOAD_TIMEOUT });
			await expect(page.getByTestId('sessions-row-current')).toBeVisible();
			await expect(page.getByTestId('sessions-revoke-others')).toBeVisible();

			const otherRow = page.locator('[data-testid="sessions-row"][data-current="false"]');
			await expect(otherRow.getByTestId('sessions-row-summary')).not.toBeEmpty();
			await expect(otherRow.getByTestId('sessions-row-place')).not.toBeEmpty();

			await otherRow.getByTestId('sessions-row-revoke').click();
			await page.getByTestId('confirm-modal-confirm').click();
			await assertToast(page, /Session revoked/i);
			await expect(rows).toHaveCount(1, { timeout: LOAD_TIMEOUT });
			await expect(page.getByTestId('sessions-row-current')).toBeVisible();

			await otherCtx.close();
		});

		test('sign out other sessions keeps this device', async ({
			regularUserPage: page,
			browser,
			ephemeralUser
		}) => {
			const otherCtx = await browser.newContext();
			await loginViaRequest(otherCtx.request, ephemeralUser);

			await page.goto('/sessions');
			await waitForPageShell(page, 'sessions-page');
			await expect(page.getByTestId('sessions-row')).toHaveCount(2, { timeout: LOAD_TIMEOUT });

			await page.getByTestId('sessions-revoke-others').click();
			await page.getByTestId('confirm-modal-confirm').click();
			await assertToast(page, /Revoked .+ other session/i);
			await expect(page.getByTestId('sessions-row')).toHaveCount(1, { timeout: LOAD_TIMEOUT });
			await expect(page.getByTestId('sessions-row')).toHaveAttribute('data-current', 'true');
			await expect(page.getByTestId('sessions-page')).toBeVisible();

			await otherCtx.close();
		});

		test('signing out the current session returns to login', async ({ regularUserPage: page }) => {
			await page.goto('/sessions');
			await waitForPageShell(page, 'sessions-page');
			const current = page.locator('[data-testid="sessions-row"][data-current="true"]');
			await expect(current).toBeVisible({ timeout: LOAD_TIMEOUT });
			await current.getByTestId('sessions-row-revoke').click();
			await page.getByTestId('confirm-modal-confirm').click();
			await expect(page.getByTestId('login-page')).toBeVisible({ timeout: LOAD_TIMEOUT });
		});
	}
);
