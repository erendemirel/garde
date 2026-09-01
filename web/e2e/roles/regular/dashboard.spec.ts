import { test, expect } from '../../helpers/fixtures';
import { describeTags, TAG } from '../../helpers/tags';
import { waitForPageShell } from '../../helpers/waits';

const DEFAULT_GROUP = 'group_a';

test.describe('Regular user navigation', describeTags(TAG.regular, TAG.dashboard, TAG.focused), () => {
	test('nav shows Dashboard only without Admin or Superuser links', async ({
		regularUserPage: page
	}) => {
		await page.goto('/dashboard');
		await waitForPageShell(page, 'dashboard-page');

		await expect(page.getByTestId('nav-dashboard')).toBeVisible();
		await expect(page.getByTestId('nav-admin')).toHaveCount(0);
		await expect(page.getByTestId('nav-superuser')).toHaveCount(0);
		await expect(page.getByTestId('nav-logout')).toBeVisible();
	});
});

test.describe('Regular user dashboard', describeTags(TAG.regular, TAG.dashboard, TAG.focused), () => {
	test('shows account summary with group membership and self-service links', async ({
		regularUserPage: page,
		ephemeralUser
	}) => {
		await page.goto('/dashboard');
		await waitForPageShell(page, 'dashboard-page');

		await expect(page.getByTestId('dashboard-email')).toHaveText(ephemeralUser.email);
		await expect(page.getByTestId('dashboard-status')).toBeVisible();
		await expect(page.getByTestId('dashboard-mfa')).toBeVisible();
		await expect(page.getByTestId('dashboard-groups')).toBeVisible();
		await expect(
			page.locator(`[data-testid="dashboard-group-chip"][data-key="${DEFAULT_GROUP}"]`)
		).toBeVisible();
		await expect(page.getByTestId('dashboard-link-mfa')).toBeVisible();
		await expect(page.getByTestId('dashboard-link-password')).toBeVisible();
		await expect(page.getByTestId('dashboard-link-request-update')).toBeVisible();
	});

	test('opens request-update from the dashboard', async ({ regularUserPage: page }) => {
		await page.goto('/dashboard');
		await waitForPageShell(page, 'dashboard-page');
		await page.getByTestId('dashboard-link-request-update').click();
		await expect(page).toHaveURL(/\/request-update/);
		await expect(page.getByTestId('request-update-page')).toBeVisible();
		await expect(page.getByTestId('request-update-submit')).toBeDisabled();
	});

	test('opens change-password and MFA pages from the dashboard', async ({
		regularUserPage: page
	}) => {
		await page.goto('/dashboard');
		await waitForPageShell(page, 'dashboard-page');

		await page.getByTestId('dashboard-link-password').click();
		await expect(page.getByTestId('password-page')).toBeVisible();
		await page.getByTestId('password-back').click();
		await waitForPageShell(page, 'dashboard-page');

		await page.getByTestId('dashboard-link-mfa').click();
		await expect(page.getByTestId('mfa-page')).toHaveAttribute('data-step', 'choice');
		await expect(page.getByTestId('mfa-back')).toHaveAttribute('href', '/dashboard');
	});

	test('logout returns to the login page', async ({ regularUserPage: page }) => {
		await page.goto('/dashboard');
		await waitForPageShell(page, 'dashboard-page');
		await page.getByTestId('nav-logout').click();
		await expect(page.getByTestId('login-page')).toBeVisible();
	});
});

test.describe('Regular user request update', describeTags(TAG.regular, TAG.requestUpdate, TAG.focused), () => {
	test('shows available groups and keeps submit disabled until a change is staged', async ({
		regularUserPage: page
	}) => {
		await page.goto('/request-update');
		await waitForPageShell(page, 'request-update-page');
		await expect(page.getByTestId('request-update-groups')).toBeVisible();
		await expect(
			page.getByTestId('multiselect-chip').or(page.getByTestId('request-update-groups-empty')).first()
		).toBeVisible({ timeout: 15_000 });
		await expect(page.getByTestId('request-update-submit')).toBeDisabled();

		const ms = page.locator('[data-testid="multiselect"][data-label="Groups"]');
		await ms.getByTestId('multiselect-input').click();
		const addable = ms.getByTestId('multiselect-option');
		if ((await addable.count()) > 0) {
			await addable.first().click();
			await expect(page.getByTestId('change-summary-added')).toBeVisible();
			await expect(page.getByTestId('request-update-submit')).toBeEnabled();
		}
		await page.keyboard.press('Escape');
	});
});
