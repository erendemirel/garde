import { test, expect } from './helpers/fixtures';
import { e2eAdmin, loginAs } from './helpers/auth';
import { waitForPageShell } from './helpers/waits';

test.describe('Dashboard account overview', () => {
	test('shows account summary and self-service links', async ({ adminPage: page }) => {
		await page.goto('/dashboard');
		await waitForPageShell(page, 'dashboard-page');
		await expect(page.getByTestId('dashboard-email')).toHaveText(e2eAdmin.email);
		await expect(page.getByTestId('dashboard-status')).toBeVisible();
		await expect(page.getByTestId('dashboard-mfa')).toBeVisible();
		await expect(page.getByTestId('dashboard-permissions')).toBeVisible();
		await expect(page.getByTestId('dashboard-groups')).toBeVisible();
		await expect(page.getByTestId('dashboard-link-mfa')).toBeVisible();
		await expect(page.getByTestId('dashboard-link-password')).toBeVisible();
		await expect(page.getByTestId('dashboard-link-request-update')).toBeVisible();

		const permChips = page.getByTestId('dashboard-permission-chip');
		const permEmpty = page.getByTestId('dashboard-permissions-empty');
		await expect(permChips.or(permEmpty).first()).toBeVisible();

		const groupChips = page.getByTestId('dashboard-group-chip');
		const groupEmpty = page.getByTestId('dashboard-groups-empty');
		await expect(groupChips.or(groupEmpty).first()).toBeVisible();
	});

	test('opens change-password from the dashboard', async ({ adminPage: page }) => {
		await page.goto('/dashboard');
		await waitForPageShell(page, 'dashboard-page');
		await page.getByTestId('dashboard-link-password').click();
		await expect(page).toHaveURL(/\/password/);
		await expect(page.getByTestId('password-page')).toBeVisible();
	});

	test('opens MFA from the dashboard', async ({ adminPage: page }) => {
		await page.goto('/dashboard');
		await waitForPageShell(page, 'dashboard-page');
		await page.getByTestId('dashboard-link-mfa').click();
		await expect(page).toHaveURL(/\/mfa/);
		await expect(page.getByTestId('mfa-page')).toBeVisible();
	});
});

test.describe('Change password page', () => {
	test('shows the form with stable locators', async ({ adminPage: page }) => {
		await page.goto('/password');
		await waitForPageShell(page, 'password-page');
		await expect(page.getByTestId('password-current')).toBeVisible();
		await expect(page.getByTestId('password-new')).toBeVisible();
		await expect(page.getByTestId('password-confirm')).toBeVisible();
		await expect(page.getByTestId('password-submit')).toBeEnabled();
		await expect(page.getByTestId('password-back')).toHaveAttribute('href', '/dashboard');
	});

	test('client-side mismatch shows an error without confirming', async ({ adminPage: page }) => {
		await page.goto('/password');
		await waitForPageShell(page, 'password-page');
		await page.getByTestId('password-current').fill(e2eAdmin.password);
		await page.getByTestId('password-new').fill('NewPassword123!');
		await page.getByTestId('password-confirm').fill('DifferentPass123!');
		await page.getByTestId('password-submit').click();
		await expect(page.getByTestId('password-error')).toHaveText('Passwords do not match');
		await expect(page.getByTestId('confirm-modal-message')).toHaveCount(0);
	});

	test('back link returns to the dashboard', async ({ adminPage: page }) => {
		await page.goto('/password');
		await waitForPageShell(page, 'password-page');
		await page.getByTestId('password-back').click();
		await expect(page).toHaveURL(/\/dashboard/);
		await waitForPageShell(page, 'dashboard-page');
	});
});

test.describe('MFA page', () => {
	test('shows disabled MFA choice for the seed admin', async ({ adminPage: page }) => {
		await page.goto('/mfa');
		await waitForPageShell(page, 'mfa-page');
		await expect(page.getByTestId('mfa-page')).toHaveAttribute('data-step', 'choice');
		await expect(page.getByTestId('mfa-status')).toContainText('disabled');
		await expect(page.getByTestId('mfa-setup')).toBeEnabled();
	});

	test('setup advances to the verify step with a secret', async ({
		browser,
		ephemeralUser
	}) => {
		// Use ephemeral user so parallel workers do not leave pending MFA on seed admin.
		const context = await browser.newContext();
		const page = await context.newPage();
		await loginAs(page, ephemeralUser);
		await waitForPageShell(page, 'dashboard-page');
		await page.getByTestId('dashboard-link-mfa').click();

		const setupResponse = page.waitForResponse(
			(res) =>
				res.url().includes('/api/users/mfa/setup') && res.request().method() === 'POST'
		);
		await page.getByTestId('mfa-setup').click();
		await setupResponse;

		await expect(page.getByTestId('mfa-page')).toHaveAttribute('data-step', 'verify');
		await expect(page.getByTestId('mfa-qr')).toBeVisible();
		await expect(page.getByTestId('mfa-secret')).not.toBeEmpty();
		await context.close();
	});
});
