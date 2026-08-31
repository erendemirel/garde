import { test, expect } from './helpers/fixtures';
import { loginAs } from './helpers/auth';

/**
 * Role gates — ephemeral (non-admin) users must not reach admin/superuser consoles.
 */
test.describe('Access denied', () => {
	test('non-admin cannot open admin or superuser', async ({ browser, ephemeralUser }) => {
		const context = await browser.newContext();
		const page = await context.newPage();
		await loginAs(page, ephemeralUser);

		await page.goto('/admin');
		await expect(page.getByTestId('admin-access-denied')).toBeVisible();
		await expect(page.getByTestId('admin-back-dashboard')).toHaveAttribute('href', '/dashboard');

		await page.goto('/superuser');
		await expect(page.getByTestId('superuser-access-denied')).toBeVisible();
		await expect(page.getByTestId('superuser-back-dashboard')).toHaveAttribute(
			'href',
			'/dashboard'
		);

		await context.close();
	});
});
