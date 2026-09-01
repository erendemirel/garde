import { test, expect } from '../../helpers/fixtures';
import { startUserSession } from '../../helpers/auth';

test.describe('Regular user access control', () => {
	test('non-admin cannot open admin or superuser', async ({ browser, ephemeralUser }) => {
		const context = await browser.newContext();
		const page = await context.newPage();
		await startUserSession(page, ephemeralUser);

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

	test('cannot open admin console after signing in as a regular user', async ({
		regularUserPage: page
	}) => {
		await page.goto('/admin');
		await expect(page.getByTestId('admin-access-denied')).toBeVisible();
		await expect(page.getByTestId('admin-back-dashboard')).toHaveAttribute('href', '/dashboard');
	});
});
