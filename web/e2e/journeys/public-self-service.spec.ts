import { test, expect } from '../helpers/fixtures';
import { describeTags, TAG } from '../helpers/tags';
import { REDIRECT_TIMEOUT } from '../helpers/waits';

test.describe('Public config and kill switch (defaults)', describeTags(TAG.journey, TAG.registration), () => {
	test('exposes registration gates on /public/config', async ({ request }) => {
		const res = await request.get('/api/public/config');
		expect(res.ok()).toBeTruthy();
		const body = await res.json();
		expect(body.data).toMatchObject({
			public_self_service: expect.any(Boolean),
			require_admin_approval: expect.any(Boolean),
			require_email_verification: expect.any(Boolean),
			registration_next: expect.stringMatching(/^(verify_email|await_admin|ready)$/)
		});
		// Dev/e2e secrets: self-service on, admin approval on, email verify off.
		expect(body.data.public_self_service).toBe(true);
		expect(body.data.require_admin_approval).toBe(true);
		expect(body.data.require_email_verification).toBe(false);
		expect(body.data.registration_next).toBe('await_admin');
	});

	test('public auth routes answer when kill switch is off', async ({ request }) => {
		const login = await request.post('/api/login', {
			data: { email: 'nobody@example.com', password: 'DevAdminTest123!' }
		});
		// Mounted: opaque auth failure, not 404.
		expect(login.status()).not.toBe(404);

		const me = await request.get('/api/users/me');
		expect(me.status()).toBe(401);

		const adminKeys = await request.get('/api/admin/api-keys');
		// Single-listener e2e: admin is on the public listener (compat).
		expect(adminKeys.status()).not.toBe(404);
	});

	test('register page shows form when self-service is on', async ({ page }) => {
		await page.goto('/register', { waitUntil: 'domcontentloaded' });
		await expect(page.getByTestId('register-page')).toBeVisible({ timeout: REDIRECT_TIMEOUT });
		await expect(page.getByTestId('register-form')).toBeVisible({ timeout: REDIRECT_TIMEOUT });
		await expect(page.getByTestId('register-disabled')).toHaveCount(0);
	});

	test('login form is available when kill switch is off', async ({ page }) => {
		await page.goto('/', { waitUntil: 'domcontentloaded' });
		await expect(page.getByTestId('login-form')).toBeVisible({ timeout: REDIRECT_TIMEOUT });
		await expect(page.getByTestId('login-disabled')).toHaveCount(0);
		await expect(page.getByTestId('login-register-link')).toBeVisible();
		await expect(page.getByTestId('login-forgot-link')).toBeVisible();
		await expect(page.getByTestId('login-verify-link')).toHaveCount(0);
	});
});
