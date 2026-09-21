import { test, expect, type Page } from '../helpers/fixtures';
import { e2eAdmin } from '../helpers/auth';
import { describeTags, TAG } from '../helpers/tags';
import { LOAD_TIMEOUT, REDIRECT_TIMEOUT, waitForPageShell } from '../helpers/waits';

const CAP_TOKEN = 'e2e-cap-token-enabled';
const WIDGET_ENDPOINT = 'http://127.0.0.1:9/e2e-site/';

async function mockCapEnabledConfig(page: Page, opts?: { loginRequired?: boolean }) {
	const loginRequired = opts?.loginRequired ?? false;
	await page.route('**/api/captcha/config', async (route) => {
		await route.fulfill({
			status: 200,
			contentType: 'application/json',
			body: JSON.stringify({
				data: {
					enabled: true,
					site_key: 'e2e-site',
					widget_endpoint: WIDGET_ENDPOINT,
					public_url: 'http://127.0.0.1:9',
					login_progressive: true,
					login_required: loginRequired,
					register_required: true
				}
			})
		});
	});
	// Cap widget may probe the mocked endpoint; keep noise out of the console.
	await page.route('**/e2e-site/**', async (route) => {
		await route.fulfill({
			status: 200,
			contentType: 'application/json',
			body: '{}'
		});
	});
}

async function mockCapAdminEnabled(page: Page) {
	await page.route('**/api/admin/captcha', async (route) => {
		await route.fulfill({
			status: 200,
			contentType: 'application/json',
			body: JSON.stringify({
				data: {
					enabled: true,
					site_key: 'e2e-site',
					public_url: 'http://127.0.0.1:9',
					api_url: 'http://cap:3000',
					widget_endpoint: WIDGET_ENDPOINT,
					secret_configured: true,
					dashboard_url: 'http://127.0.0.1:9',
					login_progressive: true,
					login_failure_threshold: 1
				}
			})
		});
	});
}

/** Inject a solved Cap token (uses the CapWidget test hook). */
async function solveCapWidget(page: Page, token = CAP_TOKEN) {
	await expect(page.getByTestId('cap-widget-wrap')).toBeVisible({ timeout: LOAD_TIMEOUT });
	await page.waitForFunction(() => typeof (window as any).__gardeCapSetToken === 'function');
	await page.evaluate((tok) => {
		(window as any).__gardeCapSetToken(tok);
	}, token);
	await expect(page.getByTestId('cap-widget-wrap')).toHaveAttribute('data-solved', 'true', {
		timeout: LOAD_TIMEOUT
	});
}

test.describe('Cap captcha when enabled', describeTags(TAG.auth, TAG.security, TAG.focused), () => {
	test('login hides widget until a failed attempt, then requires Cap', async ({ page }) => {
		await mockCapEnabledConfig(page, { loginRequired: false });
		await page.goto('/', { waitUntil: 'domcontentloaded' });
		await expect(page.getByTestId('login-page')).toBeVisible({ timeout: REDIRECT_TIMEOUT });
		await expect(page.getByTestId('login-form')).toHaveAttribute('data-ready', 'true', {
			timeout: REDIRECT_TIMEOUT
		});
		await expect(page.getByTestId('cap-loading')).toHaveCount(0);
		await expect(page.getByTestId('cap-widget-wrap')).toHaveCount(0);
		await expect(page.getByTestId('login-submit')).toBeEnabled();

		await page.getByTestId('login-email').fill(e2eAdmin.email);
		await page.getByTestId('login-password').fill('WrongPassword1!');

		await page.route('**/api/login', async (route) => {
			if (route.request().method() !== 'POST') {
				await route.continue();
				return;
			}
			await route.fulfill({
				status: 401,
				contentType: 'application/json',
				body: JSON.stringify({
					error: {
						message: 'authentication failed, please try again',
						captcha_required: true
					}
				})
			});
		});

		await page.getByTestId('login-submit').click();
		await expect(page.getByTestId('login-error')).toBeVisible({ timeout: LOAD_TIMEOUT });
		await expect(page.getByTestId('cap-widget-wrap')).toBeVisible({ timeout: LOAD_TIMEOUT });
		await expect(page.getByTestId('login-submit')).toBeDisabled();

		await page.unroute('**/api/login');
		await solveCapWidget(page);
		await expect(page.getByTestId('login-submit')).toBeEnabled();

		const loginRequest = page.waitForRequest(
			(req) => req.url().includes('/api/login') && req.method() === 'POST',
			{ timeout: LOAD_TIMEOUT }
		);
		await page.getByTestId('login-submit').click();
		const req = await loginRequest;
		const body = req.postDataJSON() as { cap_token?: string; email?: string };
		expect(body.cap_token).toBe(CAP_TOKEN);
		expect(body.email).toBe(e2eAdmin.email);
	});

	test('login remounts Cap after wrong password with solved captcha so retry is not stuck', async ({
		page
	}) => {
		// Progressive: widget hidden until first failure (matches the real login UX).
		await mockCapEnabledConfig(page, { loginRequired: false });
		await page.goto('/', { waitUntil: 'domcontentloaded' });
		await expect(page.getByTestId('login-page')).toBeVisible({ timeout: REDIRECT_TIMEOUT });
		await expect(page.getByTestId('login-form')).toHaveAttribute('data-ready', 'true', {
			timeout: REDIRECT_TIMEOUT
		});
		await expect(page.getByTestId('cap-widget-wrap')).toHaveCount(0);

		await page.getByTestId('login-email').fill(e2eAdmin.email);
		await page.getByTestId('login-password').fill('WrongPassword1!');

		await page.route('**/api/login', async (route) => {
			if (route.request().method() !== 'POST') {
				await route.continue();
				return;
			}
			await route.fulfill({
				status: 401,
				contentType: 'application/json',
				body: JSON.stringify({
					error: {
						message: 'authentication failed, please try again',
						captcha_required: true
					}
				})
			});
		});

		// 1) First wrong login → Cap appears, submit blocked until solved.
		await page.getByTestId('login-submit').click();
		await expect(page.getByTestId('login-error')).toBeVisible({ timeout: LOAD_TIMEOUT });
		await expect(page.getByTestId('cap-widget-wrap')).toBeVisible({ timeout: LOAD_TIMEOUT });
		await expect(page.getByTestId('login-submit')).toBeDisabled();

		await solveCapWidget(page, `${CAP_TOKEN}-first`);
		await expect(page.getByTestId('login-submit')).toBeEnabled();

		// 2) Second wrong login with a solved Cap → token cleared + widget remounted.
		const secondFail = page.waitForRequest(
			(req) => req.url().includes('/api/login') && req.method() === 'POST',
			{ timeout: LOAD_TIMEOUT }
		);
		await page.getByTestId('login-submit').click();
		const failBody = (await secondFail).postDataJSON() as { cap_token?: string };
		expect(failBody.cap_token).toBe(`${CAP_TOKEN}-first`);

		await expect(page.getByTestId('login-error')).toBeVisible({ timeout: LOAD_TIMEOUT });
		await expect(page.getByTestId('cap-widget-wrap')).toHaveAttribute('data-solved', 'false', {
			timeout: LOAD_TIMEOUT
		});
		await expect(page.getByTestId('login-submit')).toBeDisabled();

		// 3) Solve again → submit enabled and next request carries the new token.
		const retryToken = `${CAP_TOKEN}-retry`;
		await solveCapWidget(page, retryToken);
		await expect(page.getByTestId('login-submit')).toBeEnabled();

		await page.unroute('**/api/login');
		const retryRequest = page.waitForRequest(
			(req) => req.url().includes('/api/login') && req.method() === 'POST',
			{ timeout: LOAD_TIMEOUT }
		);
		await page.getByTestId('login-submit').click();
		const retryBody = (await retryRequest).postDataJSON() as { cap_token?: string };
		expect(retryBody.cap_token).toBe(retryToken);
	});

	test('login shows widget immediately when login_required from prior IP failures', async ({
		page
	}) => {
		await mockCapEnabledConfig(page, { loginRequired: true });
		await page.goto('/', { waitUntil: 'domcontentloaded' });
		await expect(page.getByTestId('login-page')).toBeVisible({ timeout: REDIRECT_TIMEOUT });
		await expect(page.getByTestId('cap-widget-wrap')).toBeVisible({ timeout: LOAD_TIMEOUT });
		await expect(page.getByTestId('login-submit')).toBeDisabled();
		await solveCapWidget(page);
		await expect(page.getByTestId('login-submit')).toBeEnabled();
	});

	test('register requires a solved captcha before submit is enabled', async ({ page }) => {
		await mockCapEnabledConfig(page);
		await page.goto('/register', { waitUntil: 'domcontentloaded' });
		await expect(page.getByTestId('register-page')).toBeVisible({ timeout: REDIRECT_TIMEOUT });
		await expect(page.getByTestId('register-form')).toHaveAttribute('data-ready', 'true', {
			timeout: REDIRECT_TIMEOUT
		});
		await expect(page.getByTestId('cap-widget-wrap')).toBeVisible({ timeout: LOAD_TIMEOUT });
		await expect(page.getByTestId('register-submit')).toBeDisabled();

		await solveCapWidget(page);
		await expect(page.getByTestId('register-submit')).toBeEnabled();
	});

	test('superuser captcha panel shows enabled status from admin API', async ({
		superuserPage: page
	}) => {
		await mockCapAdminEnabled(page);
		await page.goto('/superuser?tab=captcha');
		await waitForPageShell(page, 'superuser-page');
		await expect(page.getByTestId('superuser-tab-captcha')).toHaveAttribute('aria-selected', 'true');
		await expect(page.getByTestId('superuser-cap-panel')).toBeVisible();
		await expect(page.getByTestId('cap-admin-enabled')).toContainText(/Enabled/i);
		await expect(page.getByTestId('cap-admin-login-policy')).toContainText(/Progressive/i);
		await expect(page.getByTestId('cap-admin-site-key')).toHaveText('e2e-site');
		await expect(page.getByTestId('cap-admin-secret')).toHaveText('Yes');
		await expect(page.getByTestId('cap-admin-dashboard-link')).toHaveAttribute(
			'href',
			'http://127.0.0.1:9'
		);
	});
});
