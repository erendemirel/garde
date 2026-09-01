import { expect, type APIRequestContext, type Page } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
import { LOAD_TIMEOUT, REDIRECT_TIMEOUT, waitForPageShell, waitForSessionReady } from './waits';

/** Dev bootstrap accounts from README / docker compose seed. Override via env. */
export const e2eAdmin = {
	email: process.env.E2E_ADMIN_EMAIL || 'test.admin@test.com',
	password: process.env.E2E_ADMIN_PASSWORD || 'DevAdminTest123!'
};

export const e2eSuperuser = {
	email: process.env.E2E_SUPERUSER_EMAIL || 'test.superuser@test.com',
	password: process.env.E2E_SUPERUSER_PASSWORD || 'DevAdminTest123!'
};

export type LoginCreds = { email: string; password: string; mfaCode?: string };

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/** Fast cookie-based login — used by worker fixtures and tests that do not exercise the login form. */
export async function loginViaRequest(request: APIRequestContext, creds: LoginCreds) {
	const body: Record<string, string> = {
		email: creds.email,
		password: creds.password
	};
	if (creds.mfaCode) body.mfa_code = creds.mfaCode;

	let lastRes: Awaited<ReturnType<APIRequestContext['post']>> | undefined;
	for (let attempt = 0; attempt < 4; attempt++) {
		const res = await request.post('/api/login', { data: body });
		const text = await res.text().catch(() => '');
		lastRes = res;

		if (res.ok()) return res;

		const needsMfa = res.status() === 401 && text.toLowerCase().includes('mfa');
		if (needsMfa && !creds.mfaCode) return res;

		const rateLimited =
			res.status() === 429 ||
			(res.status() === 401 && /temporarily restricted|try again later/i.test(text));

		if (attempt < 3 && (res.status() >= 500 || rateLimited)) {
			await sleep(400 * (attempt + 1));
			continue;
		}

		expect(res.ok(), `API login failed: ${res.status()} ${text}`).toBeTruthy();
		return res;
	}

	expect(lastRes?.ok(), 'API login failed after retries').toBeTruthy();
	return lastRes!;
}

/**
 * Return an API context authenticated as creds; refresh storageState when stale.
 * Avoids 401 flakes when cached worker auth outlives server restarts.
 */
export async function ensureApiAuth(
	playwright: import('@playwright/test').Playwright,
	baseURL: string | undefined,
	creds: LoginCreds,
	statePath: string
) {
	const createContext = (storageState?: string) =>
		playwright.request.newContext({
			baseURL,
			...(storageState ? { storageState } : {})
		});

	if (fs.existsSync(statePath)) {
		const existing = await createContext(statePath);
		const me = await existing.get('/api/users/me');
		if (me.ok()) return existing;
		await existing.dispose();
	}

	const ctx = await createContext();
	await loginViaRequest(ctx, creds);
	fs.mkdirSync(path.dirname(statePath), { recursive: true });
	await ctx.storageState({ path: statePath });

	const me = await ctx.get('/api/users/me');
	expect(me.ok(), `Session verify failed after login: ${me.status()}`).toBeTruthy();
	return ctx;
}

/** Open dashboard with an authenticated request context (shared cookies with page.request). */
export async function openDashboardSession(page: Page) {
	await page.goto('/dashboard');
	await waitForPageShell(page, 'dashboard-page');
}

/**
 * Authenticate via API and land on dashboard.
 * Use instead of loginAs whenever the test is not specifically exercising the login form.
 */
export async function startUserSession(page: Page, creds: LoginCreds) {
	await loginViaRequest(page.request, creds);
	await openDashboardSession(page);
}

/** Sign in after account approval — API login avoids Svelte hydration flakes on the login form. */
export async function signInApprovedUser(page: Page, creds: LoginCreds) {
	await startUserSession(page, creds);
}

/** Wait until Svelte has mounted and the login form handlers are wired. */
export async function waitForLoginFormReady(page: Page, timeout = REDIRECT_TIMEOUT) {
	await expect(page.getByTestId('login-form')).toHaveAttribute('data-ready', 'true', { timeout });
	await expect(page.getByTestId('login-submit')).toBeEnabled();
}

/** Wait until the register form handlers are wired. */
export async function waitForRegisterFormReady(page: Page, timeout = REDIRECT_TIMEOUT) {
	await expect(page.getByTestId('register-form')).toHaveAttribute('data-ready', 'true', { timeout });
	await expect(page.getByTestId('register-submit')).toBeEnabled();
}

/** Open login — domcontentloaded + interactive form (no networkidle). */
export async function openLogin(page: Page) {
	await page.bringToFront();
	const alreadyOnLogin = await page
		.getByTestId('login-page')
		.isVisible()
		.catch(() => false);
	if (!alreadyOnLogin) {
		await page.goto('/', { waitUntil: 'domcontentloaded' });
	}
	await expect(page.getByTestId('login-page')).toBeVisible({ timeout: REDIRECT_TIMEOUT });
	await waitForLoginFormReady(page);
}

/** Open register — domcontentloaded + interactive form. */
export async function openRegister(page: Page) {
	await page.bringToFront();
	await page.goto('/register', { waitUntil: 'domcontentloaded' });
	await expect(page.getByTestId('register-page')).toBeVisible({ timeout: REDIRECT_TIMEOUT });
	await waitForRegisterFormReady(page);
}

/** Open forgot-password email step. */
export async function openForgotPassword(page: Page) {
	await page.bringToFront();
	await page.goto('/forgot-password', { waitUntil: 'domcontentloaded' });
	await expect(page.getByTestId('forgot-password-page')).toBeVisible({ timeout: REDIRECT_TIMEOUT });
	await expect(page.getByTestId('forgot-password-page')).toHaveAttribute('data-step', 'email');
	await expect(page.getByTestId('forgot-email-form')).toHaveAttribute('data-ready', 'true', {
		timeout: REDIRECT_TIMEOUT
	});
	await expect(page.getByTestId('forgot-send-otp')).toBeEnabled();
}

/** Fill login inputs; retry until hydration remount stops clearing values. */
export async function fillLoginForm(page: Page, creds: Pick<LoginCreds, 'email' | 'password'>) {
	await waitForLoginFormReady(page);
	for (let attempt = 0; attempt < 10; attempt++) {
		await page.getByTestId('login-email').fill(creds.email);
		await page.getByTestId('login-password').fill(creds.password);
		const email = await page.getByTestId('login-email').inputValue();
		const password = await page.getByTestId('login-password').inputValue();
		if (email === creds.email && password === creds.password) return;
	}
	throw new Error('login form inputs did not stabilize after hydration');
}

async function submitLoginForm(page: Page, creds: LoginCreds, expectSuccess: boolean) {
	let lastError: unknown;
	for (let attempt = 0; attempt < 5; attempt++) {
		if (attempt > 0) {
			await openLogin(page);
		}
		await fillLoginForm(page, creds);

		const loginResponse = page.waitForResponse(
			(res) => res.url().includes('/api/login') && res.request().method() === 'POST',
			{ timeout: LOAD_TIMEOUT }
		);
		await page.getByTestId('login-submit').click();

		try {
			const res = await loginResponse;
			if (expectSuccess && !res.ok()) {
				const text = await res.text().catch(() => '');
				const needsMfa = res.status() === 401 && text.toLowerCase().includes('mfa');
				if (!needsMfa) {
					expect(res.ok(), `login failed: ${res.status()} ${text}`).toBeTruthy();
				}
			}
			return res;
		} catch (err) {
			lastError = err;
			if (attempt < 4) {
				const stillOnLogin = await page
					.getByTestId('login-page')
					.isVisible()
					.catch(() => false);
				if (stillOnLogin) continue;
			}
			throw err;
		}
	}
	throw lastError;
}

/** Submit login form without assuming dashboard redirect (e.g. MFA enforcement). */
export async function submitLogin(page: Page, creds: Pick<LoginCreds, 'email' | 'password'>) {
	await openLogin(page);
	await submitLoginForm(page, creds, true);
}

/** UI login — only for specs that explicitly test the login page or MFA login step. */
export async function loginAs(
	page: Page,
	creds: LoginCreds,
	opts?: { expectSuccess?: boolean }
) {
	const expectSuccess = opts?.expectSuccess !== false;
	await openLogin(page);
	await submitLoginForm(page, creds, expectSuccess);

	const needsMfaStep =
		creds.mfaCode !== undefined ||
		(await page.getByTestId('login-mfa').isVisible().catch(() => false));

	if (needsMfaStep) {
		if (!creds.mfaCode) {
			throw new Error('login requires MFA code but none was provided');
		}
		await expect(page.getByTestId('login-mfa')).toBeVisible({ timeout: REDIRECT_TIMEOUT });
		await page.getByTestId('login-mfa').fill(creds.mfaCode);
		const mfaLogin = page.waitForResponse(
			(res) => res.url().includes('/api/login') && res.request().method() === 'POST',
			{ timeout: LOAD_TIMEOUT }
		);
		await page.getByTestId('login-submit').click();
		const mfaRes = await mfaLogin;
		if (expectSuccess) {
			expect(
				mfaRes.ok(),
				`MFA login failed: ${mfaRes.status()} ${await mfaRes.text().catch(() => '')}`
			).toBeTruthy();
		}
	}

	if (expectSuccess) {
		await expect(page).toHaveURL(/\/dashboard/, { timeout: REDIRECT_TIMEOUT });
		await waitForSessionReady(page);
		await expect(page.getByTestId('dashboard-page')).toBeVisible({ timeout: LOAD_TIMEOUT });
	}
}

/** Attempt login and expect the UI error (e.g. pending/rejected account). */
export async function expectLoginRejected(
	page: Page,
	creds: { email: string; password: string },
	opts?: { message?: string | RegExp }
) {
	await page.bringToFront();
	await loginAs(page, creds, { expectSuccess: false });
	await expect(page.getByTestId('login-error')).toBeVisible({ timeout: REDIRECT_TIMEOUT });
	if (opts?.message) {
		await expect(page.getByTestId('login-error')).toContainText(opts.message);
	}
}

/** API login then open a route — for MFA-enforced users who should land on /mfa. */
export async function startUserSessionAt(page: Page, creds: LoginCreds, path: string) {
	await loginViaRequest(page.request, creds);
	await page.goto(path);
	await waitForSessionReady(page);
}
