/** Shared Cap e2e helpers — keep API auth working when Cap is enabled locally. */
import type { Browser, BrowserContext, Page, Route } from '@playwright/test';

/** Must match CAP_BYPASS_TOKEN in Vault /dev.secrets (local/e2e only). */
export const E2E_CAP_BYPASS_TOKEN =
	process.env.E2E_CAP_BYPASS_TOKEN || 'e2e-cap-bypass-token';

const CAP_AUTH_POST_GLOBS = [
	'**/api/login',
	'**/api/users/password/otp',
	'**/api/users/password/reset'
] as const;

/** Mock Cap off so non-Cap UI specs are not blocked by the widget. Cap specs override this. */
export async function mockCapDisabled(page: Page) {
	await page.route('**/api/captcha/config', async (route) => {
		await route.fulfill({
			status: 200,
			contentType: 'application/json',
			body: JSON.stringify({
				data: {
					enabled: false,
					login_progressive: false,
					login_required: false,
					register_required: false
				}
			})
		});
	});
}

async function injectBypassIfMissing(route: Route) {
	const req = route.request();
	if (req.method() !== 'POST') {
		await route.continue();
		return;
	}

	let data: Record<string, unknown>;
	try {
		data = { ...(req.postDataJSON() as Record<string, unknown>) };
	} catch {
		await route.continue();
		return;
	}
	if (typeof data.cap_token === 'string' && data.cap_token.length > 0) {
		await route.continue();
		return;
	}

	data.cap_token = E2E_CAP_BYPASS_TOKEN;
	await route.continue({
		postData: JSON.stringify(data),
		headers: {
			...req.headers(),
			'content-type': 'application/json'
		}
	});
}

/**
 * Inject CAP_BYPASS_TOKEN into Cap-protected auth POSTs when the UI omits it
 * (Cap widget mocked off, but the API still enforces Cap after failed logins).
 * Existing cap_token values are left alone (Cap-focused specs).
 */
export async function injectCapBypassOnAuthPosts(page: Page) {
	for (const glob of CAP_AUTH_POST_GLOBS) {
		await page.route(glob, injectBypassIfMissing);
	}
	// Exact register POST only — do not match /api/users/:id or /api/users/me.
	await page.route('**/api/users', async (route) => {
		let pathname = '';
		try {
			pathname = new URL(route.request().url()).pathname;
		} catch {
			await route.continue();
			return;
		}
		if (pathname !== '/api/users') {
			await route.continue();
			return;
		}
		await injectBypassIfMissing(route);
	});
}

/** Default Cap harness for non-Cap e2e: hide widget + bypass API Cap when needed. */
export async function installCapE2EHarness(page: Page) {
	// Inject first; Cap-disabled mock last so it wins over any broader routes.
	await injectCapBypassOnAuthPosts(page);
	await mockCapDisabled(page);
}

/**
 * Fresh context + page with Cap harness. Use when a spec cannot reuse the
 * fixture `page` (e.g. isolated MFA login flows) — otherwise login-submit can
 * stay disabled while Cap config/progressive state races under parallel load.
 */
export async function newHarnessedPage(
	browser: Browser
): Promise<{ context: BrowserContext; page: Page }> {
	const context = await browser.newContext();
	const page = await context.newPage();
	await installCapE2EHarness(page);
	return { context, page };
}
