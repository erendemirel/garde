import { expect, type APIRequestContext, type Page } from '@playwright/test';
import {
	expectAPIKeyRejected,
	FAKE_SESSION_ID,
	validateWithAPIKey
} from './apiKeys';
import { assertToast, LOAD_TIMEOUT } from './waits';

export type IssuedPAT = {
	id: string;
	name: string;
	token?: string;
	expires_at?: string | null;
	last_used_at?: string | null;
};

type CreatePATBody = {
	name: string;
	expires_in?: string;
	never_expires?: boolean;
};

/** Issue a PAT via the authenticated session API (page.request or logged-in ctx). */
export async function issuePAT(
	sessionRequest: APIRequestContext,
	body: CreatePATBody
): Promise<IssuedPAT> {
	const res = await sessionRequest.post('/api/users/me/tokens', { data: body });
	const text = await res.text();
	expect(res.status(), `issue PAT failed: ${text}`).toBe(201);
	const data = JSON.parse(text).data as IssuedPAT;
	expect(data.token).toMatch(/^garde_pat_/);
	expect(data.id).toBeTruthy();
	return data as IssuedPAT & { token: string };
}

export async function listPATs(sessionRequest: APIRequestContext) {
	const res = await sessionRequest.get('/api/users/me/tokens');
	expect(res.ok(), await res.text()).toBeTruthy();
	return (await res.json()).data as { tokens: IssuedPAT[]; total: number };
}

export async function revokePATById(sessionRequest: APIRequestContext, tokenId: string) {
	return sessionRequest.delete(`/api/users/me/tokens/${encodeURIComponent(tokenId)}`);
}

/** Best-effort wipe of every active PAT for the session user. */
export async function cleanupPATs(sessionRequest: APIRequestContext) {
	try {
		const listed = await listPATs(sessionRequest);
		for (const t of listed.tokens || []) {
			await revokePATById(sessionRequest, t.id).catch(() => undefined);
		}
	} catch {
		/* ignore */
	}
}

/** Cookie-less call authenticated only by the PAT Bearer token. */
export async function meWithPAT(request: APIRequestContext, token: string) {
	return request.get('/api/users/me', {
		headers: { Authorization: `Bearer ${token}` },
		failOnStatusCode: false
	});
}

export async function expectPATAccepted(res: Awaited<ReturnType<typeof meWithPAT>>) {
	expect(res.status(), await res.text()).toBe(200);
	const body = await res.json();
	const user = body?.data;
	expect(user?.email || user?.id).toBeTruthy();
}

export async function expectPATRejected(res: Awaited<ReturnType<typeof meWithPAT>>) {
	expect(res.status()).toBe(401);
}

/** PAT must never authenticate /validate (tenant-key path only). */
export async function expectPATRejectedOnValidate(request: APIRequestContext, token: string) {
	const asApiKeyHeader = await validateWithAPIKey(request, token);
	await expectAPIKeyRejected(asApiKeyHeader);

	const asBearer = await request.get('/api/validate', {
		headers: {
			Authorization: `Bearer ${token}`,
			'X-Session-ID': FAKE_SESSION_ID
		},
		failOnStatusCode: false
	});
	expect(asBearer.status()).toBe(401);
	const message = String((await asBearer.json())?.error?.message || '').toLowerCase();
	expect(message).toContain('unauthorized');
	expect(message).not.toContain('session invalid');
}

export async function openTokensPage(page: Page) {
	await page.goto('/tokens');
}

export async function acknowledgePATReveal(page: Page) {
	await expect(page.getByTestId('tokens-reveal-modal')).toBeVisible();
	const secret = page.getByTestId('tokens-reveal-secret');
	await expect(secret).toContainText(/^garde_pat_/);
	const plaintext = (await secret.textContent())?.trim() || '';
	expect(plaintext).toMatch(/^garde_pat_[a-f0-9]+_/);
	await expect(page.getByTestId('tokens-reveal-done')).toBeDisabled();
	await page.getByTestId('tokens-reveal-ack').check();
	await expect(page.getByTestId('tokens-reveal-done')).toBeEnabled();
	await page.getByTestId('tokens-reveal-done').click();
	await expect(page.getByTestId('tokens-reveal-modal')).toHaveCount(0);
	return plaintext;
}

/** UI issue flow; returns plaintext. Assumes already on /tokens.
 * Asserts the success toast before acknowledge — same order as API-key specs
 * (toast auto-hides in 5s and must not be checked after the reveal modal).
 */
export async function issuePATViaUI(
	page: Page,
	opts: { name: string; expiry?: 'default' | 'never' | 'custom'; expiresIn?: string }
) {
	await page.getByTestId('tokens-issue').click();
	await expect(page.getByTestId('tokens-issue-modal')).toBeVisible();
	await page.getByTestId('tokens-issue-name').fill(opts.name);

	const expiry = opts.expiry || 'default';
	if (expiry === 'never') {
		await page.getByTestId('tokens-issue-expiry-never').check();
	} else if (expiry === 'custom') {
		await page.getByTestId('tokens-issue-expiry-custom').check();
		await page.getByTestId('tokens-issue-expires-in').fill(opts.expiresIn || '48h');
	}

	await page.getByTestId('tokens-issue-submit').click();
	await assertToast(page, opts.name);
	return acknowledgePATReveal(page);
}

/** Click revoke confirm and wait for the DELETE to settle (then toast is safe to assert). */
export async function confirmRevokePAT(page: Page) {
	const revokeResponse = page.waitForResponse(
		(res) => {
			if (res.request().method() !== 'DELETE') return false;
			try {
				return /\/api\/users\/me\/tokens\/[^/]+$/.test(new URL(res.url()).pathname);
			} catch {
				return false;
			}
		},
		{ timeout: LOAD_TIMEOUT }
	);
	await page.getByTestId('confirm-modal-confirm').click();
	const res = await revokeResponse;
	expect(res.ok(), await res.text()).toBeTruthy();
}
