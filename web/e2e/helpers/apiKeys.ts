import { expect, type APIRequestContext } from '@playwright/test';

/** Non-issued credential shape — must never authenticate /validate. */
export const e2eNonIssuedKeyShape =
	process.env.E2E_NON_ISSUED_API_KEY || 'TestApiKey123!TestApiKey123!';

/** @deprecated Use e2eNonIssuedKeyShape */
export const e2eLegacySharedSecret = e2eNonIssuedKeyShape;

export type IssuedAPIKey = {
	id: string;
	tenant_id: string;
	audience?: string;
	name: string;
	scopes: string[];
	key: string;
	expires_at?: string | null;
};

type CreateKeyBody = {
	tenant_id: string;
	audience?: 'internal' | 'tenant';
	name: string;
	scopes: string[];
	expires_in?: string;
	never_expires?: boolean;
	rate_limit?: number;
};

/** Issue a per-caller key via the superuser API (cleanup helper for UI specs). */
export async function issueAPIKey(
	suRequest: APIRequestContext,
	body: CreateKeyBody
): Promise<IssuedAPIKey> {
	const res = await suRequest.post('/api/admin/api-keys', {
		data: { audience: 'tenant', ...body }
	});
	const text = await res.text();
	expect(res.status(), `issue API key failed: ${text}`).toBe(201);
	const json = JSON.parse(text);
	const data = json.data as IssuedAPIKey;
	expect(data.key).toMatch(/^garde_/);
	expect(data.id).toBeTruthy();
	return data;
}

export async function revokeAPIKeyById(suRequest: APIRequestContext, keyId: string) {
	const res = await suRequest.delete(`/api/admin/api-keys/${encodeURIComponent(keyId)}`);
	return res;
}

export async function revokeTenantAPIKeys(suRequest: APIRequestContext, tenantId: string) {
	return suRequest.delete(`/api/admin/tenants/${encodeURIComponent(tenantId)}/api-keys`);
}

/** Best-effort cleanup so parallel workers do not leave keys behind. */
export async function cleanupTenantKeys(suRequest: APIRequestContext, tenantId: string) {
	await revokeTenantAPIKeys(suRequest, tenantId).catch(() => undefined);
}

/** Passes format checks, fails lookup. */
export const FAKE_SESSION_ID =
	'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

/**
 * Call /validate with an API key. Uses a well-formed but non-existent session id.
 * Auth success is "session invalid" (401): the key was accepted and the handler ran.
 * Auth failure is plain "unauthorized" (401) from the API-key middleware.
 */
export async function validateWithAPIKey(
	request: APIRequestContext,
	apiKey: string,
	sessionId = FAKE_SESSION_ID
) {
	return request.get('/api/validate', {
		headers: {
			'X-API-Key': apiKey,
			'X-Session-ID': sessionId
		},
		failOnStatusCode: false
	});
}

/** Assert the credential authenticated — handler rejected the fake session, not the key. */
export async function expectAPIKeyAccepted(res: Awaited<ReturnType<typeof validateWithAPIKey>>) {
	expect(res.status()).toBe(401);
	const body = await res.json();
	expect(String(body?.error?.message || '').toLowerCase()).toContain('session invalid');
}

/** Assert the credential was refused before the handler. */
export async function expectAPIKeyRejected(res: Awaited<ReturnType<typeof validateWithAPIKey>>) {
	expect(res.status()).toBe(401);
	const body = await res.json();
	const message = String(body?.error?.message || '').toLowerCase();
	expect(message).toContain('unauthorized');
	expect(message).not.toContain('session invalid');
}

/** Select a scope chip in the issue modal MultiSelectChips. */
export async function selectIssueScope(
	page: import('@playwright/test').Page,
	scopeName: string
) {
	const scopes = page.getByTestId('api-keys-issue-scopes');
	await scopes.getByTestId('multiselect-input').click();
	await expect(scopes.getByTestId('multiselect-dropdown')).toBeVisible();
	await scopes.locator(`[data-testid="multiselect-option"][data-key="${scopeName}"]`).click();
	await expect(
		scopes.locator(`[data-testid="multiselect-chip"][data-key="${scopeName}"]`)
	).toBeVisible();
	// Dropdown stays open after add(); close it so option text cannot cover expiry radios.
	// Prefer outside click over Escape so a parent Modal is never dismissed.
	await page.getByTestId('api-keys-issue-name').click();
	await expect(scopes.getByTestId('multiselect-dropdown')).toHaveCount(0);
}
