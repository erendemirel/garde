import { test, expect } from '../../helpers/fixtures';
import { describeTags, TAG } from '../../helpers/tags';
import {
	cleanupTenantKeys,
	e2eSharedApiKey,
	expectAPIKeyAccepted,
	expectAPIKeyRejected,
	issueAPIKey,
	revokeAPIKeyById,
	selectIssueScope,
	validateWithAPIKey
} from '../../helpers/apiKeys';
import { assertToast, waitForApiKeysPanel, waitForPageShell } from '../../helpers/waits';
import { e2eAdmin, loginViaRequest } from '../../helpers/auth';

async function openApiKeys(page: import('@playwright/test').Page) {
	await page.goto('/superuser?tab=api-keys');
	await waitForPageShell(page, 'superuser-page');
	await expect(page.getByTestId('superuser-tab-api-keys')).toHaveAttribute('aria-selected', 'true');
	await waitForApiKeysPanel(page);
}

async function acknowledgeReveal(page: import('@playwright/test').Page) {
	await expect(page.getByTestId('api-keys-reveal-modal')).toBeVisible();
	const secret = page.getByTestId('api-keys-reveal-secret');
	await expect(secret).toContainText(/^garde_/);
	const plaintext = (await secret.textContent())?.trim() || '';
	expect(plaintext).toMatch(/^garde_[a-f0-9]+_/);
	await expect(page.getByTestId('api-keys-reveal-done')).toBeDisabled();
	await page.getByTestId('api-keys-reveal-ack').check();
	await expect(page.getByTestId('api-keys-reveal-done')).toBeEnabled();
	await page.getByTestId('api-keys-reveal-done').click();
	await expect(page.getByTestId('api-keys-reveal-modal')).toHaveCount(0);
	return plaintext;
}

test.describe('Superuser API keys', describeTags(TAG.superuser, TAG.focused), () => {
	test.describe('access control', () => {
		test('admin cannot open API key management endpoints', async ({ playwright, baseURL }) => {
			const ctx = await playwright.request.newContext({ baseURL });
			await loginViaRequest(ctx, e2eAdmin);

			const scopes = await ctx.get('/api/admin/api-key-scopes');
			expect(scopes.status()).toBe(401);

			const list = await ctx.get('/api/admin/api-keys');
			expect(list.status()).toBe(401);

			const create = await ctx.post('/api/admin/api-keys', {
				data: { tenant_id: 'nope', name: 'nope', scopes: ['validate'] }
			});
			expect(create.status()).toBe(401);

			const revoke = await ctx.delete('/api/admin/api-keys/does-not-exist');
			expect(revoke.status()).toBe(401);

			const revokeTenant = await ctx.delete('/api/admin/tenants/nope/api-keys');
			expect(revokeTenant.status()).toBe(401);

			await ctx.dispose();
		});

		test('regular user cannot manage or list API keys', async ({
			playwright,
			baseURL,
			ephemeralUser
		}) => {
			const ctx = await playwright.request.newContext({ baseURL });
			await loginViaRequest(ctx, ephemeralUser);

			expect((await ctx.get('/api/admin/api-keys')).status()).toBe(401);
			expect(
				(
					await ctx.post('/api/admin/api-keys', {
						data: { tenant_id: 'x', name: 'x', scopes: ['validate'] }
					})
				).status()
			).toBe(401);

			await ctx.dispose();
		});

		test('admin has no Superuser API Keys tab in the nav shell', async ({ adminPage: page }) => {
			await page.goto('/superuser?tab=api-keys');
			await waitForPageShell(page, 'superuser-page');
			await expect(page.getByTestId('superuser-access-denied')).toBeVisible();
			await expect(page.getByTestId('superuser-tab-api-keys')).toHaveCount(0);
		});
	});

	test.describe('issue validation', () => {
		test('requires tenant, name, and an explicit scope before submit is enabled', async ({
			superuserPage: page
		}) => {
			await openApiKeys(page);
			await page.getByTestId('api-keys-issue').click();
			await expect(page.getByTestId('api-keys-issue-modal')).toBeVisible();

			await expect(page.getByTestId('api-keys-issue-submit')).toBeDisabled();

			await page.getByTestId('api-keys-issue-tenant').fill('e2e_scope_gate');
			await expect(page.getByTestId('api-keys-issue-submit')).toBeDisabled();

			await page.getByTestId('api-keys-issue-name').fill('needs_scope');
			await expect(page.getByTestId('api-keys-issue-submit')).toBeDisabled();

			await selectIssueScope(page, 'validate');
			await expect(page.getByTestId('api-keys-issue-submit')).toBeEnabled();

			await page.getByTestId('api-keys-issue-expiry-custom').check();
			await expect(page.getByTestId('api-keys-issue-submit')).toBeDisabled();
			await page.getByTestId('api-keys-issue-expires-in').fill('48h');
			await expect(page.getByTestId('api-keys-issue-submit')).toBeEnabled();

			await page.getByTestId('api-keys-issue-cancel').click();
			await expect(page.getByTestId('api-keys-issue-modal')).toHaveCount(0);
		});

		test('issue cancel creates nothing', async ({
			superuserPage: page,
			suRequest,
			uniqueSuffix
		}) => {
			const tenantId = `e2e_cancel_issue_${uniqueSuffix}`;
			await openApiKeys(page);
			await page.getByTestId('api-keys-issue').click();
			await page.getByTestId('api-keys-issue-tenant').fill(tenantId);
			await page.getByTestId('api-keys-issue-name').fill('should_not_exist');
			await selectIssueScope(page, 'validate');
			await page.getByTestId('api-keys-issue-cancel').click();
			await expect(page.getByTestId('api-keys-issue-modal')).toHaveCount(0);

			const listed = await suRequest.get(
				`/api/admin/api-keys?tenant_id=${encodeURIComponent(tenantId)}`
			);
			expect(listed.ok()).toBeTruthy();
			const body = await listed.json();
			expect(body.data.keys ?? []).toHaveLength(0);
		});

		test('invalid custom duration surfaces the API error and creates nothing', async ({
			superuserPage: page,
			suRequest,
			uniqueSuffix
		}) => {
			const tenantId = `e2e_bad_ttl_${uniqueSuffix}`;
			try {
				await openApiKeys(page);
				await page.getByTestId('api-keys-issue').click();
				await page.getByTestId('api-keys-issue-tenant').fill(tenantId);
				await page.getByTestId('api-keys-issue-name').fill('bad_ttl');
				await selectIssueScope(page, 'validate');
				await page.getByTestId('api-keys-issue-expiry-custom').check();
				await page.getByTestId('api-keys-issue-expires-in').fill('not-a-duration');
				await page.getByTestId('api-keys-issue-submit').click();

				await assertToast(page, /expires_in|duration/i);
				await expect(page.getByTestId('api-keys-reveal-modal')).toHaveCount(0);
				await expect(page.getByTestId('api-keys-issue-modal')).toBeVisible();

				const listed = await suRequest.get(
					`/api/admin/api-keys?tenant_id=${encodeURIComponent(tenantId)}`
				);
				const body = await listed.json();
				expect(body.data.keys ?? []).toHaveLength(0);
			} finally {
				await cleanupTenantKeys(suRequest, tenantId);
			}
		});
	});

	test.describe('issue flow', () => {
		test('issues a key, shows the secret once, and lists it under the tenant', async ({
			superuserPage: page,
			suRequest,
			uniqueSuffix
		}) => {
			const tenantId = `e2e_ui_${uniqueSuffix}`;
			const keyName = `ui_issue_${uniqueSuffix}`;

			try {
				await openApiKeys(page);
				await page.getByTestId('api-keys-issue').click();
				await page.getByTestId('api-keys-issue-tenant').fill(tenantId);
				await page.getByTestId('api-keys-issue-name').fill(keyName);
				await selectIssueScope(page, 'validate');
				await page.getByTestId('api-keys-issue-submit').click();

				await assertToast(page, keyName);
				const plaintext = await acknowledgeReveal(page);

				const tenant = page.locator(
					`[data-testid="api-keys-tenant"][data-tenant-id="${tenantId}"]`
				);
				await expect(tenant).toBeVisible();
				await expect(tenant).toHaveAttribute('data-expanded', 'true');
				const row = tenant.locator(
					`[data-testid="api-keys-row"][data-key-name="${keyName}"]`
				);
				await expect(row).toBeVisible();
				await expect(row.getByTestId('api-keys-row-scopes')).toContainText('validate');
				await expect(row.getByTestId('api-keys-row-expires')).not.toContainText('Never');

				// Secret authenticates — fake session is rejected by the handler, not the key.
				await expectAPIKeyAccepted(await validateWithAPIKey(suRequest, plaintext));

				// Closing the reveal cleared the only copy from the UI — list has no secret.
				await expect(page.getByTestId('api-keys-reveal-secret')).toHaveCount(0);
				const listed = await suRequest.get(
					`/api/admin/api-keys?tenant_id=${encodeURIComponent(tenantId)}`
				);
				expect(listed.ok()).toBeTruthy();
				const listedBody = await listed.json();
				expect(listedBody.data.keys[0].key).toBeUndefined();
			} finally {
				await cleanupTenantKeys(suRequest, tenantId);
			}
		});

		test('reveal modal stays open until the operator acknowledges', async ({
			superuserPage: page,
			suRequest,
			uniqueSuffix
		}) => {
			const tenantId = `e2e_reveal_${uniqueSuffix}`;
			try {
				await openApiKeys(page);
				await page.getByTestId('api-keys-issue').click();
				await page.getByTestId('api-keys-issue-tenant').fill(tenantId);
				await page.getByTestId('api-keys-issue-name').fill('reveal_gate');
				await selectIssueScope(page, 'validate');
				await page.getByTestId('api-keys-issue-submit').click();
				await assertToast(page, 'reveal_gate');

				await expect(page.getByTestId('api-keys-reveal-modal')).toBeVisible();
				await expect(page.getByTestId('api-keys-reveal-done')).toBeDisabled();
				// Non-dismissible: Escape must not lose the only copy of the secret.
				await page.keyboard.press('Escape');
				await expect(page.getByTestId('api-keys-reveal-modal')).toBeVisible();
				await expect(page.getByTestId('api-keys-reveal-warning')).toContainText(
					/only time|cannot be retrieved/i
				);

				await page.getByTestId('api-keys-reveal-ack').check();
				await page.getByTestId('api-keys-reveal-done').click();
				await expect(page.getByTestId('api-keys-reveal-modal')).toHaveCount(0);
			} finally {
				await cleanupTenantKeys(suRequest, tenantId);
			}
		});

		test('custom lifetime and never-expires paths both reach the server', async ({
			superuserPage: page,
			suRequest,
			uniqueSuffix
		}) => {
			const tenantId = `e2e_ttl_${uniqueSuffix}`;

			try {
				await openApiKeys(page);

				await page.getByTestId('api-keys-issue').click();
				await page.getByTestId('api-keys-issue-tenant').fill(tenantId);
				await page.getByTestId('api-keys-issue-name').fill(`custom_${uniqueSuffix}`);
				await selectIssueScope(page, 'validate');
				await page.getByTestId('api-keys-issue-expiry-custom').check();
				await page.getByTestId('api-keys-issue-expires-in').fill('48h');
				await page.getByTestId('api-keys-issue-submit').click();
				await assertToast(page, `custom_${uniqueSuffix}`);
				await acknowledgeReveal(page);

				const listed = await suRequest.get(
					`/api/admin/api-keys?tenant_id=${encodeURIComponent(tenantId)}`
				);
				const data = await listed.json();
				const custom = (data.data.keys as { name: string; expires_at?: string }[]).find(
					(k) => k.name === `custom_${uniqueSuffix}`
				);
				expect(custom?.expires_at).toBeTruthy();
				const expiresAt = Date.parse(String(custom?.expires_at));
				const hours = (expiresAt - Date.now()) / (60 * 60 * 1000);
				expect(hours).toBeGreaterThan(40);
				expect(hours).toBeLessThan(50);

				await page.getByTestId('api-keys-issue').click();
				await page.getByTestId('api-keys-issue-tenant').fill(tenantId);
				await page.getByTestId('api-keys-issue-name').fill(`immortal_${uniqueSuffix}`);
				await selectIssueScope(page, 'validate');
				await page.getByTestId('api-keys-issue-expiry-never').check();
				await page.getByTestId('api-keys-issue-submit').click();
				await assertToast(page, `immortal_${uniqueSuffix}`);
				await acknowledgeReveal(page);

				const row = page.locator(
					`[data-testid="api-keys-row"][data-key-name="immortal_${uniqueSuffix}"]`
				);
				await expect(row.getByTestId('api-keys-row-expires')).toContainText('Never');
			} finally {
				await cleanupTenantKeys(suRequest, tenantId);
			}
		});
	});

	test.describe('revoke', () => {
		test('revoking one key stops /validate for that credential only', async ({
			superuserPage: page,
			suRequest,
			uniqueSuffix
		}) => {
			const tenantId = `e2e_rev_${uniqueSuffix}`;
			const keep = await issueAPIKey(suRequest, {
				tenant_id: tenantId,
				name: `keep_${uniqueSuffix}`,
				scopes: ['validate']
			});
			const drop = await issueAPIKey(suRequest, {
				tenant_id: tenantId,
				name: `drop_${uniqueSuffix}`,
				scopes: ['validate']
			});

			try {
				await openApiKeys(page);
				await page.getByTestId('api-keys-search').fill(tenantId);
				const dropRow = page.locator(
					`[data-testid="api-keys-row"][data-key-id="${drop.id}"]`
				);
				await expect(dropRow).toBeVisible();
				await dropRow.getByTestId('api-keys-revoke').click();
				await expect(page.getByTestId('confirm-modal-message')).toContainText(drop.name);
				await page.getByTestId('confirm-modal-confirm').click();
				await assertToast(page, /Revoked key/i);
				await expect(dropRow).toHaveCount(0);

				const dead = await validateWithAPIKey(suRequest, drop.key);
				await expectAPIKeyRejected(dead);

				const alive = await validateWithAPIKey(suRequest, keep.key);
				await expectAPIKeyAccepted(alive);
			} finally {
				await cleanupTenantKeys(suRequest, tenantId);
			}
		});

		test('revoke cancel leaves the key working', async ({
			superuserPage: page,
			suRequest,
			uniqueSuffix
		}) => {
			const tenantId = `e2e_rev_cancel_${uniqueSuffix}`;
			const key = await issueAPIKey(suRequest, {
				tenant_id: tenantId,
				name: `alive_${uniqueSuffix}`,
				scopes: ['validate']
			});

			try {
				await openApiKeys(page);
				await page.getByTestId('api-keys-search').fill(tenantId);
				const row = page.locator(`[data-testid="api-keys-row"][data-key-id="${key.id}"]`);
				await row.getByTestId('api-keys-revoke').click();
				await page.getByTestId('confirm-modal-cancel').click();
				await expect(page.getByTestId('confirm-modal-message')).toHaveCount(0);
				await expect(row).toBeVisible();
				await expectAPIKeyAccepted(await validateWithAPIKey(suRequest, key.key));
			} finally {
				await cleanupTenantKeys(suRequest, tenantId);
			}
		});

		test('revoke-all removes every key for a tenant', async ({
			superuserPage: page,
			suRequest,
			uniqueSuffix
		}) => {
			const tenantId = `e2e_bulk_${uniqueSuffix}`;
			const a = await issueAPIKey(suRequest, {
				tenant_id: tenantId,
				name: `a_${uniqueSuffix}`,
				scopes: ['validate']
			});
			const b = await issueAPIKey(suRequest, {
				tenant_id: tenantId,
				name: `b_${uniqueSuffix}`,
				scopes: ['validate']
			});

			try {
				await openApiKeys(page);
				await page.getByTestId('api-keys-search').fill(tenantId);
				const tenant = page.locator(
					`[data-testid="api-keys-tenant"][data-tenant-id="${tenantId}"]`
				);
				await expect(tenant).toBeVisible();
				await tenant.getByTestId('api-keys-revoke-tenant').click();
				await expect(page.getByTestId('confirm-modal-message')).toContainText(tenantId);
				await expect(page.getByTestId('confirm-modal-message')).toContainText('2');
				await page.getByTestId('confirm-modal-confirm').click();
				await assertToast(page, /Revoked 2/i);
				await expect(tenant).toHaveCount(0);

				await expectAPIKeyRejected(await validateWithAPIKey(suRequest, a.key));
				await expectAPIKeyRejected(await validateWithAPIKey(suRequest, b.key));
			} finally {
				await cleanupTenantKeys(suRequest, tenantId);
			}
		});
	});

	test.describe('API contract and edge cases', () => {
		test('shared API_KEY still authenticates /validate in the single-listener dev layout', async ({
			suRequest
		}) => {
			// dev.secrets sets PUBLIC_VALIDATE_SHARED_KEY=true and SERVICE_LISTENER=false.
			// This asserts the acknowledgement gate kept the chosen posture, not that the
			// shared key is desirable — mesh layouts refuse it on the public edge.
			await expectAPIKeyAccepted(await validateWithAPIKey(suRequest, e2eSharedApiKey));
		});

		test('garbage and forged-looking credentials are refused', async ({ suRequest }) => {
			await expectAPIKeyRejected(await validateWithAPIKey(suRequest, 'not-a-real-key'));
			// Shape matches a tenant key, but the id/secret are unknown.
			await expectAPIKeyRejected(
				await validateWithAPIKey(
					suRequest,
					'garde_deadbeef_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
				)
			);
		});

		test('create rejects the shapes the UI must never allow through', async ({
			suRequest,
			uniqueSuffix
		}) => {
			const tenantId = `e2e_contract_${uniqueSuffix}`;

			const noScopes = await suRequest.post('/api/admin/api-keys', {
				data: { tenant_id: tenantId, name: 'x' }
			});
			expect(noScopes.status()).toBe(400);
			expect(String((await noScopes.json()).error.message)).toMatch(/scope/i);

			const emptyScopes = await suRequest.post('/api/admin/api-keys', {
				data: { tenant_id: tenantId, name: 'x', scopes: [] }
			});
			expect(emptyScopes.status()).toBe(400);

			const noTenant = await suRequest.post('/api/admin/api-keys', {
				data: { name: 'x', scopes: ['validate'] }
			});
			expect(noTenant.status()).toBe(400);
			expect(String((await noTenant.json()).error.message)).toMatch(/tenant_id/i);

			const badTenant = await suRequest.post('/api/admin/api-keys', {
				data: { tenant_id: 'bad client!', name: 'x', scopes: ['validate'] }
			});
			expect(badTenant.status()).toBe(400);

			const unknownScope = await suRequest.post('/api/admin/api-keys', {
				data: { tenant_id: tenantId, name: 'x', scopes: ['admin'] }
			});
			expect(unknownScope.status()).toBe(400);
			expect(String((await unknownScope.json()).error.message)).toMatch(/scope/i);

			const tooLong = await suRequest.post('/api/admin/api-keys', {
				data: {
					tenant_id: tenantId,
					name: 'x',
					scopes: ['validate'],
					expires_in: '9000h'
				}
			});
			expect(tooLong.status()).toBe(400);
			expect(String((await tooLong.json()).error.message)).toMatch(/8760h|exceed/i);

			const conflict = await suRequest.post('/api/admin/api-keys', {
				data: {
					tenant_id: tenantId,
					name: 'x',
					scopes: ['validate'],
					expires_in: '24h',
					never_expires: true
				}
			});
			expect(conflict.status()).toBe(400);
			expect(String((await conflict.json()).error.message)).toMatch(/never_expires|both/i);

			const negativeRate = await suRequest.post('/api/admin/api-keys', {
				data: {
					tenant_id: tenantId,
					name: 'x',
					scopes: ['validate'],
					rate_limit: -1
				}
			});
			expect(negativeRate.status()).toBe(400);

			const scopes = await suRequest.get('/api/admin/api-key-scopes');
			expect(scopes.ok()).toBeTruthy();
			const scopeBody = await scopes.json();
			expect(scopeBody.data.map((s: { name: string }) => s.name)).toContain('validate');

			// Nothing above should have created a live key.
			const listed = await suRequest.get(
				`/api/admin/api-keys?tenant_id=${encodeURIComponent(tenantId)}`
			);
			expect(((await listed.json()).data.keys ?? []) as unknown[]).toHaveLength(0);
		});

		test('revoke unknown key or empty tenant is 404; re-revoke is idempotent', async ({
			suRequest,
			uniqueSuffix
		}) => {
			const missing = await suRequest.delete('/api/admin/api-keys/ffffffffffff');
			expect(missing.status()).toBe(404);

			const emptyTenant = await suRequest.delete(
				`/api/admin/tenants/${encodeURIComponent(`e2e_empty_${uniqueSuffix}`)}/api-keys`
			);
			expect(emptyTenant.status()).toBe(404);

			const tenantId = `e2e_dbl_${uniqueSuffix}`;
			const key = await issueAPIKey(suRequest, {
				tenant_id: tenantId,
				name: 'once',
				scopes: ['validate']
			});
			try {
				expect((await revokeAPIKeyById(suRequest, key.id)).status()).toBe(200);
				// Already-revoked records stay visible and re-revoke succeeds without
				// resurrecting the credential — the important edge is that /validate dies.
				expect((await revokeAPIKeyById(suRequest, key.id)).status()).toBe(200);
				await expectAPIKeyRejected(await validateWithAPIKey(suRequest, key.key));
			} finally {
				await cleanupTenantKeys(suRequest, tenantId);
			}
		});

		test('a successful /validate call records last_used_at', async ({
			suRequest,
			uniqueSuffix
		}) => {
			const tenantId = `e2e_touch_${uniqueSuffix}`;
			const key = await issueAPIKey(suRequest, {
				tenant_id: tenantId,
				name: 'touch_me',
				scopes: ['validate']
			});
			try {
				const before = await suRequest.get(
					`/api/admin/api-keys?tenant_id=${encodeURIComponent(tenantId)}`
				);
				expect((await before.json()).data.keys[0].last_used_at ?? null).toBeNull();

				await expectAPIKeyAccepted(await validateWithAPIKey(suRequest, key.key));

				const after = await suRequest.get(
					`/api/admin/api-keys?tenant_id=${encodeURIComponent(tenantId)}`
				);
				const lastUsed = (await after.json()).data.keys[0].last_used_at;
				expect(lastUsed).toBeTruthy();
				expect(Date.now() - Date.parse(lastUsed)).toBeLessThan(60_000);
			} finally {
				await cleanupTenantKeys(suRequest, tenantId);
			}
		});
	});

	test.describe('search and grouping', () => {
		test('filters tenants by id and key name', async ({
			superuserPage: page,
			suRequest,
			uniqueSuffix
		}) => {
			const tenantA = `e2e_sa_${uniqueSuffix}`;
			const tenantB = `e2e_sb_${uniqueSuffix}`;
			await issueAPIKey(suRequest, {
				tenant_id: tenantA,
				name: `alpha_${uniqueSuffix}`,
				scopes: ['validate']
			});
			await issueAPIKey(suRequest, {
				tenant_id: tenantB,
				name: `beta_${uniqueSuffix}`,
				scopes: ['validate']
			});

			try {
				await openApiKeys(page);
				await page.getByTestId('api-keys-search').fill(tenantA);
				await expect(
					page.locator(`[data-testid="api-keys-tenant"][data-tenant-id="${tenantA}"]`)
				).toBeVisible();
				await expect(
					page.locator(`[data-testid="api-keys-tenant"][data-tenant-id="${tenantB}"]`)
				).toHaveCount(0);

				await page.getByTestId('api-keys-search').fill(`beta_${uniqueSuffix}`);
				await expect(
					page.locator(`[data-testid="api-keys-tenant"][data-tenant-id="${tenantB}"]`)
				).toBeVisible();
				await expect(
					page.locator(`[data-testid="api-keys-tenant"][data-tenant-id="${tenantA}"]`)
				).toHaveCount(0);
			} finally {
				await cleanupTenantKeys(suRequest, tenantA);
				await cleanupTenantKeys(suRequest, tenantB);
			}
		});

		test('tenant group collapses and expands without losing rows', async ({
			superuserPage: page,
			suRequest,
			uniqueSuffix
		}) => {
			const tenantId = `e2e_fold_${uniqueSuffix}`;
			const key = await issueAPIKey(suRequest, {
				tenant_id: tenantId,
				name: `fold_${uniqueSuffix}`,
				scopes: ['validate']
			});
			try {
				await openApiKeys(page);
				await page.getByTestId('api-keys-search').fill(tenantId);
				const tenant = page.locator(
					`[data-testid="api-keys-tenant"][data-tenant-id="${tenantId}"]`
				);
				await expect(tenant).toHaveAttribute('data-expanded', 'true');
				await expect(
					tenant.locator(`[data-testid="api-keys-row"][data-key-id="${key.id}"]`)
				).toBeVisible();

				await tenant.getByTestId('api-keys-tenant-toggle').click();
				await expect(tenant).toHaveAttribute('data-expanded', 'false');
				await expect(tenant.getByTestId('api-keys-tenant-keys')).toHaveCount(0);

				await tenant.getByTestId('api-keys-tenant-toggle').click();
				await expect(tenant).toHaveAttribute('data-expanded', 'true');
				await expect(
					tenant.locator(`[data-testid="api-keys-row"][data-key-id="${key.id}"]`)
				).toBeVisible();
			} finally {
				await cleanupTenantKeys(suRequest, tenantId);
			}
		});
	});
});
