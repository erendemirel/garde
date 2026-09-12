import { expect } from '@playwright/test';
import { test } from '../../helpers/fixtures';
import { describeTags, TAG } from '../../helpers/tags';
import {
	cleanupPATs,
	expectPATAccepted,
	expectPATRejected,
	expectPATRejectedOnValidate,
	issuePAT,
	issuePATViaUI,
	listPATs,
	meWithPAT,
	openTokensPage,
	confirmRevokePAT,
	revokePATById
} from '../../helpers/pats';
import { assertToast, waitForPageShell, waitForTokensPage } from '../../helpers/waits';
import { loginViaRequest } from '../../helpers/auth';
import { createEphemeralUser, deleteUserById } from '../../helpers/userApi';

test.describe(
	'Personal access tokens',
	describeTags(TAG.regular, TAG.selfService, TAG.focused, TAG.security),
	() => {
		test.describe('UI lifecycle', () => {
			test('issue default TTL, use Bearer, refuse manage-via-PAT, revoke', async ({
				regularUserPage: page,
				request
			}) => {
				await page.goto('/dashboard');
				await waitForPageShell(page, 'dashboard-page');
				await page.getByTestId('dashboard-link-tokens').click();
				await waitForTokensPage(page);

				const name = `e2e_pat_${Date.now()}`;
				const token = await issuePATViaUI(page, { name });

				const row = page.locator('[data-testid="tokens-row"]').filter({ hasText: name });
				await expect(row).toBeVisible();
				await expect(row.getByTestId('tokens-row-expires')).not.toHaveText('Never');

				await expectPATAccepted(await meWithPAT(request, token));

				const createViaPat = await request.post('/api/users/me/tokens', {
					headers: { Authorization: `Bearer ${token}` },
					data: { name: 'should-fail' }
				});
				expect(createViaPat.status()).toBe(401);
				expect(String((await createViaPat.json())?.error?.message || '')).toMatch(/session/i);

				const listViaPat = await request.get('/api/users/me/tokens', {
					headers: { Authorization: `Bearer ${token}` }
				});
				expect(listViaPat.status()).toBe(401);

				await row.getByTestId('tokens-revoke').click();
				await expect(page.getByTestId('confirm-modal-message')).toContainText(name);
				await confirmRevokePAT(page);
				await assertToast(page, /revoked/i);
				await expect(row).toHaveCount(0);

				await expectPATRejected(await meWithPAT(request, token));
			});

			test('requires a name; custom expiry enables submit; cancel creates nothing', async ({
				regularUserPage: page
			}) => {
				await openTokensPage(page);
				await waitForTokensPage(page);

				await page.getByTestId('tokens-issue').click();
				await expect(page.getByTestId('tokens-issue-modal')).toBeVisible();
				await expect(page.getByTestId('tokens-issue-submit')).toBeDisabled();

				await page.getByTestId('tokens-issue-name').fill('needs_name_ok');
				await expect(page.getByTestId('tokens-issue-submit')).toBeEnabled();

				await page.getByTestId('tokens-issue-expiry-custom').check();
				await expect(page.getByTestId('tokens-issue-submit')).toBeDisabled();
				await page.getByTestId('tokens-issue-expires-in').fill('24h');
				await expect(page.getByTestId('tokens-issue-submit')).toBeEnabled();

				await page.getByTestId('tokens-issue-cancel').click();
				await expect(page.getByTestId('tokens-issue-modal')).toHaveCount(0);

				const listed = await listPATs(page.request);
				expect(listed.tokens.some((t) => t.name === 'needs_name_ok')).toBeFalsy();
			});

			test('reveal modal blocks Done until acknowledged', async ({ regularUserPage: page }) => {
				await openTokensPage(page);
				await waitForTokensPage(page);

				const name = `e2e_ack_${Date.now()}`;
				await page.getByTestId('tokens-issue').click();
				await page.getByTestId('tokens-issue-name').fill(name);
				await page.getByTestId('tokens-issue-submit').click();

				await assertToast(page, name);
				await expect(page.getByTestId('tokens-reveal-modal')).toBeVisible();
				await expect(page.getByTestId('tokens-reveal-done')).toBeDisabled();
				await page.getByTestId('tokens-reveal-ack').check();
				await expect(page.getByTestId('tokens-reveal-done')).toBeEnabled();
				await page.getByTestId('tokens-reveal-done').click();

				await cleanupPATs(page.request);
			});

			test('never-expires token shows Never and still authenticates', async ({
				regularUserPage: page,
				request
			}) => {
				await openTokensPage(page);
				await waitForTokensPage(page);

				const name = `e2e_never_${Date.now()}`;
				const token = await issuePATViaUI(page, { name, expiry: 'never' });

				const row = page.locator(`[data-testid="tokens-row"]`).filter({ hasText: name });
				await expect(row.getByTestId('tokens-row-expires')).toHaveText('Never');
				await expectPATAccepted(await meWithPAT(request, token));

				await cleanupPATs(page.request);
			});

			test('custom TTL appears on the row', async ({ regularUserPage: page }) => {
				await openTokensPage(page);
				await waitForTokensPage(page);

				const name = `e2e_ttl_${Date.now()}`;
				await issuePATViaUI(page, { name, expiry: 'custom', expiresIn: '48h' });

				const row = page.locator(`[data-testid="tokens-row"]`).filter({ hasText: name });
				await expect(row.getByTestId('tokens-row-expires')).not.toHaveText('Never');
				const expiresText = (await row.getByTestId('tokens-row-expires').textContent()) || '';
				const expiresAt = new Date(expiresText);
				expect(Number.isNaN(expiresAt.getTime())).toBeFalsy();
				const deltaMs = expiresAt.getTime() - Date.now();
				expect(deltaMs).toBeGreaterThan(40 * 60 * 60 * 1000);
				expect(deltaMs).toBeLessThan(50 * 60 * 60 * 1000);

				await cleanupPATs(page.request);
			});

			test('revoke confirm cancel leaves the token usable', async ({
				regularUserPage: page,
				request
			}) => {
				await openTokensPage(page);
				await waitForTokensPage(page);

				const name = `e2e_cancel_rev_${Date.now()}`;
				const token = await issuePATViaUI(page, { name });
				const row = page.locator(`[data-testid="tokens-row"]`).filter({ hasText: name });

				await row.getByTestId('tokens-revoke').click();
				await page.getByTestId('confirm-modal-cancel').click();
				await expect(row).toBeVisible();
				await expectPATAccepted(await meWithPAT(request, token));

				await cleanupPATs(page.request);
			});
		});

		test.describe('API contract', () => {
			test('rejects bad names and expiry conflicts; list never returns secrets', async ({
				regularUserPage: page
			}) => {
				const session = page.request;

				const badName = await session.post('/api/users/me/tokens', {
					data: { name: 'bad name!' }
				});
				expect(badName.status()).toBe(400);

				const emptyName = await session.post('/api/users/me/tokens', { data: { name: '' } });
				expect(emptyName.status()).toBe(400);

				const conflict = await session.post('/api/users/me/tokens', {
					data: { name: 'conflict', expires_in: '24h', never_expires: true }
				});
				expect(conflict.status()).toBe(400);

				const tooLong = await session.post('/api/users/me/tokens', {
					data: { name: 'toolong', expires_in: '9000h' }
				});
				expect(tooLong.status()).toBe(400);

				const created = await issuePAT(session, { name: `e2e_list_${Date.now()}` });
				const listed = await listPATs(session);
				const row = listed.tokens.find((t) => t.id === created.id);
				expect(row).toBeTruthy();
				expect((row as { token?: string }).token).toBeUndefined();

				const missing = await revokePATById(session, 'deadbeefdeadbeef');
				expect(missing.status()).toBe(404);

				await cleanupPATs(session);
			});

			test('unauthenticated callers cannot list or create tokens', async ({ request }) => {
				expect((await request.get('/api/users/me/tokens')).status()).toBe(401);
				expect(
					(await request.post('/api/users/me/tokens', { data: { name: 'nope' } })).status()
				).toBe(401);
			});
		});

		test.describe('isolation', () => {
			test('PAT cannot authenticate /validate', async ({ regularUserPage: page, request }) => {
				const created = await issuePAT(page.request, { name: `e2e_val_${Date.now()}` });
				await expectPATRejectedOnValidate(request, created.token);
				await cleanupPATs(page.request);
			});

			test('user A cannot revoke user B tokens; B PAT does not see A', async ({
				playwright,
				baseURL,
				ephemeralUser,
				suRequest,
				uniqueSuffix,
				request
			}) => {
				const other = await createEphemeralUser(suRequest, `${uniqueSuffix}_b`);

				const ctxA = await playwright.request.newContext({ baseURL });
				const ctxB = await playwright.request.newContext({ baseURL });
				try {
					await loginViaRequest(ctxA, ephemeralUser);
					await loginViaRequest(ctxB, other);

					const aPat = await issuePAT(ctxA, { name: `a_${uniqueSuffix}` });
					const bPat = await issuePAT(ctxB, { name: `b_${uniqueSuffix}` });

					const steal = await ctxA.delete(`/api/users/me/tokens/${bPat.id}`);
					expect(steal.status()).toBe(404);

					await expectPATAccepted(await meWithPAT(request, bPat.token));

					const aList = await listPATs(ctxA);
					expect(aList.tokens.some((t) => t.id === bPat.id)).toBeFalsy();
					expect(aList.tokens.some((t) => t.id === aPat.id)).toBeTruthy();

					await cleanupPATs(ctxA);
					await cleanupPATs(ctxB);
				} finally {
					await ctxA.dispose();
					await ctxB.dispose();
					await deleteUserById(suRequest, other.id).catch(() => undefined);
				}
			});

			test('successful PAT use updates last_used_at', async ({
				regularUserPage: page,
				request
			}) => {
				const created = await issuePAT(page.request, { name: `e2e_touch_${Date.now()}` });
				const before = (await listPATs(page.request)).tokens.find((t) => t.id === created.id);
				expect(before).toBeTruthy();
				expect(before!.last_used_at == null || before!.last_used_at === '').toBeTruthy();

				await expectPATAccepted(await meWithPAT(request, created.token));

				await expect
					.poll(async () => {
						const after = (await listPATs(page.request)).tokens.find((t) => t.id === created.id);
						return after?.last_used_at;
					})
					.toBeTruthy();

				await cleanupPATs(page.request);
			});
		});
	}
);
