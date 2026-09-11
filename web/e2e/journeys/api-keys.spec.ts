import { test, expect } from '../helpers/fixtures';
import { describeTags, TAG } from '../helpers/tags';
import {
	cleanupTenantKeys,
	expectAPIKeyAccepted,
	expectAPIKeyRejected,
	selectIssueScope,
	validateWithAPIKey
} from '../helpers/apiKeys';
import { assertToast, waitForApiKeysPanel, waitForPageShell } from '../helpers/waits';

/**
 * Multi-step API key lifecycle: issue → use → rotate → retire old → wipe holder.
 * Mirrors how an operator would cut a caller over without downtime.
 */
test.describe(
	'API key rotation journey',
	describeTags(TAG.journey, TAG.superuser, TAG.security),
	() => {
		test('issue, validate, rotate, revoke old, then revoke-all', async ({
			superuserPage: page,
			suRequest,
			uniqueSuffix
		}) => {
			const tenantId = `e2e_journey_${uniqueSuffix}`;

			async function openPanel() {
				await page.goto('/superuser?tab=api-keys');
				await waitForPageShell(page, 'superuser-page');
				await waitForApiKeysPanel(page);
			}

			async function issueNamed(name: string) {
				await page.getByTestId('api-keys-issue').click();
				await expect(page.getByTestId('api-keys-issue-modal')).toBeVisible();
				await page.getByTestId('api-keys-issue-tenant').fill(tenantId);
				await page.getByTestId('api-keys-issue-name').fill(name);
				await selectIssueScope(page, 'validate');
				await page.getByTestId('api-keys-issue-submit').click();
				await assertToast(page, name);
				await expect(page.getByTestId('api-keys-reveal-modal')).toBeVisible();
				const secret =
					(await page.getByTestId('api-keys-reveal-secret').textContent())?.trim() || '';
				expect(secret).toMatch(/^garde_/);
				await page.getByTestId('api-keys-reveal-ack').check();
				await page.getByTestId('api-keys-reveal-done').click();
				await expect(page.getByTestId('api-keys-reveal-modal')).toHaveCount(0);
				return secret;
			}

			try {
				await openPanel();

				// 1. First credential for the holder — proves /validate accepts it.
				const v1 = await issueNamed(`v1_${uniqueSuffix}`);
				await expectAPIKeyAccepted(await validateWithAPIKey(suRequest, v1));

				const tenant = page.locator(
					`[data-testid="api-keys-tenant"][data-tenant-id="${tenantId}"]`
				);
				await expect(tenant).toBeVisible();
				await expect(tenant.getByTestId('api-keys-row')).toHaveCount(1);

				// 2. Rotation: second key for the same tenant, both live during cutover.
				const v2 = await issueNamed(`v2_${uniqueSuffix}`);
				await expect(tenant.getByTestId('api-keys-row')).toHaveCount(2);
				await expectAPIKeyAccepted(await validateWithAPIKey(suRequest, v1));
				await expectAPIKeyAccepted(await validateWithAPIKey(suRequest, v2));

				// 3. Retire the old credential only — new one keeps working.
				const oldRow = tenant.locator(
					`[data-testid="api-keys-row"][data-key-name="v1_${uniqueSuffix}"]`
				);
				await oldRow.getByTestId('api-keys-revoke').click();
				await expect(page.getByTestId('confirm-modal-message')).toContainText(`v1_${uniqueSuffix}`);
				await page.getByTestId('confirm-modal-confirm').click();
				await assertToast(page, /Revoked key/i);
				await expect(oldRow).toHaveCount(0);
				await expect(tenant.getByTestId('api-keys-row')).toHaveCount(1);

				await expectAPIKeyRejected(await validateWithAPIKey(suRequest, v1));
				await expectAPIKeyAccepted(await validateWithAPIKey(suRequest, v2));

				// 4. Holder compromised — wipe every remaining credential in one step.
				await tenant.getByTestId('api-keys-revoke-tenant').click();
				await expect(page.getByTestId('confirm-modal-message')).toContainText(tenantId);
				await page.getByTestId('confirm-modal-confirm').click();
				await assertToast(page, /Revoked 1/i);
				await expect(tenant).toHaveCount(0);

				await expectAPIKeyRejected(await validateWithAPIKey(suRequest, v2));

				// Panel stays usable after the wipe; empty filter for this tenant.
				await page.getByTestId('api-keys-search').fill(tenantId);
				await expect(
					page.locator(`[data-testid="api-keys-tenant"][data-tenant-id="${tenantId}"]`)
				).toHaveCount(0);
			} finally {
				await cleanupTenantKeys(suRequest, tenantId);
			}
		});
	}
);
