import { test, expect } from '../helpers/fixtures';
import { describeTags, TAG } from '../helpers/tags';
import {
	cleanupClientKeys,
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
			const clientId = `e2e_journey_${uniqueSuffix}`;

			async function openPanel() {
				await page.goto('/superuser?tab=api-keys');
				await waitForPageShell(page, 'superuser-page');
				await waitForApiKeysPanel(page);
			}

			async function issueNamed(name: string) {
				await page.getByTestId('api-keys-issue').click();
				await expect(page.getByTestId('api-keys-issue-modal')).toBeVisible();
				await page.getByTestId('api-keys-issue-client').fill(clientId);
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

				const client = page.locator(
					`[data-testid="api-keys-client"][data-client-id="${clientId}"]`
				);
				await expect(client).toBeVisible();
				await expect(client.getByTestId('api-keys-row')).toHaveCount(1);

				// 2. Rotation: second key for the same client, both live during cutover.
				const v2 = await issueNamed(`v2_${uniqueSuffix}`);
				await expect(client.getByTestId('api-keys-row')).toHaveCount(2);
				await expectAPIKeyAccepted(await validateWithAPIKey(suRequest, v1));
				await expectAPIKeyAccepted(await validateWithAPIKey(suRequest, v2));

				// 3. Retire the old credential only — new one keeps working.
				const oldRow = client.locator(
					`[data-testid="api-keys-row"][data-key-name="v1_${uniqueSuffix}"]`
				);
				await oldRow.getByTestId('api-keys-revoke').click();
				await expect(page.getByTestId('confirm-modal-message')).toContainText(`v1_${uniqueSuffix}`);
				await page.getByTestId('confirm-modal-confirm').click();
				await assertToast(page, /Revoked key/i);
				await expect(oldRow).toHaveCount(0);
				await expect(client.getByTestId('api-keys-row')).toHaveCount(1);

				await expectAPIKeyRejected(await validateWithAPIKey(suRequest, v1));
				await expectAPIKeyAccepted(await validateWithAPIKey(suRequest, v2));

				// 4. Holder compromised — wipe every remaining credential in one step.
				await client.getByTestId('api-keys-revoke-client').click();
				await expect(page.getByTestId('confirm-modal-message')).toContainText(clientId);
				await page.getByTestId('confirm-modal-confirm').click();
				await assertToast(page, /Revoked 1/i);
				await expect(client).toHaveCount(0);

				await expectAPIKeyRejected(await validateWithAPIKey(suRequest, v2));

				// Panel stays usable after the wipe; empty filter for this client.
				await page.getByTestId('api-keys-search').fill(clientId);
				await expect(
					page.locator(`[data-testid="api-keys-client"][data-client-id="${clientId}"]`)
				).toHaveCount(0);
			} finally {
				await cleanupClientKeys(suRequest, clientId);
			}
		});
	}
);
