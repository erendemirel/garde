import { expect } from '@playwright/test';
import { test } from '../helpers/fixtures';
import { describeTags, TAG } from '../helpers/tags';
import {
	cleanupPATs,
	confirmRevokePAT,
	expectPATAccepted,
	expectPATRejected,
	issuePATViaUI,
	meWithPAT,
	openTokensPage
} from '../helpers/pats';
import { assertToast, waitForTokensPage } from '../helpers/waits';

/**
 * Multi-step PAT lifecycle: issue → use → rotate → retire old → wipe.
 * Mirrors how a developer would cut CI over without downtime.
 */
test.describe(
	'PAT rotation journey',
	describeTags(TAG.journey, TAG.regular, TAG.selfService, TAG.security),
	() => {
		test('issue, use, rotate, revoke old, then wipe remaining', async ({
			regularUserPage: page,
			request,
			uniqueSuffix
		}) => {
			await openTokensPage(page);
			await waitForTokensPage(page);

			try {
				const v1Name = `v1_${uniqueSuffix}`;
				const v1 = await issuePATViaUI(page, { name: v1Name });
				await expectPATAccepted(await meWithPAT(request, v1));
				await expect(page.locator('[data-testid="tokens-row"]')).toHaveCount(1);

				const v2Name = `v2_${uniqueSuffix}`;
				const v2 = await issuePATViaUI(page, { name: v2Name });
				await expect(page.locator('[data-testid="tokens-row"]')).toHaveCount(2);
				await expectPATAccepted(await meWithPAT(request, v1));
				await expectPATAccepted(await meWithPAT(request, v2));

				const oldRow = page.locator('[data-testid="tokens-row"]').filter({ hasText: v1Name });
				await oldRow.getByTestId('tokens-revoke').click();
				await expect(page.getByTestId('confirm-modal-message')).toContainText(v1Name);
				await confirmRevokePAT(page);
				await assertToast(page, /revoked/i);
				await expect(oldRow).toHaveCount(0);
				await expect(page.locator('[data-testid="tokens-row"]')).toHaveCount(1);

				await expectPATRejected(await meWithPAT(request, v1));
				await expectPATAccepted(await meWithPAT(request, v2));

				const newRow = page.locator('[data-testid="tokens-row"]').filter({ hasText: v2Name });
				await newRow.getByTestId('tokens-revoke').click();
				await confirmRevokePAT(page);
				await expect(page.getByTestId('tokens-empty').or(page.getByTestId('tokens-list'))).toBeVisible();
				await expect(page.locator('[data-testid="tokens-row"]')).toHaveCount(0);
				await expectPATRejected(await meWithPAT(request, v2));
			} finally {
				await cleanupPATs(page.request);
			}
		});
	}
);
