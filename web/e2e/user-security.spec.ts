import { test, expect } from './helpers/fixtures';
import { expectLoginRejected } from './helpers/auth';
import { openUserDetailFromSuperuser } from './helpers/userApi';

async function waitForToastGone(page: import('@playwright/test').Page) {
	await expect(page.getByTestId('toast')).toBeHidden({ timeout: 7000 });
}

async function confirmSecurityAction(
	page: import('@playwright/test').Page,
	toastText: string
) {
	await expect(page.getByTestId('confirm-modal-message')).toBeVisible();
	await page.getByTestId('confirm-modal-confirm').click();
	await expect(page.getByTestId('toast')).toContainText(toastText);
	await waitForToastGone(page);
}

/**
 * Lock/MFA on ephemeral users — seed admin stays untouched for parallel admin specs.
 */
test.describe('User security actions', () => {
	test('locks then unlocks the account', async ({ superuserPage: page, ephemeralUser }) => {
		await page.goto('/superuser');
		await openUserDetailFromSuperuser(page, ephemeralUser.email);

		await expect(page.getByTestId('user-detail-lock-row')).toHaveAttribute(
			'data-lock-state',
			'unlocked'
		);
		await page.getByTestId('user-detail-lock-btn').click();
		await confirmSecurityAction(page, 'Account locked by admin');
		await expect(page.getByTestId('user-detail-lock-row')).toHaveAttribute(
			'data-lock-state',
			'locked-admin'
		);

		await page.getByTestId('user-detail-lock-btn').click();
		await confirmSecurityAction(page, 'Account unlocked');
		await expect(page.getByTestId('user-detail-lock-row')).toHaveAttribute(
			'data-lock-state',
			'unlocked'
		);
	});

	test('locked account cannot sign in', async ({
		browser,
		superuserPage: suPage,
		ephemeralUser
	}) => {
		await suPage.goto('/superuser');
		await openUserDetailFromSuperuser(suPage, ephemeralUser.email);
		await suPage.getByTestId('user-detail-lock-btn').click();
		await confirmSecurityAction(suPage, 'Account locked by admin');

		const targetContext = await browser.newContext();
		const targetPage = await targetContext.newPage();
		try {
			await expectLoginRejected(targetPage, ephemeralUser);
			await expect(targetPage.getByTestId('dashboard-page')).toHaveCount(0);
		} finally {
			await targetContext.close();
		}

		await suPage.getByTestId('user-detail-lock-btn').click();
		await confirmSecurityAction(suPage, 'Account unlocked');
	});

	test('enforces MFA then stops enforcing', async ({ superuserPage: page, ephemeralUser }) => {
		await page.goto('/superuser');
		await openUserDetailFromSuperuser(page, ephemeralUser.email);

		await expect(page.getByTestId('user-detail-mfa-enforce-row')).toHaveAttribute(
			'data-enforced',
			'false'
		);
		await page.getByTestId('user-detail-mfa-enforce-btn').click();
		await confirmSecurityAction(page, 'MFA enforcement enabled');
		await expect(page.getByTestId('user-detail-mfa-enforce-row')).toHaveAttribute(
			'data-enforced',
			'true'
		);

		await page.getByTestId('user-detail-mfa-enforce-btn').click();
		await confirmSecurityAction(page, 'MFA enforcement removed');
		await expect(page.getByTestId('user-detail-mfa-enforce-row')).toHaveAttribute(
			'data-enforced',
			'false'
		);
	});
});
