import { test, expect } from '../../helpers/fixtures';
import { describeTags, TAG } from '../../helpers/tags';
import { expectLoginRejected } from '../../helpers/auth';
import {
	createEphemeralUser,
	deleteUserById,
	openUserDetailFromAdmin
} from '../../helpers/userApi';

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

test.describe('Admin user security actions', describeTags(TAG.admin, TAG.userDetail, TAG.security, TAG.focused), () => {
	test('locks then unlocks an in-scope user', async ({ adminPage: page, ephemeralUser }) => {
		await page.goto('/admin');
		await openUserDetailFromAdmin(page, ephemeralUser.email);

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

	test('locked in-scope user cannot sign in', async ({
		browser,
		adminPage,
		ephemeralUser
	}) => {
		await adminPage.goto('/admin');
		await openUserDetailFromAdmin(adminPage, ephemeralUser.email);
		await adminPage.getByTestId('user-detail-lock-btn').click();
		await confirmSecurityAction(adminPage, 'Account locked by admin');

		const targetContext = await browser.newContext();
		const targetPage = await targetContext.newPage();
		try {
			await expectLoginRejected(targetPage, ephemeralUser);
		} finally {
			await targetContext.close();
		}

		await adminPage.getByTestId('user-detail-lock-btn').click();
		await confirmSecurityAction(adminPage, 'Account unlocked');
	});

	test('enforces MFA then stops enforcing on an in-scope user', async ({
		adminPage: page,
		ephemeralUser
	}) => {
		await page.goto('/admin');
		await openUserDetailFromAdmin(page, ephemeralUser.email);

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

	test('MFA enforce confirmation cancel keeps enforcement unchanged', async ({
		adminPage: page,
		ephemeralUser
	}) => {
		await page.goto('/admin');
		await openUserDetailFromAdmin(page, ephemeralUser.email);

		await page.getByTestId('user-detail-mfa-enforce-btn').click();
		await expect(page.getByTestId('confirm-modal-message')).toBeVisible();
		await page.getByTestId('confirm-modal-cancel').click();

		await expect(page.getByTestId('confirm-modal-message')).toHaveCount(0);
		await expect(page.getByTestId('user-detail-mfa-enforce-row')).toHaveAttribute(
			'data-enforced',
			'false'
		);
	});

	test('pending approval account has no admin lock control', async ({
		adminPage: page,
		suRequest,
		uniqueSuffix
	}) => {
		const user = await createEphemeralUser(suRequest, `pending_lock_${uniqueSuffix}`, {
			approve: false,
			groups: ['group_a']
		});
		try {
			await page.goto('/admin');
			await openUserDetailFromAdmin(page, user.email);
			await expect(page.getByTestId('user-detail-account-approval')).toHaveAttribute(
				'data-approval-state',
				'pending'
			);
			await expect(page.getByTestId('user-detail-lock-btn')).toHaveCount(0);
		} finally {
			await deleteUserById(suRequest, user.id).catch(() => undefined);
		}
	});
});
