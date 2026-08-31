import { test, expect } from './helpers/fixtures';
import { expectLoginRejected, loginAs } from './helpers/auth';
import {
	createEphemeralUser,
	deleteUserById,
	openUserDetailFromSuperuser
} from './helpers/userApi';

async function waitForToastGone(page: import('@playwright/test').Page) {
	await expect(page.getByTestId('toast')).toBeHidden({ timeout: 7000 });
}

/**
 * Account approval lifecycle. Registration UI is covered in public-auth;
 * here we create pending users via API so parallel workers stay fast and
 * avoid SvelteKit hydration races on the register form.
 */
test.describe('Register account approval', () => {
	test('registers, gets approved, can sign in, then is deleted', async ({
		page,
		superuserPage: suPage,
		suRequest,
		uniqueSuffix
	}) => {
		const user = await createEphemeralUser(suRequest, `approve_${uniqueSuffix}`, {
			approve: false,
			groups: []
		});
		try {
			await expectLoginRejected(page, user);

			await suPage.goto('/superuser');
			await openUserDetailFromSuperuser(suPage, user.email);
			await expect(suPage.getByTestId('user-detail-account-approval')).toHaveAttribute(
				'data-approval-state',
				'pending'
			);
			await suPage.getByTestId('user-detail-approve-account').click();
			await suPage.getByTestId('confirm-modal-confirm').click();
			await expect(suPage.getByTestId('toast')).toContainText('Account approved');
			await waitForToastGone(suPage);

			await loginAs(page, user);
			await expect(page.getByTestId('dashboard-email')).toHaveText(user.email);
		} finally {
			await deleteUserById(suRequest, user.id).catch(() => undefined);
		}
	});

	test('registers, gets rejected, stays blocked, then is deleted', async ({
		page,
		superuserPage: suPage,
		suRequest,
		uniqueSuffix
	}) => {
		const user = await createEphemeralUser(suRequest, `reject_${uniqueSuffix}`, {
			approve: false,
			groups: []
		});
		try {
			await suPage.goto('/superuser');
			await openUserDetailFromSuperuser(suPage, user.email);
			await suPage.getByTestId('user-detail-reject-account').click();
			await suPage.getByTestId('confirm-modal-confirm').click();
			await expect(suPage.getByTestId('toast')).toContainText('rejected');
			await waitForToastGone(suPage);
			await expect(suPage.getByTestId('user-detail-account-approval')).toHaveAttribute(
				'data-approval-state',
				'rejected'
			);

			await expectLoginRejected(page, user);
		} finally {
			await deleteUserById(suRequest, user.id).catch(() => undefined);
		}
	});

	test('registers, gets rejected, then approved anyway and can sign in', async ({
		page,
		superuserPage: suPage,
		suRequest,
		uniqueSuffix
	}) => {
		const user = await createEphemeralUser(suRequest, `anyway_${uniqueSuffix}`, {
			approve: false,
			groups: []
		});
		try {
			await suPage.goto('/superuser');
			await openUserDetailFromSuperuser(suPage, user.email);
			await suPage.getByTestId('user-detail-reject-account').click();
			await suPage.getByTestId('confirm-modal-confirm').click();
			await expect(suPage.getByTestId('toast')).toContainText('rejected');
			await waitForToastGone(suPage);

			await suPage.getByTestId('user-detail-approve-account').click();
			await expect(suPage.getByTestId('confirm-modal-message')).toContainText(/anyway|Approve/i);
			await suPage.getByTestId('confirm-modal-confirm').click();
			await expect(suPage.getByTestId('toast')).toContainText('Account approved');
			await waitForToastGone(suPage);

			await loginAs(page, user);
			await expect(page.getByTestId('dashboard-email')).toHaveText(user.email);
		} finally {
			await deleteUserById(suRequest, user.id).catch(() => undefined);
		}
	});
});
