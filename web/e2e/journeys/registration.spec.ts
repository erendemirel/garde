import { test, expect } from '../helpers/fixtures';
import { expectLoginRejected, signInApprovedUser } from '../helpers/auth';
import {
	createEphemeralUser,
	deleteUserById,
	findUserByEmail,
	openUserDetailFromAdmin,
	openUserDetailFromSuperuser
} from '../helpers/userApi';
import { matchUserUpdate, waitForPageShell, LOAD_TIMEOUT, REDIRECT_TIMEOUT, waitForToastGone } from '../helpers/waits';
import { describeTags, TAG } from '../helpers/tags';

test.describe.configure({ timeout: 120_000 });

async function fillRegisterForm(page: import('@playwright/test').Page, email: string, password: string) {
	for (let attempt = 0; attempt < 10; attempt++) {
		await page.getByTestId('register-email').fill(email);
		await page.getByTestId('register-password').fill(password);
		await page.getByTestId('register-confirm').fill(password);
		if ((await page.getByTestId('register-email').inputValue()) === email) return;
	}
	throw new Error('register form inputs did not stabilize after hydration');
}

async function submitRegisterForm(page: import('@playwright/test').Page, email: string, password: string) {
	let lastError: unknown;
	for (let attempt = 0; attempt < 3; attempt++) {
		await page.goto('/register', { waitUntil: 'domcontentloaded' });
		await expect(page.getByTestId('register-page')).toBeVisible({ timeout: REDIRECT_TIMEOUT });
		await expect(page.getByTestId('register-form')).toHaveAttribute('data-ready', 'true', {
			timeout: REDIRECT_TIMEOUT
		});
		await expect(page.getByTestId('register-submit')).toBeEnabled({ timeout: REDIRECT_TIMEOUT });
		await fillRegisterForm(page, email, password);

		const registerResponse = page.waitForResponse(
			(res) => res.url().includes('/api/users') && res.request().method() === 'POST',
			{ timeout: LOAD_TIMEOUT }
		);
		await page.getByTestId('register-submit').click();

		try {
			const res = await registerResponse;
			expect(res.ok()).toBeTruthy();
			return res;
		} catch (err) {
			lastError = err;
			if (attempt < 2) continue;
			throw err;
		}
	}
	throw lastError;
}

/**
 * Pending-account approval journeys. Registration UI is covered in auth/register;
 * pending users are API-created here for parallel-safe speed.
 */
test.describe('Registration approval', describeTags(TAG.journey, TAG.registration), () => {
	test.describe('superuser', () => {
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

				await signInApprovedUser(page, user);
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

				await signInApprovedUser(page, user);
				await expect(page.getByTestId('dashboard-email')).toHaveText(user.email);
			} finally {
				await deleteUserById(suRequest, user.id).catch(() => undefined);
			}
		});

		test('reject account confirmation cancel keeps pending state', async ({
			superuserPage: suPage,
			suRequest,
			uniqueSuffix
		}) => {
			const user = await createEphemeralUser(suRequest, `reject_cancel_${uniqueSuffix}`, {
				approve: false,
				groups: []
			});
			try {
				await suPage.goto('/superuser');
				await openUserDetailFromSuperuser(suPage, user.email);
				await suPage.getByTestId('user-detail-reject-account').click();
				await expect(suPage.getByTestId('confirm-modal-message')).toBeVisible();
				await suPage.getByTestId('confirm-modal-cancel').click();

				await expect(suPage.getByTestId('confirm-modal-message')).toHaveCount(0);
				await expect(suPage.getByTestId('user-detail-account-approval')).toHaveAttribute(
					'data-approval-state',
					'pending'
				);
			} finally {
				await deleteUserById(suRequest, user.id).catch(() => undefined);
			}
		});
	});

	test.describe('admin', () => {
		test('approves a pending registration for an in-scope user', async ({
			page,
			adminPage,
			suRequest,
			uniqueSuffix
		}) => {
			const user = await createEphemeralUser(suRequest, `admin_approve_${uniqueSuffix}`, {
				approve: false,
				groups: ['group_a']
			});
			try {
				await expectLoginRejected(page, user);

				await adminPage.goto('/admin');
				await openUserDetailFromAdmin(adminPage, user.email);
				await expect(adminPage.getByTestId('user-detail-account-approval')).toHaveAttribute(
					'data-approval-state',
					'pending'
				);
				await adminPage.getByTestId('user-detail-approve-account').click();
				await adminPage.getByTestId('confirm-modal-confirm').click();
				await expect(adminPage.getByTestId('toast')).toContainText('Account approved');
				await waitForToastGone(adminPage);

				await signInApprovedUser(page, user);
				await expect(page.getByTestId('dashboard-email')).toHaveText(user.email);
			} finally {
				await deleteUserById(suRequest, user.id).catch(() => undefined);
			}
		});

		test('rejects a pending registration for an in-scope user', async ({
			page,
			adminPage,
			suRequest,
			uniqueSuffix
		}) => {
			const user = await createEphemeralUser(suRequest, `admin_reject_${uniqueSuffix}`, {
				approve: false,
				groups: ['group_a']
			});
			try {
				await adminPage.goto('/admin');
				await openUserDetailFromAdmin(adminPage, user.email);
				await adminPage.getByTestId('user-detail-reject-account').click();
				await adminPage.getByTestId('confirm-modal-confirm').click();
				await expect(adminPage.getByTestId('toast')).toContainText('rejected');
				await waitForToastGone(adminPage);
				await expect(adminPage.getByTestId('user-detail-account-approval')).toHaveAttribute(
					'data-approval-state',
					'rejected'
				);

				await expectLoginRejected(page, user);
			} finally {
				await deleteUserById(suRequest, user.id).catch(() => undefined);
			}
		});

		test('rejects then approves anyway for an in-scope user', async ({
			page,
			adminPage,
			suRequest,
			uniqueSuffix
		}) => {
			const user = await createEphemeralUser(suRequest, `admin_anyway_${uniqueSuffix}`, {
				approve: false,
				groups: ['group_a']
			});
			try {
				await adminPage.goto('/admin');
				await openUserDetailFromAdmin(adminPage, user.email);
				await adminPage.getByTestId('user-detail-reject-account').click();
				await adminPage.getByTestId('confirm-modal-confirm').click();
				await expect(adminPage.getByTestId('toast')).toContainText('rejected');
				await waitForToastGone(adminPage);

				await adminPage.getByTestId('user-detail-approve-account').click();
				await expect(adminPage.getByTestId('confirm-modal-message')).toContainText(/anyway|Approve/i);
				await adminPage.getByTestId('confirm-modal-confirm').click();
				await expect(adminPage.getByTestId('toast')).toContainText('Account approved');
				await waitForToastGone(adminPage);

				await signInApprovedUser(page, user);
				await expect(page.getByTestId('dashboard-email')).toHaveText(user.email);
			} finally {
				await deleteUserById(suRequest, user.id).catch(() => undefined);
			}
		});

		test('reject account confirmation cancel keeps pending state', async ({
			adminPage,
			suRequest,
			uniqueSuffix
		}) => {
			const user = await createEphemeralUser(suRequest, `admin_rej_cancel_${uniqueSuffix}`, {
				approve: false,
				groups: ['group_a']
			});
			try {
				await adminPage.goto('/admin');
				await openUserDetailFromAdmin(adminPage, user.email);
				await adminPage.getByTestId('user-detail-reject-account').click();
				await expect(adminPage.getByTestId('confirm-modal-message')).toBeVisible();
				await adminPage.getByTestId('confirm-modal-cancel').click();

				await expect(adminPage.getByTestId('confirm-modal-message')).toHaveCount(0);
				await expect(adminPage.getByTestId('user-detail-account-approval')).toHaveAttribute(
					'data-approval-state',
					'pending'
				);
			} finally {
				await deleteUserById(suRequest, user.id).catch(() => undefined);
			}
		});
	});

	test.describe('actor handoffs', () => {
		test('admin rejects registration, superuser approves anyway, user can sign in', async ({
			page,
			adminPage,
			superuserPage: suPage,
			suRequest,
			uniqueSuffix
		}) => {
			const user = await createEphemeralUser(suRequest, `handoff_reg_${uniqueSuffix}`, {
				approve: false,
				groups: ['group_a']
			});
			try {
				await expectLoginRejected(page, user);

				await adminPage.goto('/admin');
				await openUserDetailFromAdmin(adminPage, user.email);
				await adminPage.getByTestId('user-detail-reject-account').click();
				await adminPage.getByTestId('confirm-modal-confirm').click();
				await expect(adminPage.getByTestId('toast')).toContainText('rejected');
				await waitForToastGone(adminPage);
				await expect(adminPage.getByTestId('user-detail-account-approval')).toHaveAttribute(
					'data-approval-state',
					'rejected'
				);

				await suPage.goto('/superuser');
				await openUserDetailFromSuperuser(suPage, user.email);
				await suPage.getByTestId('user-detail-approve-account').click();
				await expect(suPage.getByTestId('confirm-modal-message')).toContainText(/anyway|Approve/i);
				await suPage.getByTestId('confirm-modal-confirm').click();
				await expect(suPage.getByTestId('toast')).toContainText('Account approved');
				await waitForToastGone(suPage);

				await signInApprovedUser(page, user);
				await expect(page.getByTestId('dashboard-email')).toHaveText(user.email);
			} finally {
				await deleteUserById(suRequest, user.id).catch(() => undefined);
			}
		});
	});

	test.describe('from register UI', () => {
		test('register form, admin approves, user can sign in', async ({
			page,
			adminPage,
			suRequest,
			uniqueSuffix
		}) => {
			const email = `e2e.ui.reg.${uniqueSuffix}@example.com`;
			const password = 'DevAdminTest123!';

			await submitRegisterForm(page, email, password);
			await expect(page.getByTestId('register-success-panel')).toBeVisible();

			const summary = await findUserByEmail(suRequest, email);
			expect(summary?.id).toBeTruthy();
			const userId = summary!.id;

			try {
				// Bootstrap in-scope membership so the seed admin can open this pending user.
				const scopeRes = await suRequest.put(`/api/users/${userId}`, {
					data: { groups: { group_a: true } }
				});
				expect(scopeRes.ok()).toBeTruthy();

				await adminPage.goto('/admin');
				await openUserDetailFromAdmin(adminPage, email);
				await expect(adminPage.getByTestId('user-detail-account-approval')).toHaveAttribute(
					'data-approval-state',
					'pending'
				);
				await adminPage.getByTestId('user-detail-approve-account').click();
				await adminPage.getByTestId('confirm-modal-confirm').click();
				await expect(adminPage.getByTestId('toast')).toContainText('Account approved');
				await waitForToastGone(adminPage);

				await signInApprovedUser(page, { email, password });
				await expect(page.getByTestId('dashboard-email')).toHaveText(email);
			} finally {
				await deleteUserById(suRequest, userId).catch(() => undefined);
			}
		});
	});
});
