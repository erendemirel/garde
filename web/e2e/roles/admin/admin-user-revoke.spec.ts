import { test, expect } from '../../helpers/fixtures';
import { loginAs, startUserSession } from '../../helpers/auth';
import {
	createEphemeralUser,
	openUserDetailFromAdmin
} from '../../helpers/userApi';
import { waitForSignedOut, matchUserUpdate, matchRevokeSessions, LOAD_TIMEOUT } from '../../helpers/waits';

async function waitForToastGone(page: import('@playwright/test').Page) {
	await expect(page.getByTestId('toast')).toBeHidden({ timeout: 7000 });
}

test.describe('Admin revoke and delete', () => {
	test('revoking sessions signs the target user out', async ({
		browser,
		adminPage,
		ephemeralUser
	}) => {
		const targetContext = await browser.newContext();
		const targetPage = await targetContext.newPage();
		await startUserSession(targetPage, ephemeralUser);
		await expect(targetPage.getByTestId('dashboard-page')).toBeVisible();

		await adminPage.goto('/admin');
		await openUserDetailFromAdmin(adminPage, ephemeralUser.email);
		const revokeResponse = adminPage.waitForResponse(matchRevokeSessions, { timeout: LOAD_TIMEOUT });
		await adminPage.getByTestId('user-detail-revoke-btn').click();
		await adminPage.getByTestId('confirm-modal-confirm').click();
		await revokeResponse;
		await expect(adminPage.getByTestId('toast')).toContainText('Sessions revoked', {
			timeout: LOAD_TIMEOUT
		});
		await waitForToastGone(adminPage);

		await waitForSignedOut(targetPage);

		await targetContext.close();
	});

	test('deleting a logged-in user signs them out on navigation', async ({
		browser,
		adminPage,
		suRequest,
		uniqueSuffix
	}) => {
		const user = await createEphemeralUser(suRequest, `admin_del_${uniqueSuffix}`);
		const targetContext = await browser.newContext();
		const targetPage = await targetContext.newPage();
		try {
			await startUserSession(targetPage, user);
			await expect(targetPage.getByTestId('dashboard-page')).toBeVisible();

			await adminPage.goto('/admin');
			await openUserDetailFromAdmin(adminPage, user.email);
			const deleteResponse = adminPage.waitForResponse(
				(res) => res.request().method() === 'DELETE' && res.url().includes('/api/users/'),
				{ timeout: LOAD_TIMEOUT }
			);
			await adminPage.getByTestId('user-detail-delete-btn').click();
			await adminPage.getByTestId('confirm-modal-confirm').click();
			await deleteResponse;
			await expect(adminPage.getByTestId('toast')).toContainText('User deleted', {
				timeout: LOAD_TIMEOUT
			});
			await waitForToastGone(adminPage);

			await waitForSignedOut(targetPage);
		} finally {
			await targetContext.close();
		}
	});
});
