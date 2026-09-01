import { test, expect } from '../../helpers/fixtures';
import { describeTags, TAG } from '../../helpers/tags';
import { createEphemeralUser, deleteUserById } from '../../helpers/userApi';

/**
 * Admin scope — seed admin can only manage users in shared groups.
 * API returns 401 for out-of-scope GET /users/:id; the client treats that as session expiry.
 */
test.describe('User detail admin scope', describeTags(TAG.userDetail, TAG.admin, TAG.focused), () => {
	test('admin is signed out when opening a user outside their groups', async ({
		adminPage: page,
		suRequest,
		uniqueSuffix
	}) => {
		const groupName = `e2e_scope_${uniqueSuffix}`;
		let userId: string | undefined;

		try {
			const createGroup = await suRequest.post('/api/admin/groups', {
				data: { name: groupName, definition: 'E2E admin scope isolation' }
			});
			expect(createGroup.ok()).toBeTruthy();

			const isolated = await createEphemeralUser(suRequest, `scope_${uniqueSuffix}`, {
				groups: [groupName]
			});
			userId = isolated.id;

			await page.goto(`/admin/users/${isolated.id}`);
			await expect(page).toHaveURL('/', { timeout: 15_000 });
			await expect(page.getByTestId('login-page')).toBeVisible();
		} finally {
			if (userId) await deleteUserById(suRequest, userId).catch(() => undefined);
			await suRequest
				.delete(`/api/admin/groups/${encodeURIComponent(groupName)}`)
				.catch(() => undefined);
		}
	});
});
