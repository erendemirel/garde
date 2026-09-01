import { test, expect } from '../../helpers/fixtures';
import { describeTags, TAG } from '../../helpers/tags';
import { createEphemeralUser, deleteUserById } from '../../helpers/userApi';
import { waitForOutOfScopeDenied } from '../../helpers/waits';

/**
 * Admin scope — admins only manage users who share a group with them.
 * Out-of-scope GET /users/:id → 401 "unauthorized"; UI shows access denied (admin stays signed in).
 */
test.describe('User detail admin scope', describeTags(TAG.userDetail, TAG.admin, TAG.focused), () => {
	test('admin sees access denied when opening a user outside their groups', async ({
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

			await waitForOutOfScopeDenied(page, isolated.id);

			// Session must remain valid — admin can still use the console.
			await page.goto('/admin');
			await expect(page.getByTestId('admin-page')).toBeVisible();
			await expect(page.getByTestId('login-page')).toHaveCount(0);
		} finally {
			if (userId) await deleteUserById(suRequest, userId).catch(() => undefined);
			await suRequest
				.delete(`/api/admin/groups/${encodeURIComponent(groupName)}`)
				.catch(() => undefined);
		}
	});
});
