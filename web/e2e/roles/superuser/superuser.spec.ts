import { test, expect } from '../../helpers/fixtures';
import { describeTags, TAG } from '../../helpers/tags';
import {
	waitForAdminManagement,
	waitForApiKeysPanel,
	waitForPageShell,
	waitForSuperuserCatalog,
	waitForUsersList,
	waitForVisibilityPanel
} from '../../helpers/waits';

test.describe('Superuser console', describeTags(TAG.superuser, TAG.focused), () => {
	test('opens Superuser from nav and shows users by default', async ({ superuserPage: page }) => {
		await page.goto('/dashboard');
		await waitForPageShell(page, 'dashboard-page');
		await page.getByTestId('nav-superuser').click();
		await expect(page).toHaveURL(/\/superuser/);
		await expect(page.getByTestId('superuser-page')).toBeVisible();
		await expect(page.getByTestId('superuser-tab-users')).toHaveAttribute('aria-selected', 'true');
		await waitForUsersList(page);
	});

	test('switches through catalog, management, and API keys tabs', async ({
		superuserPage: page
	}) => {
		await page.goto('/superuser');
		await waitForPageShell(page, 'superuser-page');
		await page.getByTestId('superuser-tab-permissions').click();
		await expect(page.getByTestId('superuser-catalog')).toHaveAttribute('data-mode', 'permissions');
		await waitForSuperuserCatalog(page);

		await page.getByTestId('superuser-tab-groups').click();
		await expect(page.getByTestId('superuser-catalog')).toHaveAttribute('data-mode', 'groups');
		await waitForSuperuserCatalog(page);

		await page.getByTestId('superuser-tab-visibility').click();
		await expect(page.getByTestId('superuser-visibility-panel')).toBeVisible();
		await waitForVisibilityPanel(page);

		await page.getByTestId('superuser-tab-admin-management').click();
		await expect(page.getByTestId('superuser-admin-management-panel')).toBeVisible();
		await waitForAdminManagement(page);

		await page.getByTestId('superuser-tab-api-keys').click();
		await expect(page.getByTestId('superuser-panel-api-keys')).toBeVisible();
		await waitForApiKeysPanel(page);
	});
});
