import { test as setup, expect } from '@playwright/test';
import { e2eSuperuser, loginViaRequest, openDashboardSession } from './helpers/auth';
import { restoreSeedAdminAccess } from './helpers/userApi';

/**
 * Once before the suite: ensure seed admin has expected groups/permissions.
 * Does not share session cookies with workers (each worker logs in separately).
 */
setup('restore seed admin access', async ({ page }) => {
	await loginViaRequest(page.request, e2eSuperuser);
	await openDashboardSession(page);
	await restoreSeedAdminAccess(page.request);
	await page.getByTestId('nav-logout').click();
});
