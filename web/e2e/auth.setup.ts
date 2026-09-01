import { test as setup, expect } from '@playwright/test';
import { e2eSuperuser, loginViaRequest, openDashboardSession } from './helpers/auth';
import { restoreSeedAdminAccess, ensureSeedAdminReady, ensureE2eCatalog } from './helpers/userApi';

/**
 * Once before the suite: seed permission catalog (fresh CI SQLite) and restore seed admin groups/permissions.
 * Does not share session cookies with workers (each worker logs in separately).
 */
setup('restore seed admin access', async ({ page }) => {
	await loginViaRequest(page.request, e2eSuperuser);
	await openDashboardSession(page);
	await ensureE2eCatalog(page.request);
	await ensureSeedAdminReady(page.request);
	await page.getByTestId('nav-logout').click();
});
