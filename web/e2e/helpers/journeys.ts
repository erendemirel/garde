import { expect, type APIRequestContext, type Page } from '@playwright/test';
import { totpCode } from './totp';
import {
	LOAD_TIMEOUT,
	matchUserUpdate,
	waitForPageShell,
	waitForRequestUpdateCatalog,
	waitForRequestUpdateGroups,
	waitForSuperuserCatalog,
	waitForVisibilityPanel
} from './waits';
import {
	openUserDetailFromAdmin,
	openUserDetailFromSuperuser,
	patchUserMaps
} from './userApi';

export const VISIBILITY_GROUP = 'group_a';
export const SCOPE_GROUP = 'asdfasdf';

/** When true, act helpers wait for API/UI completion without toast copy assertions (for @epic specs). */
export type JourneyActOptions = { outcomesOnly?: boolean };

export async function waitForToastGone(page: Page) {
	await expect(page.getByTestId('toast')).toBeHidden({ timeout: 7000 });
}

async function dismissToast(page: Page, pattern?: string | RegExp, opts?: JourneyActOptions) {
	if (opts?.outcomesOnly) {
		const toast = page.getByTestId('toast');
		if (await toast.isVisible().catch(() => false)) {
			await waitForToastGone(page);
		}
		return;
	}
	if (pattern) {
		await expect(page.getByTestId('toast')).toContainText(pattern, { timeout: LOAD_TIMEOUT });
	}
	await waitForToastGone(page);
}

export async function reloadDashboardWithMe(page: Page) {
	const meResponse = page.waitForResponse(
		(res) => res.url().includes('/api/users/me') && res.request().method() === 'GET',
		{ timeout: LOAD_TIMEOUT }
	);
	await page.reload();
	await meResponse;
	await waitForPageShell(page, 'dashboard-page');
}

/** User still unauthenticated — outcome check for epics (details in auth/registration specs). */
export async function expectStillSignedOut(page: Page, path = '/dashboard') {
	await page.goto(path);
	await expect(page.getByTestId('login-page')).toBeVisible({ timeout: LOAD_TIMEOUT });
}

export async function fillRegisterForm(page: Page, email: string, password: string) {
	await expect(page.getByTestId('register-form')).toHaveAttribute('data-ready', 'true', {
		timeout: LOAD_TIMEOUT
	});
	for (let attempt = 0; attempt < 10; attempt++) {
		await page.getByTestId('register-email').fill(email);
		await page.getByTestId('register-password').fill(password);
		await page.getByTestId('register-confirm').fill(password);
		if ((await page.getByTestId('register-email').inputValue()) === email) return;
	}
	throw new Error('register form inputs did not stabilize after hydration');
}

export async function submitRegisterForm(page: Page, email: string, password: string) {
	await page.goto('/register', { waitUntil: 'domcontentloaded' });
	await expect(page.getByTestId('register-page')).toBeVisible({ timeout: LOAD_TIMEOUT });
	await fillRegisterForm(page, email, password);

	const registerResponse = page.waitForResponse(
		(res) => res.url().includes('/api/users') && res.request().method() === 'POST',
		{ timeout: LOAD_TIMEOUT }
	);
	await page.getByTestId('register-submit').click();
	const res = await registerResponse;
	expect(res.ok()).toBeTruthy();
}

export async function createCatalogItem(
	page: Page,
	tab: 'permissions' | 'groups',
	name: string,
	definition: string,
	opts?: JourneyActOptions
) {
	await page.getByTestId(`superuser-tab-${tab}`).click();
	await waitForSuperuserCatalog(page);
	await page.getByTestId('superuser-catalog-create').click();
	await page.getByTestId('superuser-catalog-item-name').fill(name);
	await page.getByTestId('superuser-catalog-item-definition').fill(definition);
	await page.getByTestId('superuser-catalog-item-save').click();
	await dismissToast(page, name, opts);
	if (opts?.outcomesOnly) {
		await expect(page.getByTestId('superuser-catalog-item-modal')).toHaveCount(0);
	}
}

export async function addVisibilityInMatrix(
	page: Page,
	permissionName: string,
	groupName: string,
	opts?: JourneyActOptions
) {
	await page.getByTestId('superuser-tab-visibility').click();
	await waitForVisibilityPanel(page);
	await page.getByTestId('superuser-visibility-view-matrix').click();
	await page.getByTestId('superuser-visibility-search').fill(permissionName);
	const cell = page.locator(
		`[data-testid="superuser-visibility-cell"][data-permission-name="${permissionName}"][data-group-name="${groupName}"]`
	);
	await expect(cell).toBeVisible();
	await cell.click();
	await dismissToast(page, /Visibility/i, opts);
	if (!opts?.outcomesOnly) {
		await expect(cell).toHaveAttribute('aria-pressed', 'true');
	}
}

export async function removeVisibilityInMatrix(
	page: Page,
	permissionName: string,
	groupName: string,
	opts?: JourneyActOptions
) {
	await page.getByTestId('superuser-tab-visibility').click();
	await waitForVisibilityPanel(page);
	await page.getByTestId('superuser-visibility-view-matrix').click();
	await page.getByTestId('superuser-visibility-search').fill(permissionName);
	const cell = page.locator(
		`[data-testid="superuser-visibility-cell"][data-permission-name="${permissionName}"][data-group-name="${groupName}"]`
	);
	await expect(cell).toHaveAttribute('aria-pressed', 'true');
	await cell.click();
	await page.getByTestId('confirm-modal-confirm').click();
	await dismissToast(page, /removed/i, opts);
}

export async function cleanupCatalog(
	suRequest: APIRequestContext,
	permissionName: string,
	groupName?: string
) {
	await suRequest
		.delete('/api/admin/permissions/visibility', {
			data: { permission_name: permissionName, group_name: VISIBILITY_GROUP }
		})
		.catch(() => undefined);
	await suRequest
		.delete(`/api/admin/permissions/${encodeURIComponent(permissionName)}`)
		.catch(() => undefined);
	if (groupName) {
		await suRequest
			.delete(`/api/admin/groups/${encodeURIComponent(groupName)}`)
			.catch(() => undefined);
	}
}

export async function adminApproveAccount(
	adminPage: Page,
	email: string,
	opts?: JourneyActOptions
) {
	await adminPage.goto('/admin');
	await openUserDetailFromAdmin(adminPage, email);
	const updateResponse = adminPage.waitForResponse(matchUserUpdate, { timeout: LOAD_TIMEOUT });
	await adminPage.getByTestId('user-detail-approve-account').click();
	await adminPage.getByTestId('confirm-modal-confirm').click();
	await updateResponse;
	await dismissToast(adminPage, 'Account approved', opts);
}

export async function adminRejectAccount(
	adminPage: Page,
	email: string,
	opts?: JourneyActOptions
) {
	await adminPage.goto('/admin');
	await openUserDetailFromAdmin(adminPage, email);
	const updateResponse = adminPage.waitForResponse(matchUserUpdate, { timeout: LOAD_TIMEOUT });
	await adminPage.getByTestId('user-detail-reject-account').click();
	await adminPage.getByTestId('confirm-modal-confirm').click();
	await updateResponse;
	await dismissToast(adminPage, 'rejected', opts);
}

export async function superuserApproveAccountAnyway(
	suPage: Page,
	email: string,
	opts?: JourneyActOptions
) {
	await suPage.goto('/superuser');
	await openUserDetailFromSuperuser(suPage, email);
	const updateResponse = suPage.waitForResponse(matchUserUpdate, { timeout: LOAD_TIMEOUT });
	await suPage.getByTestId('user-detail-approve-account').click();
	await suPage.getByTestId('confirm-modal-confirm').click();
	await updateResponse;
	await dismissToast(suPage, 'Account approved', opts);
}

export async function adminApproveUpdate(
	adminPage: Page,
	email: string,
	opts?: JourneyActOptions
) {
	await adminPage.goto('/admin');
	await waitForPageShell(adminPage, 'admin-page');
	await openUserDetailFromAdmin(adminPage, email);
	if (!opts?.outcomesOnly) {
		await expect(adminPage.getByTestId('user-detail-pending-update')).toBeVisible();
	}
	const updateResponse = adminPage.waitForResponse(matchUserUpdate, { timeout: LOAD_TIMEOUT });
	await adminPage.getByTestId('user-detail-approve-update').click();
	await adminPage.getByTestId('confirm-modal-confirm').click();
	await updateResponse;
	await dismissToast(adminPage, 'Update approved', opts);
}

export async function adminRejectUpdate(
	adminPage: Page,
	email: string,
	opts?: JourneyActOptions
) {
	await adminPage.goto('/admin');
	await waitForPageShell(adminPage, 'admin-page');
	await openUserDetailFromAdmin(adminPage, email);
	if (!opts?.outcomesOnly) {
		await expect(adminPage.getByTestId('user-detail-pending-update')).toBeVisible();
	}
	const updateResponse = adminPage.waitForResponse(matchUserUpdate, { timeout: LOAD_TIMEOUT });
	await adminPage.getByTestId('user-detail-reject-update').click();
	await adminPage.getByTestId('confirm-modal-confirm').click();
	await updateResponse;
	await dismissToast(adminPage, 'Update rejected', opts);
}

export async function stageGroupAddByName(page: Page, groupName: string, opts?: JourneyActOptions) {
	const ms = page.locator('[data-testid="multiselect"][data-label="Groups"]');
	await ms.getByTestId('multiselect-input').fill(groupName);
	await ms.locator(`[data-testid="multiselect-option"][data-key="${groupName}"]`).click();
	if (!opts?.outcomesOnly) {
		await expect(page.getByTestId('change-summary-added')).toBeVisible();
	}
	await page.keyboard.press('Escape');
}

export async function stagePermissionAddByName(
	page: Page,
	permissionName: string,
	opts?: JourneyActOptions
) {
	const ms = page.locator('[data-testid="multiselect"][data-label="Permissions"]');
	await ms.getByTestId('multiselect-input').fill(permissionName);
	await ms.locator(`[data-testid="multiselect-option"][data-key="${permissionName}"]`).click();
	if (!opts?.outcomesOnly) {
		await expect(page.getByTestId('change-summary-added')).toBeVisible();
	}
	await page.keyboard.press('Escape');
}

export async function stagePermissionRemoveByName(page: Page, permissionName: string) {
	const ms = page.locator('[data-testid="multiselect"][data-label="Permissions"]');
	const chip = ms.locator(`[data-testid="multiselect-chip"][data-key="${permissionName}"]`);
	await expect(chip).toBeVisible();
	await chip.click();
	await expect(page.getByTestId('change-summary-removed')).toBeVisible();
}

export async function submitRequestUpdate(page: Page, opts?: JourneyActOptions) {
	const submitResponse = page.waitForResponse(
		(res) =>
			res.url().includes('/api/users/request-update-from-admin') &&
			res.request().method() === 'POST',
		{ timeout: LOAD_TIMEOUT }
	);
	await page.getByTestId('request-update-submit').click();
	await submitResponse;
	if (!opts?.outcomesOnly) {
		await expect(page.getByTestId('toast')).toContainText('Request submitted');
	}
	await page.waitForURL(/\/dashboard/, { timeout: LOAD_TIMEOUT });
}

export async function openRequestUpdate(page: Page, opts?: { requireGroups?: boolean }) {
	await Promise.all([
		page.waitForResponse(
			(res) => {
				if (res.request().method() !== 'GET') return false;
				try {
					const path = new URL(res.url()).pathname;
					return path.endsWith('/api/groups') || path.endsWith('/api/permissions');
				} catch {
					return false;
				}
			},
			{ timeout: LOAD_TIMEOUT }
		),
		(async () => {
			await page.getByTestId('dashboard-link-request-update').click();
			await waitForPageShell(page, 'request-update-page');
		})()
	]);
	if (opts?.requireGroups) {
		await waitForRequestUpdateGroups(page);
	} else {
		await waitForRequestUpdateCatalog(page);
	}
}

export async function completeMfaSetupFromChoice(page: Page): Promise<string> {
	await waitForPageShell(page, 'mfa-page');
	await expect(page.getByTestId('mfa-page')).toHaveAttribute('data-step', 'choice');
	const setupResponse = page.waitForResponse(
		(res) => res.url().includes('/api/users/mfa/setup') && res.request().method() === 'POST'
	);
	await page.getByTestId('mfa-setup').click();
	await setupResponse;
	await expect(page.getByTestId('mfa-page')).toHaveAttribute('data-step', 'verify');
	const secret = (await page.getByTestId('mfa-secret').innerText()).trim();
	expect(secret.length).toBeGreaterThan(10);
	return secret;
}

export async function verifyMfaSetup(page: Page, secret: string, expectSuccess: boolean) {
	await page.getByTestId('mfa-code').fill(expectSuccess ? totpCode(secret) : '000000');
	const verifyResponse = page.waitForResponse(
		(res) => res.url().includes('/api/users/mfa/verify') && res.request().method() === 'POST'
	);
	await page.getByTestId('mfa-verify-submit').click();
	const res = await verifyResponse;
	if (expectSuccess) {
		expect(res.ok()).toBeTruthy();
		await expect(page.getByTestId('dashboard-page')).toBeVisible({ timeout: LOAD_TIMEOUT });
	}
	return res;
}

export { patchUserMaps };
