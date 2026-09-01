import { expect, type APIRequestContext, type Page } from '@playwright/test';
import path from 'node:path';
import { e2eAdmin, e2eSuperuser, loginAs } from './auth';
import {
	matchUsersListRequest,
	waitForPageShell,
	waitForUserDetail,
	waitForUsersList
} from './waits';

export type BoolMap = Record<string, boolean>;

export const AUTH_DIR = path.join(process.cwd(), 'playwright', '.auth');

/** Re-export for existing call sites. Prefer `./waits` for new code. */
export { waitForUsersList } from './waits';

/** API wraps payloads as `{ data: T }`. */
export async function apiData<T>(res: { json: () => Promise<any>; ok: () => boolean; status: () => number; text: () => Promise<string> }): Promise<T> {
	const body = await res.json();
	return (body.data ?? body) as T;
}

type RequestLike = Pick<APIRequestContext, 'get' | 'put' | 'post' | 'delete'>;

export async function findUserByEmail(
	api: RequestLike,
	email: string
): Promise<{ id: string; permissions?: BoolMap; groups?: BoolMap; status?: string } | null> {
	const listRes = await api.get(`/api/users?q=${encodeURIComponent(email)}&limit=20`);
	if (!listRes.ok()) return null;
	const list = await apiData<{ users: { id: string; email: string; permissions?: BoolMap; groups?: BoolMap; status?: string }[] }>(
		listRes
	);
	return (list.users || []).find((u) => u.email === email) ?? null;
}

/**
 * PUT /users/:id replaces the whole permissions/groups maps when those fields are sent.
 * Always merge onto the current map before writing. Only enabled keys are sent so
 * concurrent catalog deletes cannot invalidate stale false entries.
 */
export async function patchUserMaps(
	api: RequestLike,
	userId: string,
	patch: {
		permissions?: BoolMap;
		groups?: BoolMap;
		status?: string;
		mfa_enforced?: boolean;
		reject_update?: boolean;
		approve_update?: boolean;
	}
) {
	const getRes = await api.get(`/api/users/${userId}`);
	if (!getRes.ok()) {
		throw new Error(`Failed to load user ${userId}: ${getRes.status()}`);
	}
	const user = await apiData<{ permissions?: BoolMap; groups?: BoolMap }>(getRes);
	const body: Record<string, unknown> = {};
	if (patch.status !== undefined) body.status = patch.status;
	if (patch.mfa_enforced !== undefined) body.mfa_enforced = patch.mfa_enforced;
	if (patch.reject_update !== undefined) body.reject_update = patch.reject_update;
	if (patch.approve_update !== undefined) body.approve_update = patch.approve_update;
	if (patch.permissions) {
		const merged = { ...(user.permissions || {}), ...patch.permissions };
		body.permissions = Object.fromEntries(
			Object.entries(merged).filter(([, enabled]) => enabled)
		);
	}
	if (patch.groups) {
		const merged = { ...(user.groups || {}), ...patch.groups };
		body.groups = Object.fromEntries(Object.entries(merged).filter(([, enabled]) => enabled));
	}
	const putRes = await api.put(`/api/users/${userId}`, { data: body });
	if (!putRes.ok()) {
		throw new Error(`Failed to patch user ${userId}: ${putRes.status()} ${await putRes.text()}`);
	}
}

/** Restore seed admin memberships (run once in auth setup, not per-test). */
export async function restoreSeedAdminAccess(api: RequestLike) {
	const summary = await findUserByEmail(api, e2eAdmin.email);
	if (!summary?.id) return;

	// Only send enabled keys so stale/deleted catalog entries are not referenced.
	const putRes = await api.put(`/api/users/${summary.id}`, {
		data: {
			status: 'ok',
			mfa_enforced: false,
			groups: {
				asdfasdf: true,
				group_a: true
			},
			permissions: {
				a_permission: true,
				another_permission: true,
				permission_b: true,
				some_permission: true
			}
		}
	});
	if (!putRes.ok()) {
		throw new Error(`Failed to restore seed admin: ${putRes.status()} ${await putRes.text()}`);
	}
}

export type EphemeralUser = {
	id: string;
	email: string;
	password: string;
};

export type CreateEphemeralOptions = {
	/** Groups to enable (defaults to group_a so seed admin can see the user). */
	groups?: string[];
	permissions?: string[];
	/** If false, leave status pending admin approval. Default true. */
	approve?: boolean;
};

/**
 * Register + optionally approve/bootstrap an isolated user for parallel-safe mutation tests.
 * Caller must pass an API context authenticated as superuser.
 *
 * Only enabled groups/permissions are sent on PUT so parallel catalog create/delete
 * cannot leave stale false keys that fail validation after a fixture disappears.
 */
export async function createEphemeralUser(
	api: RequestLike,
	suffix: string,
	opts: CreateEphemeralOptions = {}
): Promise<EphemeralUser> {
	const email = `e2e.u.${suffix}@example.com`;
	const password = 'DevAdminTest123!';
	const approve = opts.approve !== false;
	const groups = opts.groups ?? ['group_a'];

	const regRes = await api.post('/api/users', {
		data: { email, password }
	});
	if (!regRes.ok()) {
		throw new Error(`Register failed: ${regRes.status()} ${await regRes.text()}`);
	}
	const reg = await apiData<{ user_id: string }>(regRes);
	const id = reg.user_id;

	const groupMap: BoolMap = {};
	for (const g of groups) groupMap[g] = true;

	const body: Record<string, unknown> = { groups: groupMap };
	if (opts.permissions?.length) {
		const permMap: BoolMap = {};
		for (const p of opts.permissions) permMap[p] = true;
		body.permissions = permMap;
	}
	if (approve) body.status = 'ok';

	const putRes = await api.put(`/api/users/${id}`, { data: body });
	if (!putRes.ok()) {
		await api.delete(`/api/users/${id}`).catch(() => undefined);
		throw new Error(`Bootstrap ephemeral user failed: ${putRes.status()} ${await putRes.text()}`);
	}

	return { id, email, password };
}

export async function deleteUserById(api: RequestLike, userId: string) {
	await api.delete(`/api/users/${userId}`);
}

export async function deleteUserByEmail(api: RequestLike, email: string) {
	const user = await findUserByEmail(api, email);
	if (!user?.id) return;
	await deleteUserById(api, user.id);
}

/** Open a user detail page from the admin users tab. */
export async function openUserDetailFromAdmin(page: Page, email: string) {
	if (!page.url().includes('/admin')) {
		await page.goto('/admin');
		await waitForPageShell(page, 'admin-page');
	}
	await waitForUsersList(page);

	const usersResponse = page.waitForResponse((res) => matchUsersListRequest(res, { q: email }));
	await page.getByTestId('users-list-search').fill(email);
	await usersResponse;

	const row = page.locator(`[data-testid="users-list-row"][data-user-email="${email}"]`);
	await expect(row).toBeVisible();
	await row.getByTestId('users-list-edit').click();
	await waitForUserDetail(page);
	await expect(page.getByTestId('user-detail-email')).toHaveText(email);
}

/** Open a user detail page from the superuser users tab. */
export async function openUserDetailFromSuperuser(page: Page, email: string) {
	if (!page.url().includes('/superuser')) {
		await page.getByTestId('nav-superuser').click();
		await waitForPageShell(page, 'superuser-page');
	}
	await page.getByTestId('superuser-tab-users').click();
	await waitForUsersList(page);

	const usersResponse = page.waitForResponse((res) => matchUsersListRequest(res, { q: email }));
	await page.getByTestId('users-list-search').fill(email);
	await usersResponse;

	const row = page.locator(`[data-testid="users-list-row"][data-user-email="${email}"]`);
	await expect(row).toBeVisible();
	await row.getByTestId('users-list-edit').click();
	await waitForUserDetail(page);
	await expect(page.getByTestId('user-detail-email')).toHaveText(email);
}

export async function ensureSuperuserSession(page: Page) {
	await loginAs(page, e2eSuperuser);
}

export { e2eAdmin, e2eSuperuser };
