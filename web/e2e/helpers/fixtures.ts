import { test as base, expect, type APIRequestContext, type Page } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
import { e2eAdmin, e2eSuperuser, ensureApiAuth, loginViaRequest, openDashboardSession } from './auth';
import {
	AUTH_DIR,
	createEphemeralUser,
	deleteUserById,
	type EphemeralUser
} from './userApi';

const e2eBaseURL =
	process.env.PLAYWRIGHT_BASE_URL ||
	`http://localhost:${Number(process.env.PLAYWRIGHT_PORT || 5173)}`;

type WorkerFixtures = {
	/** Per-worker admin session file (isolated login; safe under parallel workers). */
	workerAdminState: string;
	/** Per-worker superuser session file. */
	workerSuperuserState: string;
};

type Fixtures = {
	uniqueSuffix: string;
	suRequest: APIRequestContext;
	adminPage: Page;
	superuserPage: Page;
	/** Logged-in ephemeral (regular) user — isolated per test. */
	regularUserPage: Page;
	ephemeralUser: EphemeralUser;
};

async function warmWorkerAuth(
	playwright: import('@playwright/test').Playwright,
	baseURL: string | undefined,
	creds: { email: string; password: string },
	statePath: string
) {
	if (process.env.PLAYWRIGHT_FRESH_AUTH && fs.existsSync(statePath)) {
		fs.unlinkSync(statePath);
	}
	const ctx = await ensureApiAuth(playwright, baseURL, creds, statePath);
	await ctx.dispose();
}

export const test = base.extend<Fixtures, WorkerFixtures>({
	workerAdminState: [
		async ({ playwright }, use, workerInfo) => {
			const statePath = path.join(AUTH_DIR, `admin-w${workerInfo.workerIndex}.json`);
			await warmWorkerAuth(playwright, e2eBaseURL, e2eAdmin, statePath);
			await use(statePath);
		},
		{ scope: 'worker' }
	],

	workerSuperuserState: [
		async ({ playwright }, use, workerInfo) => {
			const statePath = path.join(AUTH_DIR, `superuser-w${workerInfo.workerIndex}.json`);
			await warmWorkerAuth(playwright, e2eBaseURL, e2eSuperuser, statePath);
			await use(statePath);
		},
		{ scope: 'worker' }
	],

	uniqueSuffix: async ({}, use, testInfo) => {
		const suffix = [
			`w${testInfo.workerIndex}`,
			`p${testInfo.parallelIndex}`,
			Date.now().toString(36),
			Math.random().toString(36).slice(2, 8)
		].join('_');
		await use(suffix);
	},

	suRequest: async ({ playwright, baseURL, workerSuperuserState }, use) => {
		const ctx = await ensureApiAuth(playwright, baseURL, e2eSuperuser, workerSuperuserState);
		await use(ctx);
		await ctx.dispose();
	},

	adminPage: async ({ browser, workerAdminState }, use) => {
		const context = await browser.newContext({ storageState: workerAdminState });
		const page = await context.newPage();
		await use(page);
		await context.close();
	},

	superuserPage: async ({ browser, workerSuperuserState }, use) => {
		const context = await browser.newContext({ storageState: workerSuperuserState });
		const page = await context.newPage();
		await use(page);
		await context.close();
	},

	regularUserPage: async ({ browser, ephemeralUser }, use) => {
		const context = await browser.newContext();
		await loginViaRequest(context.request, ephemeralUser);
		const page = await context.newPage();
		await openDashboardSession(page);
		await use(page);
		await context.close();
	},

	ephemeralUser: async ({ suRequest, uniqueSuffix }, use) => {
		const user = await createEphemeralUser(suRequest, uniqueSuffix);
		await use(user);
		await deleteUserById(suRequest, user.id).catch(() => undefined);
	}
});

export { expect };
