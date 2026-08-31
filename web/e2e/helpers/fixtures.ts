import { test as base, expect, type APIRequestContext, type Page } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
import { e2eAdmin, e2eSuperuser, loginAs } from './auth';
import {
	AUTH_DIR,
	createEphemeralUser,
	deleteUserById,
	type EphemeralUser
} from './userApi';

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
	ephemeralUser: EphemeralUser;
};

async function loginAndSaveState(
	browser: import('@playwright/test').Browser,
	creds: { email: string; password: string },
	statePath: string
) {
	fs.mkdirSync(AUTH_DIR, { recursive: true });
	const context = await browser.newContext();
	const page = await context.newPage();
	await loginAs(page, creds);
	await context.storageState({ path: statePath });
	await context.close();
}

export const test = base.extend<Fixtures, WorkerFixtures>({
	workerAdminState: [
		async ({ browser }, use, workerInfo) => {
			const statePath = path.join(AUTH_DIR, `admin-w${workerInfo.workerIndex}.json`);
			await loginAndSaveState(browser, e2eAdmin, statePath);
			await use(statePath);
		},
		{ scope: 'worker' }
	],

	workerSuperuserState: [
		async ({ browser }, use, workerInfo) => {
			const statePath = path.join(AUTH_DIR, `superuser-w${workerInfo.workerIndex}.json`);
			await loginAndSaveState(browser, e2eSuperuser, statePath);
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
		const ctx = await playwright.request.newContext({
			baseURL,
			storageState: workerSuperuserState
		});
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

	ephemeralUser: async ({ suRequest, uniqueSuffix }, use) => {
		const user = await createEphemeralUser(suRequest, uniqueSuffix);
		await use(user);
		await deleteUserById(suRequest, user.id).catch(() => undefined);
	}
});

export { expect };
