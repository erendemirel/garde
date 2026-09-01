import { defineConfig, devices } from '@playwright/test';

const PORT = Number(process.env.PLAYWRIGHT_PORT || 5173);
// Must be localhost (not 127.0.0.1): API session cookies are Domain=localhost.
const baseURL = process.env.PLAYWRIGHT_BASE_URL || `http://localhost:${PORT}`;

/**
 * UI + API auth tests.
 * Vite proxies /api → garde (:8443). API must be running for authenticated specs.
 *
 * Parallelism: mutating tests use ephemeral users (see helpers/fixtures.ts).
 * Seed admin/superuser are only read or used via isolated storageState copies.
 */
export default defineConfig({
	testDir: './e2e',
	fullyParallel: true,
	forbidOnly: !!process.env.CI,
	retries: Number(process.env.PLAYWRIGHT_RETRIES ?? (process.env.CI ? 2 : 0)),
	// Local: Playwright default (CPU cores). CI: modest parallelism.
	workers: process.env.CI ? 2 : undefined,
	// Multi-actor journeys + slow /api/me under many workers need headroom.
	timeout: Number(process.env.PLAYWRIGHT_TEST_TIMEOUT || 120_000),
	expect: {
		timeout: Number(process.env.PLAYWRIGHT_EXPECT_TIMEOUT || 30_000)
	},
	reporter: [['list'], ['html', { open: 'never' }]],
	use: {
		baseURL,
		trace: 'on-first-retry',
		screenshot: 'only-on-failure'
	},
	projects: [
		{
			name: 'setup',
			testMatch: /auth\.setup\.ts/
		},
		{
			name: 'chromium',
			dependencies: ['setup'],
			testIgnore: /auth\.setup\.ts/,
			use: { ...devices['Desktop Chrome'] }
		}
	],
	webServer: process.env.PLAYWRIGHT_BASE_URL
		? undefined
		: {
				command: `npm run dev -- --host localhost --port ${PORT}`,
				url: baseURL,
				reuseExistingServer: !process.env.CI,
				timeout: 120_000
			}
});
