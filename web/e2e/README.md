# E2E test layout



Playwright specs are organized by **feature or journey**, not by outcome. Happy-path, validation, and API-error cases for the same page live together in nested `test.describe` blocks.



## Directory structure



```

e2e/

  auth/                    # Public auth (no session required)

    login.spec.ts          # UI smoke, API login/logout, MFA login errors

    register.spec.ts

    forgot-password.spec.ts

  dashboard/               # Logged-in self-service

    self-service.spec.ts   # Overview, password, MFA (happy + validation + errors)

    pending.spec.ts        # Pending-update banner

  roles/

    nav.spec.ts            # Nav links by role (admin, superuser, regular)

    catalog-modals.spec.ts # Modal cancel flows (admin + superuser)

    admin/                 # Admin console

    superuser/             # Superuser console

    regular/               # Ephemeral regular-user perspective

      dashboard.spec.ts

      access.spec.ts

    user-detail/           # /admin/users/:id (primarily superuser; scope test uses admin)

  journeys/                # Multi-actor or multi-step flows (named by domain)

    registration.spec.ts   # Pending-account approve/reject + actor handoffs

    request-update.spec.ts # Form UX, decisions, dashboard outcomes, handoffs

    active-session.spec.ts # Lock, delete, MFA enforce while user is online

    epic-lifecycle.spec.ts       # @epic — register → reject → approve → access → password → delete

    epic-catalog-to-access.spec.ts # @epic — catalog, visibility, scope, safeguard

    epic-scope-alignment.spec.ts   # @epic — admin scope expansion + lock cycle

    epic-security-hardening.spec.ts # @epic — MFA enforce, TOTP login, revoke

  helpers/                 # Fixtures, auth, API helpers, waits

  auth.setup.ts            # Seed admin access restore (setup project)

```



## Conventions



- **Where to add a test**

  - Single page or feature → file under `auth/`, `dashboard/`, or the relevant `roles/` folder.

  - Multi-actor flow → `journeys/`, in the file for that **domain** (`registration`, `request-update`, `active-session`).

  - Long cross-feature epics → `journeys/epic-*.spec.ts` (tagged `@epic`; run with `--grep @epic`).

  - Use nested `test.describe` blocks for story type (`form`, `actor handoffs`, `user dashboard outcomes`, etc.).

  - Group validation/API errors with `test.describe('happy path' | 'validation' | 'API errors', …)` inside feature files.



- **Fixtures** (`helpers/fixtures.ts`)

  - `adminPage` / `superuserPage` — per-worker isolated sessions.

  - `regularUserPage` + `ephemeralUser` — fresh regular user per test.

  - Mutating tests must use ephemeral users; never mutate seed admin/superuser credentials.



- **Imports** — from a spec file, import helpers relative to depth:

  - `auth/login.spec.ts` → `../helpers/fixtures`

  - `roles/admin/admin.spec.ts` → `../../helpers/fixtures`



## Running



Requires the API running (Vite dev server proxies `/api` to garde on `:8443`):

```bash
docker compose --profile dev up --build -d   # from repo root
cd web
bun install
```

```bash
bun run test:e2e              # default workers (CPU cores)

bun run test:e2e -- --workers=8

# Stress / low-resource simulation (optional env overrides):

PLAYWRIGHT_LOAD_TIMEOUT=60000 PLAYWRIGHT_TEST_TIMEOUT=180000 PLAYWRIGHT_RETRIES=1 bun run test:e2e -- --workers=32

# Force fresh worker auth cookies (default reuses playwright/.auth when present):

PLAYWRIGHT_FRESH_AUTH=1 bun run test:e2e
```

### CI

GitHub Actions (`.github/workflows/e2e.yml`) runs on push and pull request:

- Starts the dev Docker stack (`docker compose --profile dev`)
- Installs web deps with Bun and runs `bun run test:e2e` (full suite, including `@epic`)
- Uses **4 workers + 2 retries** (`playwright.config.ts` when `CI=true`)
- Uploads the HTML report and test results after every run (1-day retention)

The 32-worker command above is for local stress only.

### Tags

Tests use Playwright [`tag`](https://playwright.dev/docs/test-annotations#tag-tests) annotations via `helpers/tags.ts`:

| Tag | Meaning |
|-----|---------|
| `@focused` | Single-feature / role spec (default CI signal) |
| `@journey` | Multi-actor domain journey (focused cases) |
| `@epic` | Long integration story (outcome assertions only) |
| `@auth`, `@registration`, `@request-update`, … | Domain filter |

```bash
bun run test:e2e:focused   # all except @epic (~165 tests)
bun run test:e2e:epic      # integration epics only (4 tests)
bun run test:e2e -- --grep @registration
```

**Epic vs focused overlap:** `@epic` specs use `outcomesOnly` journey helpers — they verify chain **outcomes** (chips, signed-in/out, URLs). Toast copy, error messages, and form validation stay in `@focused` / `@journey` specs. If only an epic fails, re-run the matching domain tag before debugging the full chain.

### Epics vs focused journeys

Focused journey files (`registration`, `request-update`, `active-session`) keep fast, parallel-safe cases. **`epic-*.spec.ts`** adds four long integration stories (one test each) that chain multiple actors and negative branches. They are additive — nothing replaces the focused specs.

### Auth helpers

- **`startUserSession`** / **`loginViaRequest`** — preferred for any test that is not exercising the login form.
- **`loginAs`** / **`expectLoginRejected`** — only for login-page specs, MFA second step after logout, and blocked-account messages.
- Worker **`suRequest`** validates `/api/users/me` and re-authenticates when cached cookies are stale (`ensureApiAuth`).
- Login/register forms expose `data-ready="true"` after mount and stay disabled until then; sign-in uses `type="button"` + click handler so Playwright clicks always fire the handler.
- **`openLogin` / `openRegister` / `openForgotPassword`** — navigate public auth pages without `networkidle` (waits for testids + `data-ready` where applicable).
- Request-update waits for `data-ready="true"` on the form (catalog fetch complete) before interacting with multiselects.
- **`waitForOutOfScopeDenied`** — admin opens `/admin/users/:id` for a user outside their groups: API returns 401 `unauthorized`, UI shows `user-detail-access-denied`, session stays signed in (not a login redirect).
- **`gotoDashboardFresh`** — navigate to `/dashboard` and wait for `/api/users/me` (dashboard refetches on mount).
- **`waitForToastGone`** — centralized in `helpers/waits.ts` (toast uses deadline-based auto-hide resilient to background-tab timer throttling).
- **Timeout tiers:** `REDIRECT_TIMEOUT` (15s) for login/redirect assertions; `LOAD_TIMEOUT` (30s default, env override) for session boot and API-backed panels. CI uses 4 workers; very high local worker counts can saturate the dev stack — use default parallelism for routine runs.
