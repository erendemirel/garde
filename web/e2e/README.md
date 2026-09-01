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

  helpers/                 # Fixtures, auth, API helpers, waits

  auth.setup.ts            # Seed admin access restore (setup project)

```



## Conventions



- **Where to add a test**

  - Single page or feature → file under `auth/`, `dashboard/`, or the relevant `roles/` folder.

  - Multi-actor flow → `journeys/`, in the file for that **domain** (`registration`, `request-update`, `active-session`).

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



```bash

cd web

npm run test:e2e              # default workers (CPU cores)

npm run test:e2e -- --workers=8

# Stress / low-resource simulation (optional env overrides):

PLAYWRIGHT_LOAD_TIMEOUT=60000 PLAYWRIGHT_TEST_TIMEOUT=180000 PLAYWRIGHT_RETRIES=1 npm run test:e2e -- --workers=32

# Force fresh worker auth cookies (default reuses playwright/.auth when present):

PLAYWRIGHT_FRESH_AUTH=1 npm run test:e2e
```

CI uses **2 workers + 2 retries** (`playwright.config.ts`). The 32-worker command above is for local stress only.

### Auth helpers under load

- **`startUserSession`** / **`loginViaRequest`** — preferred for any test that is not exercising the login form. Avoids Svelte hydration flakes.
- **`loginAs`** / **`expectLoginRejected`** — only for login-page specs, MFA second step after logout, and blocked-account messages.
- Worker **`suRequest`** validates `/api/users/me` and re-authenticates when cached cookies are stale (`ensureApiAuth`).
- Login/register forms expose `data-ready="true"` after mount; sign-in uses `type="button"` + click handler so Playwright clicks always fire the handler.

Requires the API running (Vite dev server proxies `/api` to garde on `:8443`).
