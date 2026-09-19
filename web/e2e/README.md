# E2E test layout

Playwright specs are organized by **domain or page** (primary axis). Multi-actor chains and long epics live under `journeys/`. Shared widget interaction locks live under `ui-contracts/`.

Within a feature file, group cases with nested `test.describe` blocks (`happy path`, `validation`, `API errors`, etc.).

## Directory structure

```
e2e/
  auth/                         # Public auth pages (no session)
    login.spec.ts
    register.spec.ts
    forgot-password.spec.ts

  dashboard/                    # Signed-in self-service + regular dashboard UX
    self-service.spec.ts        # Overview, password, MFA
    pending.spec.ts             # Pending-update banner
    regular.spec.ts             # Regular-user nav / dashboard / request-update entry

  admin/                        # Admin console (lists, catalog)
    admin.spec.ts
    admin-users-list.spec.ts
    admin-catalog.spec.ts
    admin-catalog-members.spec.ts

  superuser/                    # Superuser console
    superuser.spec.ts
    users-list.spec.ts
    superuser-group.spec.ts
    superuser-permission.spec.ts
    superuser-visibility.spec.ts
    superuser-catalog-members.spec.ts
    superuser-admin-management.spec.ts
    superuser-api-keys.spec.ts  # Tenant API keys (focused)

  regular/                      # Regular-user access + PATs
    access.spec.ts
    access-tokens.spec.ts       # User access tokens / PATs (focused)

  user-detail/                  # /admin|superuser/users/:id (page, both actors)
    user-detail-flows.spec.ts
    user-access.spec.ts
    user-delete.spec.ts
    user-revoke.spec.ts
    user-security.spec.ts
    user-detail-scope.spec.ts   # Admin out-of-scope
    admin-user-detail.spec.ts
    admin-user-edit.spec.ts
    admin-user-revoke.spec.ts
    admin-user-security.spec.ts

  catalog/
    modals.spec.ts              # Catalog cancel / don't-persist (admin + superuser)

  nav/
    by-role.spec.ts             # Nav links by role

  journeys/                     # Multi-actor (@journey) + long epics (@epic)
    registration.spec.ts
    request-update.spec.ts
    active-session.spec.ts
    api-keys.spec.ts            # Tenant API-key lifecycle
    access-tokens.spec.ts       # PAT lifecycle across actors
    epic-lifecycle.spec.ts
    epic-catalog-to-access.spec.ts
    epic-scope-alignment.spec.ts
    epic-security-hardening.spec.ts

  ui-contracts/
    widget-contracts.spec.ts    # ConfirmModal, ManageModal, MultiSelect, Tablist, Toast

  helpers/                      # Fixtures, auth, waits, domain helpers
    fixtures.ts
    auth.ts                     # Login helpers (not auth.setup.ts)
    journeyActs.ts              # Multi-step act helpers for journeys/epics
    apiKeys.ts                  # Tenant API keys
    accessTokens.ts             # User PATs (/api/users/me/tokens)
    catalog.ts
    mfa.ts
    totp.ts
    userApi.ts
    waits.ts
    tags.ts

  auth.setup.ts                 # Seed admin access restore (Playwright setup project)
```

## Where to add a test

| Kind | Location |
|------|----------|
| Single page / feature | `auth/`, `dashboard/`, `admin/`, `superuser/`, `regular/`, `user-detail/`, `catalog/` |
| Cross-role nav | `nav/by-role.spec.ts` |
| Multi-actor domain flow | `journeys/<domain>.spec.ts` (`@journey`) |
| Long cross-feature story | `journeys/epic-*.spec.ts` (`@epic`) |
| Shared widget mechanics | `ui-contracts/widget-contracts.spec.ts` |

**Ownership**

- **Feature specs** own product meaning (copy, permissions, API outcomes, cancel-without-persist).
- **`ui-contracts/`** owns control behavior (Escape, overlay, keyboard, tablist keys, toast dismiss). Do not duplicate a full save/search/toast chain in both.
- **`journeys/`** owns multi-actor handoffs; focused specs own the single-page mechanics for the same domain (e.g. `auth/register` vs `journeys/registration`).
- **Tenant API keys** (`helpers/apiKeys.ts`, `superuser/superuser-api-keys`, `journeys/api-keys`) vs **user PATs** (`helpers/accessTokens.ts`, `regular/access-tokens`, `journeys/access-tokens`) — different credentials; keep names distinct.

## Tags and scripts

Tags live in `helpers/tags.ts`.

| Tag | Meaning |
|-----|---------|
| `@focused` | Single-feature / page / actor spec |
| `@journey` | Multi-actor domain journey |
| `@epic` | Long integration (outcome assertions only) |
| `@ui-contracts` | Shared widget locks |
| `@auth`, `@registration`, `@request-update`, `@api-keys`, `@access-tokens`, … | Domain filters |

```bash
bun run test:e2e              # full suite
bun run test:e2e:focused      # --grep @focused
bun run test:e2e:journey      # --grep @journey
bun run test:e2e:epic         # --grep @epic
bun run test:e2e:no-epic      # everything except @epic (focused + journey)
bun run test:e2e -- --grep @registration
```

**Epic vs focused overlap:** `@epic` specs use `outcomesOnly` journey act helpers — they verify chain outcomes (chips, signed-in/out, URLs). Toast copy, error messages, and form validation stay in `@focused` / `@journey` specs.

## Fixtures

(`helpers/fixtures.ts`)

- `adminPage` / `superuserPage` — per-worker isolated sessions.
- `regularUserPage` + `ephemeralUser` — fresh regular user per test.
- Mutating tests must use ephemeral users; never mutate seed admin/superuser credentials.

## Imports

From a one-level domain folder (`admin/`, `auth/`, …):

```ts
import { test } from '../helpers/fixtures';
```

## Running

Requires the API running (Vite proxies `/api` to garde on `:8443`):

```bash
docker compose --profile dev up --build -d   # from repo root
cd web
bun install
bun run test:e2e
```

Optional stress overrides: `PLAYWRIGHT_LOAD_TIMEOUT`, `PLAYWRIGHT_TEST_TIMEOUT`, `PLAYWRIGHT_RETRIES`, `PLAYWRIGHT_FRESH_AUTH=1`.

### CI

GitHub Actions (`.github/workflows/e2e.yml`) runs `bun run test:e2e` (full suite) with 4 workers + 2 retries when `CI=true`.

### Auth helpers

- **`startUserSession` / `loginViaRequest`** — preferred when not exercising the login form.
- **`loginAs` / `expectLoginRejected`** — login-page specs, MFA second step, blocked-account messages.
- Worker **`suRequest`** re-authenticates when cached cookies are stale (`ensureApiAuth`).
- **`assertToast` / `dismissToast`** — assert then dismiss; do not wait for the 5s auto-hide.
- **Timeouts:** `REDIRECT_TIMEOUT` (15s), `LOAD_TIMEOUT` (30s default, env override).
