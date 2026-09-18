# Backend unit tests

Go unit tests live next to the code (`*_test.go`). Ephemeral Redis is in-memory via
`miniredis`. Durable PostgreSQL uses `GARDE_TEST_DATABASE_URL` (CI provides
`postgres:16`). Config comes from temp secret dirs. Anything needing live Redis
beyond miniredis, real SMTP/TLS, or a shared DB outside the test harness belongs
to the integration/e2e suite, not here.

```bash
export GARDE_TEST_DATABASE_URL='postgres://garde:garde@localhost:5432/garde?sslmode=disable'
CGO_ENABLED=0 go vet ./...
# Serialise packages that share the scratch DB (TRUNCATE races under -p > 1).
CGO_ENABLED=0 go test -p 1 ./...
go test -p 1 -cover ./...
go test -coverprofile cover.out ./internal/service/ && go tool cover -func cover.out
```

CI: `.github/workflows/unit.yml` runs vet/test with `CGO_ENABLED=0`, a
`postgres:16` service, `GARDE_TEST_DATABASE_URL`, and `go test -p 1`.

## Layout

```
internal/testutil/      # InitConfig, NewMiniRedis, OpenTestDB, NewTestStore
internal/handlers/      # endpoint tables through real service on Postgres+miniredis
internal/middleware/    # gates, dispatch tables, direct validator tests,
                        # fabricated TLS chains for mTLS domain logic
internal/models/        # predicates, JSON shape (secret omission), catalogue types
internal/repository/    # Postgres durable CRUD, Redis ephemeral primitives,
                        # migrations, optimistic locking
internal/service/       # auth flows (login/lockout/MFA/OTP/reset), guards,
                        # bootstrap, catalogue fallbacks
pkg/*/                 # pure units: validators, crypto, session, mail shape,
                        # error-catalogue lint, config semantics, TOTP
```

## Conventions

- **Table-driven, one behaviour per case**, `t.Fatalf` with got/want. Nest with
  `t.Run` subtests; follow the existing `TestXxxTable` / `TestXxxLifecycle` shape.
- **Config is process-global.** Seed it per test with `testutil.InitConfig`
  (or a local temp dir + `config.Init`); never assume another test's values.
  Do not use `t.Parallel()` in tests that touch config or globals.
- **Durable store via `testutil.NewTestStore`** (Postgres + miniredis). Skips when
  `GARDE_TEST_DATABASE_URL` is unset. Ephemeral-only tests may use
  `repository.NewRedisRepositoryFromClient` / miniredis alone.
- **Never initialise the permission singleton** (`InitPermissionRepository` /
  `GetPermissionRepository`) in unit tests: it flips `IsPermissionsLoaded` /
  `IsGroupsLoaded` process-wide and breaks guard assertions elsewhere.
  Catalogue-backed branches are asserted as `NotLoaded` errors instead.
  Catalogue CRUD tests call `repository.NewPermissionRepository(db)` with a
  throwaway pool.
- **Optimistic locking:** `StoreUser` mutates `UpdatedAt` on the struct you
  pass in. Re-fetch (`GetUserByID`) before any second direct store or you
  will manufacture an `ErrConcurrentUpdate` — that failure is the test
  harness racing itself, not the app. Postgres timestamps may be coarser than
  wall-clock nanoseconds; re-fetch before a second write even in the same test.
- **MFA secrets are encrypted at rest in PostgreSQL:** any store carrying
  `MFASecret` needs `mfa_encryption_key` configured
  *before* the write, or the store fails. Temp MFA during setup stays in Redis.
- **Sessions bind IP + UA:** `httptest` defaults to `192.0.2.1` with an empty
  agent — pass the same values to `Login` and the request. A different IP
  blacklists and deletes the session by design; use a second session for
  negative checks.
- **Gin contexts:** seed what middleware would have set
  (`user_id`, `is_superuser`/`is_admin`, `ContextKeyValidatedRequest`) rather
  than running the middleware chain, except in `validation_dispatch_test.go`,
  which exercises `ValidateRequestParameters` routing end to end.
- **mTLS:** `MTLSMiddleware` is tested with fabricated
  `tls.ConnectionState` chains (self-signed ECDSA certs). This covers domain
  logic only; live handshakes stay in deploy tests.
- **Do not touch app code in test PRs.** If a test fails on correct-looking
  input, investigate in this order: test bug (stale struct, key ordering,
  wrong router) → correct-but-surprising app behavior (pin it with a comment)
  → real app bug (record it, keep the test red or pin with a TODO pointing at
  the fix — never weaken the assertion to green).

## Coverage policy

- New behaviour ships with tests; pure helpers and guards must be table-tested.
- Sentinel error strings are linted (`pkg/errors/errors_test.go`): non-empty
  and unique. Any intentional duplicate needs its own justification comment.
- Bug fixes land with a regression test that failed before the fix.
- Deliberately uncovered (heavier harness required): tenant/visibility admin
  handlers and the approval matrix (permission singleton), `mail` SMTP dialog
  (fake STARTTLS server), `MTLSMiddleware` live handshakes, `NewStore` /
  live Redis reconnect, `cmd` wiring, `entities` (structs),
  `endpoint_documentation` (generated).

## Current standing

`models` 100% · `session` 92% · `crypto` 91% · `config` 88% · `validation`
85–87% · `repository` ~79% · `service` ~57% · `handlers` ~54% ·
`middleware` ~60% · `mfa` 75% · `mail` 31% (SMTP dialog excluded above) ·
`testutil` 81%. Run `go test -cover ./...` for the exact numbers; they move
with every batch, so they live here as guidance, not gates.
