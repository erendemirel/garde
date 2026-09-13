# Backend unit tests

Go unit tests live next to the code (`*_test.go`), run with no external
services — Redis is in-memory via `miniredis`, SQLite uses a temp `DATA_DIR`,
config comes from temp secret dirs. Anything needing live Redis, real SMTP/TLS,
or the SQLite singleton belongs to the integration/e2e suite, not here.

```bash
go vet ./...
go test ./...
go test -cover ./...            # per-package statement coverage
go test -coverprofile cover.out ./internal/service/ && go tool cover -func cover.out
```

## Layout

```
internal/testutil/      # shared helpers: InitConfig, NewMiniRedis (+ self-test)
internal/handlers/      # endpoint tables through real service on miniredis
internal/middleware/    # gates, dispatch tables, direct validator tests,
                        # fabricated TLS chains for mTLS domain logic
internal/models/        # predicates, JSON shape (secret omission), catalogue types
internal/repository/    # SQLite CRUD/visibility/cascade, Redis security
                        # primitives, legacy migration, optimistic locking
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
- **Redis via `testutil.NewMiniRedis`** (already a dependency). Wrap with
  `repository.NewRedisRepositoryFromClient`. Repos never dial real Redis here.
- **Never initialise the permission singleton** (`InitPermissionRepository` /
  `GetPermissionRepository`) in unit tests: it flips `IsPermissionsLoaded` /
  `IsGroupsLoaded` process-wide and breaks guard assertions elsewhere.
  Catalogue-backed branches are asserted as `NotLoaded` errors instead.
- **Optimistic locking:** `StoreUser` mutates `UpdatedAt` on the struct you
  pass in. Re-fetch (`GetUserByID`) before any second direct store or you
  will manufacture an `ErrConcurrentUpdate` — that failure is the test
  harness racing itself, not the app.
- **MFA secrets are encrypted at rest:** any store carrying `MFASecret`
  needs `mfa_encryption_key` (or `api_key` fallback) configured *before* the
  write, or the store fails.
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
  handlers and the approval matrix (SQLite singleton), `mail` SMTP dialog
  (fake STARTTLS server), `MTLSMiddleware` live handshakes, `NewRedisRepository`
  / `connect` / `Reconnect` (live Redis), `cmd` wiring, `entities` (structs),
  `endpoint_documentation` (generated).

## Current standing

`models` 100% · `session` 92% · `crypto` 91% · `config` 88% · `validation`
85–87% · `repository` ~79% · `service` ~57% · `handlers` ~54% ·
`middleware` ~60% · `mfa` 75% · `mail` 31% (SMTP dialog excluded above) ·
`testutil` 81%. Run `go test -cover ./...` for the exact numbers; they move
with every batch, so they live here as guidance, not gates.
