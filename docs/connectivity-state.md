# Connectivity & Auth State (IDE-1988)

Centralised, event-driven state source that gates outbound calls when we know they will fail or be wasted (unauthenticated, offline). Replaces scattered `IsAuthenticated()` checks and PR #1245's IsSet/prime workaround for `ConfigResolver.GlobalOrg()`.

## Motivation

GAF default-value funcs (`ORGANIZATION`, `ORGANIZATION_SLUG`, `API_URL` from token audience) fire outbound calls (`/rest/self`) on every read while unauthenticated. GAF's default-value cache only stores results when `err == nil` (`go-application-framework/pkg/configuration/configuration.go:492`), so failures degenerate into retry storms on hot paths (settings page, `StateSnapshot`). The default-value cache is not enabled in snyk-ls production anyway — so today *every* read re-runs the default func from scratch.

The same pattern repeats elsewhere: LDX-Sync fetches, learn cache, feature flags, analytics, scanner init, and `IsAuthenticated()` itself all hit the network without first asking whether it's worth the attempt.

## Goals

- A single state source consumed from any layer.
- Hot-path reads (`StateSnapshot`, settings page) trigger zero outbound calls.
- Repeated reads while unauthenticated/offline issue zero outbound calls (no retry loop).
- Scattered "is authenticated?" guards consolidated.
- Retire PR #1245's IsSet gate + the two `GetGlobalOrganization` prime calls.
- Wire `startOfflineDetection` (`application/server/server.go:569`, currently `//nolint:unused`) into the state source.

## Non-goals (v1)

- Push-based subscriber model that fans transitions out to consumers for automatic refresh (cache warm, analytics flush). Pull-based is sufficient for the acceptance criteria; we can layer push on top later.
- HTTP-roundtripper-based "ground-truth promotion." The adaptive offline probe alone is the v1 signal; in-process traffic almost all flows through GAF clients anyway, so the probe is timely in practice.
- Enabling GAF's default-value cache globally. Orthogonal change; risks affecting other default funcs we haven't audited. The wrapper persists results via `Set()`, which is sufficient.

## State model

```go
// internal/connectivity
type State int
const (
    Unknown State = iota
    Authenticated
    Unauthenticated
    Offline
)

type Service interface {
    State() State
    IsAuthenticated() bool  // State == Authenticated
    IsOnline() bool         // State != Offline

    // Pushed in by AuthenticationService and the offline detector.
    OnAuthEvent(AuthEvent)
    OnReachability(reachable bool)
}
```

`Offline` takes precedence over auth status. `Authenticated` does not strictly imply "right now online" — it means "last validation still valid"; a subsequent network failure demotes to `Offline`.

### Transition table

| From → on event              | Unknown   | Unauth | Auth         | Offline     |
|---|---|---|---|---|
| `reachable=false`            | Offline   | Offline | Offline      | Offline     |
| `reachable=true` + no token  | Unauth    | –       | –            | Unauth      |
| `reachable=true` + token     | (recheck) | (recheck) | Auth       | (recheck)   |
| `TokenSet` / `TokenChanged`  | (recheck) | (recheck) | (recheck)  | Offline     |
| `TokenCleared`               | Unauth    | –       | Unauth       | Offline     |
| `WhoamiOK`                   | Auth      | Auth    | –            | Offline (keep) |
| `Whoami401`                  | Unauth    | –       | Unauth       | Offline (keep) |
| `WhoamiNetErr`               | Offline   | Offline | Offline      | –           |

Eager `Unknown` resolution at construction: query AuthService for "is a token loaded?" (no network) → `Unauth` if no, `Unknown` if yes (next event resolves it).

## Components

### `infrastructure/authentication` — event source

Subscribe-style hook on `AuthenticationService`. No reverse dependency on connectivity; AuthService just publishes.

```go
type AuthEvent struct {
    Kind  AuthEventKind  // TokenSet | TokenCleared | TokenChanged | WhoamiOK | Whoami401 | WhoamiNetErr
}

Subscribe(fn func(AuthEvent)) (unsubscribe func())
```

Emit points (extending existing call sites):

- `auth_service_impl.go:569` (`updateCredentials`) — `TokenSet` / `TokenChanged` / `TokenCleared`.
- `auth_service_impl.go:662` (`doAuthCheck`) outcomes — `WhoamiOK` / `Whoami401` / `WhoamiNetErr` (distinguish by error type).
- Logout path — `TokenCleared`.

Subscriber lifecycle: process-lifetime (AuthService stays alive for the LS process), no explicit teardown.

### `internal/connectivity` — derived state

Holds the current `State` enum. Applies the transition table to inbound `AuthEvent` and reachability signals. Stateless logic, single mutex around the enum.

On transitions, performs side effects:

- `→ Unauthenticated`: clear stored `ORGANIZATION`, `ORGANIZATION_SLUG`, `API_URL` (audience-derived) via `conf.Set(key, "")`.
- `→ Offline`: no side effect (stored values remain valid for cached reads while we can't reach the network).

### Adaptive offline detector

Rewires `application/server/server.go:569` (`startOfflineDetection`). Removes the `//nolint:unused`. Probes `https://downloads.snyk.io/cli/stable/version` via `engine.GetNetworkAccess().GetUnauthorizedHttpClient()`. Publishes `OnReachability(true|false)` to `ConnectivityService`. Adaptive cadence:

- Fast (10s) while `Offline`.
- Slow (60s) when `Online` and stable.

`SettingOffline` (the existing config bool) becomes a derived view over `!connectivity.IsOnline()` for backward compatibility with any remaining readers (`auth_service_impl.go:677`, `cli/initializer.go`, `snyk_api.go`, `scanner.go`).

### GAF default-func wrappers

At the snyk-ls boundary where the engine is constructed, replace registrations for `ORGANIZATION`, `ORGANIZATION_SLUG`, and `API_URL` with auth-aware wrappers:

```go
conf.AddDefaultValue(configuration.ORGANIZATION, func(ev, existing any) (any, error) {
    if s, ok := existing.(string); ok && s != "" {
        return s, nil  // already resolved
    }
    if !connectivity.IsAuthenticated() {
        return "", nil  // skip the network call; no retry storm
    }
    val, err := originalOrgDefaultFunc(ev, existing)
    if err == nil && val != nil && val != "" {
        ev.Set(configuration.ORGANIZATION, val)  // primes for future reads
    }
    return val, err
})
```

The wrapper does three things: short-circuit when the stored value is non-empty, short-circuit when not authenticated (returns `("", nil)` so the absence of an org is *not* an error), and persist successful results via `Set()` so subsequent reads bypass the default func entirely. Invalidation on auth-state transitions is done by ConnectivityService writing `""` back into the same keys.

## Implementation phases

1. **Auth events.** Add `Subscribe` / `publish` to `AuthenticationService`. Emit at `updateCredentials`, `doAuthCheck` outcomes, logout. Tests for emit-on-transition.
2. **ConnectivityService.** New `internal/connectivity` package with transition table and side effects. Unit tests for the full table.
3. **Adaptive offline detector.** Replace `startOfflineDetection`; remove `//nolint:unused`. Wire to `ConnectivityService.OnReachability`. Derive `SettingOffline` from state for back-compat.
4. **GAF default-func wrappers.** Wrap `ORGANIZATION`, `ORGANIZATION_SLUG`, `API_URL`. Integration test: 100 reads while unauthenticated → 0 outbound calls.
5. **Call-site migration.** Switch `IsAuthenticated()` callers (`scanner.go`, `get_active_user.go`, `server.go:268`, …) and `IsOffline` readers to the new primitives. Keep the AuthService 1-minute positive cache — it dedups `/whoami` within a window, which is a different concern.
6. **Retire #1245.** Delete:
   - `auth_service_impl.go:569` — `GetGlobalOrganization` prime call.
   - `server.go:325` — same prime call before LDX-Sync.
   - `config_resolver.go:256` — IsSet gate in `GlobalOrg()`.
7. **Tests + smoke.** Settings page read while unauthenticated issues zero requests. Login flow primes org via the wrapper (no explicit call). Logout clears org and slug.

## File touch points

- `infrastructure/authentication/auth_service_impl.go` — add `Subscribe`/publish; emit events at existing sites; remove prime call at :569.
- `internal/connectivity/` (new) — service, state machine, transition tests.
- `application/server/server.go` — rewire `startOfflineDetection` at :569; remove prime call at :325.
- `application/di/init.go` — wire `ConnectivityService`; subscribe to AuthService; register wrapped default funcs.
- `internal/types/config_resolver.go` — remove IsSet gate at :256.
- `internal/types/config_readers.go` — remove `GetGlobalOrganization` if no remaining callers (likely yes after phase 5/6).
- Call-site migrations (phase 5): `domain/snyk/scanner/scanner.go`, `domain/ide/command/get_active_user.go`, `infrastructure/learn/service.go`, `infrastructure/featureflag/featureflag.go`, `infrastructure/analytics/analytics.go`, `domain/ide/command/ldx_sync_service.go`.

## Acceptance criteria

- [ ] Settings page open while unauthenticated: 0 outbound calls regardless of read volume.
- [ ] N repeated reads of `ORGANIZATION` (or slug/API URL) while unauthenticated or offline: 0 outbound calls after the first state resolution.
- [ ] No remaining direct callers of `authService.IsAuthenticated()` outside `AuthenticationService` itself and `ConnectivityService`.
- [ ] PR #1245's prime calls and IsSet gate deleted.
- [ ] `startOfflineDetection` no longer `//nolint:unused`; publishes into `ConnectivityService`.
- [ ] Logout transitions ConnectivityService to `Unauthenticated` and clears stored org/slug/API URL; next read returns `""` without network.

## Follow-ups (out of scope for v1)

- Push-based subscriber model on `ConnectivityService` for refresh-on-transition (e.g., feature-flag refresh on `→ Authenticated`).
- HTTP roundtripper instrumentation for ground-truth reachability promotion. Requires either decorating `engine.NetworkAccess` (per-call client minting makes a single wrap impossible) or a GAF `AddTransport` middleware hook.
- Linter rule against direct `http.DefaultClient` / `http.Get` in production code, to keep future traffic flowing through the shared transport.
