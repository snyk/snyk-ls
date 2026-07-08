# Auth Re-login Investigation (IDE-2133-like)

Branch: `fix/auth-relogin-waits-for-timeout`  
Status: **incomplete / parked** — OAuth→OAuth re-login works, method-switching still broken.

## Symptom

Re-login waits for the previous OAuth flow to time out (120 s). Scenario:

1. Click **Authenticate** (OAuth) → browser link opens
2. Close the browser tab
3. Click **Authenticate** again in the HTML settings form
4. Nothing happens until the first flow times out (120 s)

Also observed: `auth method change requested new_auth_method=oauth old_auth_method=oauth` logged on every re-login.

## Root Cause

Two independent locks serialize authentication:

### Lock 1 — `a.m` (RWMutex on `AuthenticationServiceImpl`)

**Old code**: `Authenticate()` held `a.m.Lock()` for the entire OAuth browser wait (up to 120 s).

`loginCommand.Execute` (n==3, from the HTML form) calls `ConfigureProviders()` before starting the new auth. `ConfigureProviders()` tries `a.m.Lock()` → **deadlock for 120 s**.

**Fix (commit `900bd1ed`)**: Capture the provider under a brief `RLock`, run `provider.Authenticate(ctx)` without holding `a.m`, re-acquire `a.m.Lock()` only to save results.

### Lock 2 — `p.m` (Mutex on `OAuth2Provider`)

`OAuth2Provider.Authenticate` holds `p.m.Lock()` for the entire `CancelableAuthenticate` call.

When the auth method is **unchanged** (oauth → oauth), `configureProviders` previously skipped creating a new provider (the `if authMethodChanged` guard). So the second `Authenticate()` captured the **same** provider and blocked on its locked `p.m`.

**Fix (commit `2fcc534c`)**: Always replace the provider in `configureProviders`, even when the method is unchanged. Credential mismatch is checked before replacement so `ClearAuthentication` is called on the correct (old) provider, then `logout`'s recursive `configureProviders` call handles the actual replacement.

## What Works After These Fixes

- OAuth → OAuth re-login: second browser link opens immediately ✓
- `ConfigureProviders()` no longer blocks for 120 s ✓
- All 154 auth tests pass ✓
- CI green (32 min) ✓

## What Is Still Broken

Switching auth method (OAuth → Legacy Token or PAT) still locks the user out, and switching back to OAuth also fails. Root cause not fully identified — needs LS logs from around the method switch. Suspected causes:

- `CliAuthenticationProvider.Authenticate` runs `snyk auth` CLI; if the CLI path is wrong or the user dismisses the browser, they end up with no token and no way back without restarting
- Possible race: `defer SetPostCredentialUpdateHook(nil)` from the first (canceled) `loginCommand.Execute` clears the hook set by the concurrent second command, so post-auth LDX sync / feature flag flush doesn't run
- `OAuth2Provider.ClearAuthentication` acquires `p.m.Lock()` — still contends with a concurrent auth's `p.m` during method-switch + mismatch path (brief block, not 120 s, but may leave config in unexpected state)

## Key Files

| File | What |
|------|------|
| `infrastructure/authentication/auth_service_impl.go` | `Authenticate()`, `configureProviders()` — both changed |
| `infrastructure/authentication/auth_configuration.go` | `Default()`, `Token()`, `Pat()` — factory functions with config side effects |
| `infrastructure/authentication/oauth_provider.go` | `OAuth2Provider.Authenticate` holds `p.m` for full browser wait |
| `infrastructure/authentication/cli_provider.go` | `CliAuthenticationProvider.Authenticate` runs `snyk auth` via exec |
| `domain/ide/command/login.go` | `loginCommand.Execute` — calls `CancelOngoingAuth` + `ConfigureProviders` + `Authenticate` |
| `domain/ide/command/apply_auth_config.go` | `ApplyAuthMethodChange` — always calls `ConfigureProviders` even for same method |

## GAF Context

`globalRefreshMutex` in GAF's `CancelableAuthenticate` (`pkg/auth/oauth2authenticator.go`) is held briefly only to read OAuth config — **not** during the browser wait. The real bottleneck is `OAuth2Provider.p.m`.

`serveAndListen` wraps the incoming context with `context.WithTimeout(ctx, 120s)`. When `CancelOngoingAuth()` cancels the parent context, the timeout context is also canceled, the `<-ctx.Done()` goroutine fires `srv.Shutdown(context.Background())`, and `srv.Serve` returns `http.ErrServerClosed` — releasing `p.m` in milliseconds.

## How To Resume

1. Reproduce method-switch lockout and capture LS logs (VSCode Output → Snyk Security or `snyk.logPath`)
2. Look for lines after `"auth method change requested"` — does `"authentication canceled"` appear? Does the second browser link open?
3. Check if `postCredentialUpdateHook` race (see above) is the cause by adding a temporary log in `updateCredentials` when `postCredentialUpdateHook == nil`
4. Consider fixing `SetPostCredentialUpdateHook` race: the hook should be owned by the service, not set/cleared per-command
