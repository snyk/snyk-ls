/*
 * © 2022-2024 Snyk Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package authentication

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/erni27/imcache"
	"github.com/rs/zerolog"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
	sglsp "github.com/sourcegraph/go-lsp"
	"golang.org/x/oauth2"
	"golang.org/x/sync/singleflight"

	"github.com/snyk/snyk-ls/application/config"
	analytics2 "github.com/snyk/snyk-ls/infrastructure/analytics"
	"github.com/snyk/snyk-ls/internal/data_structure"
	noti "github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/util"
)

const ExpirationMsg = "Your authentication failed due to token expiration. Please re-authenticate to continue using Snyk."
const InvalidCredsMessage = "Your authentication credentials cannot be validated. Automatically clearing credentials. You need to re-authenticate to use Snyk."
const MethodChangedMessage = "Your authentication method has changed. Please re-authenticate to continue using Snyk."

// credentialUpdate represents a request to update credentials with synchronization.
type credentialUpdate struct {
	token            string
	sendNotification bool
	updateApiUrl     bool
}

type AuthenticationServiceImpl struct {
	authProvider   AuthenticationProvider
	errorReporter  error_reporting.ErrorReporter
	notifier       noti.Notifier
	engine         workflow.Engine
	tokenService   types.TokenService
	configResolver types.ConfigResolverInterface
	// key = token, value = isAuthenticated
	authCache *imcache.Cache[string, bool]
	// Last token that was successfully used for authentication. It might have expired (so not be present in authCache).
	// Uses its own mutex (not m) because doAuthCheck runs under m.RLock, which allows
	// concurrent writers here.
	lastUsedToken               string
	lastUsedTokenMu             sync.Mutex
	m                           sync.RWMutex
	previousAuthCtxCancelFunc   context.CancelFunc
	previousAuthCtxCancelFuncMu sync.Mutex
	postCredentialUpdateHook    func()
	postCredentialUpdateHookMu  sync.RWMutex
	// notifDedup deduplicates "Could not retrieve authentication status" balloon notifications
	// from concurrent IsAuthenticated() callers. Uses its own mutex (not m) because doAuthCheck
	// runs under m.RLock. Different error messages are shown immediately; identical messages
	// are suppressed for 30 seconds.
	notifDedup struct {
		sync.Mutex
		lastMsg  string
		lastTime int64 // UnixNano
	}
	// authCheckGroup coalesces concurrent auth API calls so only one in-flight request
	// is made at a time; all waiters share the same result.
	authCheckGroup singleflight.Group
	// credentialUpdateChan serializes credential updates from the OAuth storage bridge
	// to prevent race conditions where older tokens overwrite newer ones during rapid rotations.
	credentialUpdateChan chan credentialUpdate
	// credentialUpdateCancel cancels the credential update worker on shutdown.
	credentialUpdateCancel context.CancelFunc
	// writingToken holds a pointer to the token string that the credentialUpdateWorker
	// is currently writing to conf via updateCredentials → tokenService.SetToken →
	// WriteTokenToConfig → conf.Set(auth.CONFIG_KEY_OAUTH_TOKEN, …).  When the conf key
	// is persisted, that conf.Set call flows back through the storage's Set method, which
	// fires the registered OAuth storage-bridge callback, which calls QueueCredentialUpdate
	// again — re-enqueueing the same token the worker is already applying.  The re-enqueued
	// copy lands after newer tokens in the channel and, on Windows where time.Now() has
	// 15 ms resolution and all three rapid-rotation tokens share the same expiry, the
	// shouldUpdateToken expiry check allows the stale copy to overwrite the final token.
	//
	// QueueCredentialUpdate skips the enqueue when the value matches writingToken, breaking
	// the re-entrancy cycle.  External updates (from GAF refreshing the OAuth token) always
	// carry a different token string and are never silently dropped by this guard.
	writingToken atomic.Pointer[string]
}

func NewAuthenticationService(engine workflow.Engine, tokenService types.TokenService, authProviders AuthenticationProvider, errorReporter error_reporting.ErrorReporter, notifier noti.Notifier, configResolver types.ConfigResolverInterface) AuthenticationService {
	cache := imcache.New[string, bool]()
	updateChan := make(chan credentialUpdate, 100)
	ctx, cancel := context.WithCancel(context.Background())

	service := &AuthenticationServiceImpl{
		authProvider:           authProviders,
		errorReporter:          errorReporter,
		notifier:               notifier,
		engine:                 engine,
		tokenService:           tokenService,
		configResolver:         configResolver,
		authCache:              cache,
		credentialUpdateChan:   updateChan,
		credentialUpdateCancel: cancel,
	}

	// Start worker goroutine to process credential updates sequentially
	go service.credentialUpdateWorker(ctx)

	return service
}

func (a *AuthenticationServiceImpl) AuthURL(ctx context.Context) string {
	// no lock should be used here, as this is usually called during authentication flow, which write-locks the mutex
	return a.authProvider.AuthURL(ctx)
}

// credentialUpdateWorker processes credential updates sequentially from the channel.
// This prevents race conditions where older tokens overwrite newer ones during rapid rotations.
func (a *AuthenticationServiceImpl) credentialUpdateWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case update := <-a.credentialUpdateChan:
			// Advertise which token we are about to write so QueueCredentialUpdate can
			// recognize and drop the re-entrant callback that fires when
			// WriteTokenToConfig calls conf.Set(auth.CONFIG_KEY_OAUTH_TOKEN, …) and
			// the key is persisted in storage (which triggers the bridge callback again).
			// The clear is deferred so it always runs even if updateCredentials panics,
			// preventing the guard from staying permanently armed for that token string.
			func() {
				a.writingToken.Store(&update.token)
				defer a.writingToken.Store(nil)
				a.updateCredentials(update.token, update.sendNotification, update.updateApiUrl)
			}()
		}
	}
}

// QueueCredentialUpdate queues a credential update for sequential processing.
// This is used by the OAuth storage bridge callback to serialize updates.
//
// Re-entrancy guard: when WriteTokenToConfig calls conf.Set(auth.CONFIG_KEY_OAUTH_TOKEN, …)
// and the key is persisted in storage, the storage fires the bridge callback again with the
// exact same token the worker is currently applying.  Enqueueing that copy would let a stale
// token overwrite a newer one after the main sequence has already finished (observable on
// Windows where time.Now() has 15 ms resolution and rapid-rotation tokens share the same
// expiry, making shouldUpdateToken return true for the stale copy).  We drop the re-entrant
// call by comparing the incoming token against writingToken; external updates from GAF always
// carry a different token string and are never silently dropped by this guard.
func (a *AuthenticationServiceImpl) QueueCredentialUpdate(token string, sendNotification bool, updateApiUrl bool) {
	if w := a.writingToken.Load(); w != nil && *w == token {
		// Re-entrant call: the worker is already applying this exact token via
		// conf.Set → storage.Set → callback.  Drop it to prevent the stale copy
		// from landing behind newer tokens in the channel.
		a.engine.GetLogger().Debug().
			Str("method", "AuthenticationService.QueueCredentialUpdate").
			Msg("dropping duplicate credential update for token already being written")
		return
	}
	select {
	case a.credentialUpdateChan <- credentialUpdate{
		token:            token,
		sendNotification: sendNotification,
		updateApiUrl:     updateApiUrl,
	}:
	default:
		a.engine.GetLogger().Warn().
			Msg("credential update channel full, dropping update")
	}
}

// Shutdown cleans up resources such as the credential update worker goroutine.
func (a *AuthenticationServiceImpl) Shutdown() {
	if a.credentialUpdateCancel != nil {
		a.credentialUpdateCancel()
	}
}

func (a *AuthenticationServiceImpl) Provider() AuthenticationProvider {
	a.m.RLock()
	defer a.m.RUnlock()

	return a.authProvider
}

func (a *AuthenticationServiceImpl) provider() AuthenticationProvider {
	return a.authProvider
}

func (a *AuthenticationServiceImpl) Authenticate(ctx context.Context) (token string, err error) {
	a.CancelOngoingAuth()

	// Capture our own cancel func in a local: a.previousAuthCtxCancelFunc is written under its mutex by
	// concurrent Authenticate calls, so deferring the field directly would both data-race and risk
	// canceling a newer login. The local always refers to this call's own cancel func.
	//
	// Concurrent Authenticate calls are not strictly single-flight: if two race past CancelOngoingAuth
	// before either registers its cancel func, neither cancels the other and both proceed — they then
	// resolve last-writer-wins in finishAuthenticate under a.m, which is acceptable (both apply
	// legitimate credentials).
	a.previousAuthCtxCancelFuncMu.Lock()
	var cancel context.CancelFunc
	ctx, cancel = context.WithCancel(ctx)
	a.previousAuthCtxCancelFunc = cancel
	a.previousAuthCtxCancelFuncMu.Unlock()
	defer cancel() // safe to double-call; cleans up if we weren't interrupted

	// Snapshot the provider under the auth mutex, then release it for the interactive
	// provider.Authenticate call, which can block for up to ~2 minutes waiting for the browser.
	// Holding a.m across that wait blocks ConfigureProviders and every other a.m user — including a
	// didChangeConfiguration notification handler, which would then stall the whole LSP request
	// pipeline (jrpc2 serializes request dispatch behind an outstanding notification) and stop a
	// subsequent login from canceling this one.
	//
	// Supersession invariant: a caller that supersedes an in-flight login by clearing or reconfiguring
	// provider state cancels the auth context first (via CancelOngoingAuth), so the ctx.Err() guard
	// below discards this login's now-stale result. Logout does this directly; ConfigureProviders
	// relies on its caller ApplyAuthMethodChange to cancel before reconfiguring. This is about
	// correctness, not deadlock avoidance — releasing a.m above means nothing ever waits on the
	// interactive provider call while holding a.m.
	a.m.RLock()
	provider := a.authProvider
	a.m.RUnlock()

	if provider == nil {
		err = errors.New("authentication provider is not configured")
		a.engine.GetLogger().Warn().Err(err).Msg("Failed to authenticate: auth provider is nil")
		a.m.Lock()
		a.authCache.RemoveAll()
		a.m.Unlock()
		return "", err
	}

	token, err = provider.Authenticate(ctx)

	a.m.Lock()
	defer a.m.Unlock()

	// While we waited without the lock, a concurrent Logout or a newer Authenticate may have run its
	// own a.m critical section, canceling our context. If so, this login has been superseded — do not
	// apply its result, or we would re-establish credentials a Logout just cleared (or clobber a newer
	// login). This deliberately discards even a token the provider had just successfully returned when
	// a cancel coincides; that is the accepted trade-off. The cancellation propagates upward and is
	// treated as expected by util.IsCancellation.
	if ctxErr := ctx.Err(); ctxErr != nil {
		a.engine.GetLogger().Debug().Str("method", "Authenticate").Msg("authentication superseded before applying result; discarding")
		return "", ctxErr
	}

	return a.finishAuthenticate(provider, token, err)
}

// finishAuthenticate applies the result of the provider's Authenticate call — caching, endpoint
// discovery, credential update and provider reconfiguration. The caller must hold a.m.
func (a *AuthenticationServiceImpl) finishAuthenticate(provider AuthenticationProvider, token string, err error) (string, error) {
	if token == "" || err != nil {
		// A canceled authentication (e.g. the IDE canceled the login via $/cancelRequest) is expected,
		// not a failure: log at debug rather than warning.
		if util.IsCancellation(err) {
			a.engine.GetLogger().Debug().Str("method", "finishAuthenticate").Msg("authentication canceled")
		} else {
			a.engine.GetLogger().Warn().Err(err).Msgf("Failed to authenticate using auth provider %v", reflect.TypeOf(provider))
		}
		a.authCache.RemoveAll()
		return token, err
	}

	a.authCache.Set(token, true, imcache.WithSlidingExpiration(time.Minute))

	// Normalize whitespace and trailing slash once up front.
	// getPrioritizedApiUrl right-trims " " and "/" so the post-resolution
	// "did the URL change?" gate would otherwise compare a trimmed
	// prioritizedUrl against an un-trimmed customUrl and fire a spurious
	// "API Endpoint has been updated" notification on every authenticate
	// when the user has stray whitespace or a trailing slash in the
	// endpoint setting.
	customUrl := strings.TrimRight(strings.TrimSpace(a.configResolver.GetString(types.SettingApiEndpoint, nil)), "/ ")

	// Prefer the new token's aud claim — it is the OAuth-authoritative URL
	// after any instance redirect. GAF's modifyTokenUrl rewrites only
	// oauthConfig.Endpoint.TokenURL, not configuration.API_URL, so the freshly
	// issued access token is the only signal we have.
	//
	// Note: when the aud claim names a host that is rejected by the allowed-host
	// regex, this branch is a no-op — but GAF's defaultFuncApiUrl callback
	// still re-derives configuration.API_URL from the persisted token's aud
	// regardless of our validation. Outbound calls (analytics, Snyk Code) may
	// therefore target the rogue host until the user logs out. Closing that gap
	// is tracked separately as the locked-endpoint follow-up.
	newTokenHost := extractAudHost(token, a.engine.GetConfiguration(), a.engine.GetLogger())

	var prioritizedUrl string
	if newTokenHost != "" {
		// Compare on hosts only so that path-bearing customUrls (e.g. the
		// single-tenant pattern "https://api.snyk.io/api/v1") are preserved
		// when the aud claim names the same host. When hosts differ, swap
		// only the host portion of customUrl so any path/query/fragment
		// configured by the user survives the override.
		customHost, parseOK := customUrlHost(customUrl)
		switch {
		case !parseOK:
			// customUrl is unparseable; fall back to the previous full-string
			// comparison and emit the bare https://<host> override as before.
			// customUrl is already TrimRight'd of "/ " above, so a direct
			// equality check suffices here.
			if "https://"+newTokenHost != customUrl {
				prioritizedUrl = "https://" + newTokenHost
			}
		case strings.EqualFold(customHost, newTokenHost):
			// Same host (case-insensitive): override is a no-op, fall through
			// to the standard custom-vs-engine resolution.
		default:
			prioritizedUrl = swapHost(customUrl, newTokenHost)
		}
	}
	if prioritizedUrl == "" {
		engineUrl := a.engine.GetConfiguration().GetString(configuration.API_URL)
		prioritizedUrl = getPrioritizedApiUrl(customUrl, engineUrl)
	}

	shouldSendUrlUpdatedNotification := prioritizedUrl != customUrl
	if shouldSendUrlUpdatedNotification {
		defer a.notifier.SendShowMessage(sglsp.Info, fmt.Sprintf("The Snyk API Endpoint has been updated to %s.", prioritizedUrl))
		config.UpdateApiEndpointsOnConfig(a.engine.GetConfiguration(), prioritizedUrl)
	}

	a.updateCredentials(token, true, shouldSendUrlUpdatedNotification)
	a.configureProviders(a.engine.GetConfiguration(), a.engine.GetLogger())
	a.sendAuthenticationAnalytics()
	return token, err
}

func (a *AuthenticationServiceImpl) sendAuthenticationAnalytics() {
	event := analytics2.NewAnalyticsEventParam("authenticated", nil, "")
	// Add the authentication details in the extension fields. We only send the method name; we must not include any
	// authentication tokens.
	event.Extension = map[string]any{
		"auth::auth-type": string(config.GetAuthenticationMethodFromConfig(a.engine.GetConfiguration())),
	}

	// Send to any folder's org, since authentication is not folder-specific, but analytics have to be sent to a
	// specific org, so any folder's org has as good a chance as any other to work and not 404.
	// TODO - This is a temporary solution to avoid inflating analytics counts.
	ws := config.GetWorkspace(a.engine.GetConfiguration())
	if ws != nil {
		folders := ws.Folders()
		if len(folders) > 0 {
			aFolderOrg := config.FolderOrganization(a.engine.GetConfiguration(), folders[0].Path(), a.engine.GetLogger())
			analytics2.SendAnalytics(a.engine, a.configResolver.GetString(types.SettingDeviceId, nil), aFolderOrg, event, nil)
			return
		}
	}

	// Fallback: If no folders, send with global org (user's preferred org from the web UI if not explicitly set)
	analytics2.SendAnalytics(a.engine, a.configResolver.GetString(types.SettingDeviceId, nil), types.GetGlobalOrganization(a.engine.GetConfiguration()), event, nil)
}

func getPrioritizedApiUrl(customUrl string, engineUrl string) string {
	defaultUrl := config.DefaultSnykApiUrl
	customUrl = strings.TrimRight(customUrl, "/ ")

	// If the custom URL is not changed (equals default) and no engine URL is provided,
	// use the default URL.
	if customUrl == defaultUrl && engineUrl == "" {
		return defaultUrl
	}

	// If the custom URL equals the default but an engine URL is provided, use the engine URL.
	// The authentication flow has redirected the user to the correct endpoint.
	// http://api.eu.snyk.io
	if customUrl == defaultUrl {
		return engineUrl
	}

	if customUrl == "" && engineUrl != "" {
		return engineUrl
	}

	// Otherwise, return the custom URL set by the user.
	// FedRAMP and single tenant environments.
	return customUrl
}

// extractAudHost decodes the JWT `aud` claim of the access token and returns
// the canonical lowercase host (e.g. "api.snyk.io") when the host is a valid
// Snyk auth host (per CONFIG_KEY_ALLOWED_HOST_REGEXP). Returns "" for opaque
// tokens, missing/empty/null claims, parse failures, an unset or
// invalid-regex CONFIG_KEY_ALLOWED_HOST_REGEXP (fail-closed), or hosts that
// fail the allowed-host regex check.
//
// RFC 7519 says `aud` MAY be a single string OR an array of strings, and
// when an array there is no guaranteed ordering. Snyk OAuth tokens can
// therefore carry the API host at any index of the array, optionally
// preceded by non-host entries (e.g. a client ID). extractAudHost iterates
// every entry and returns the first one that passes the full validation
// chain — only checking index 0 would silently fail discovery for
// legitimate tokens whose host happens not to be first.
//
// This is a snyk-ls-side workaround for GAF's modifyTokenUrl, which on an
// OAuth instance redirect rewrites only oauthConfig.Endpoint.TokenURL and
// leaves configuration.API_URL untouched.
func extractAudHost(token string, conf configuration.Configuration, logger *zerolog.Logger) string {
	if token == "" {
		return ""
	}
	audiences, err := auth.GetAudienceClaimFromOauthToken(token)
	if err != nil {
		logger.Debug().Err(err).Msg("cannot decode oauth token aud claim; skipping API URL discovery")
		return ""
	}
	// Read the regex once up front so the per-entry hot loop doesn't
	// repeat the conf.GetString lookup, and so the fail-closed branch
	// triggers regardless of how many audiences are present.
	regex := conf.GetString(auth.CONFIG_KEY_ALLOWED_HOST_REGEXP)
	if regex == "" {
		logger.Debug().Msg("CONFIG_KEY_ALLOWED_HOST_REGEXP unset; skipping API URL discovery")
		return ""
	}
	for _, raw := range audiences {
		if host := audHostFromClaim(raw, regex, logger); host != "" {
			return host
		}
	}
	return ""
}

// audHostFromClaim parses a single aud claim entry and returns its
// canonical lowercase host iff it passes the scheme allowlist and the
// CONFIG_KEY_ALLOWED_HOST_REGEXP check. Returns "" on any rejection so the
// caller can move on to the next array entry. Per-entry rejections are
// logged at Debug (not Warn) because most array-form aud claims contain
// non-host entries (e.g. a client ID) that legitimately fail this check;
// promoting them to Warn would flood production logs on every authenticate.
func audHostFromClaim(raw, regex string, logger *zerolog.Logger) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	// Delegate to parseCustomUrl so schemeless aud claims with a port
	// ("api.snyk.io:8080" — which url.Parse misreads as Scheme="api.snyk.io"
	// / Opaque="8080") get re-parsed under "https://" the same way custom
	// API URLs do; otherwise the scheme allowlist would silently drop them.
	parsed, ok := parseCustomUrl(raw)
	if !ok {
		logger.Debug().Str("aud_claim", raw).Msg("cannot parse aud claim entry as URL; trying next")
		return ""
	}
	// After parseCustomUrl's re-parse, Scheme is either empty (path-only
	// inputs that yielded no Host on re-parse, handled by the Path
	// fallback below) or http/https. Anything else is a genuinely
	// unsupported scheme.
	if parsed.Scheme != "" && parsed.Scheme != "http" && parsed.Scheme != "https" {
		logger.Debug().Str("scheme", parsed.Scheme).Str("aud_claim", raw).Msg("unsupported scheme in aud claim entry; trying next")
		return ""
	}
	// Hostname() strips the port, so swapHost cannot double-append the
	// customUrl's port onto the aud-derived host (which would corrupt
	// SettingApiEndpoint as "host:audPort:customPort").
	host := parsed.Hostname()
	if host == "" {
		// Path fallback for inputs parseCustomUrl couldn't recover into
		// a Host (e.g. "/path-only"). The result is still validated
		// below by IsValidAuthHost, which enforces domain-suffix
		// membership against CONFIG_KEY_ALLOWED_HOST_REGEXP (not
		// generic host syntax).
		host = parsed.Path
	}
	if host == "" {
		return ""
	}
	host = strings.ToLower(host)
	valid, verr := auth.IsValidAuthHost(host, regex)
	if verr != nil || !valid {
		logger.Debug().Str("host", host).Str("aud_claim", raw).Msg("aud claim entry failed allowed-host check; trying next")
		return ""
	}
	return host
}

// parseCustomUrl normalises a user-supplied customUrl into a *url.URL by
// re-parsing schemeless inputs (e.g. "api.snyk.io:8080/v1") under "https://"
// so swapHost can surgically swap the host while preserving port, path,
// query, and fragment. Schemeless inputs land in url.Parse in two shapes,
// both with an empty Host and no recognizable web Scheme:
//   - "api.eu.snyk.io/v1"      -> Scheme="", Host="", Path=<all>
//   - "api.eu.snyk.io:8080/v1" -> Scheme="api.eu.snyk.io", Opaque="8080/v1"
//
// The boolean return is false only when url.Parse itself fails (e.g.
// invalid percent-encoding) so callers can distinguish "unparseable" from
// "parseable but empty host".
//
// The re-parse trigger is `Host == "" && Scheme not in {"http", "https"}`.
// This intentionally INCLUDES Scheme == "" (the schemeless host case we
// want to recover) and EXCLUDES well-formed but pathological inputs like
// "http:///v1" (recognized scheme, empty Host) — those keep their original
// parse and yield parseOK=true with an empty Host so swapHost falls back
// to "https://" + newHost.
//
// Defense-in-depth: the secondary `reparsed.Host != ""` guard rejects any
// re-parse that still produces an empty Host. This catches both pathological
// inputs like "http:///v1" (which url.Parse would otherwise interpret as
// Host="http:" — a host-injection-shaped result we never want to feed back
// into SettingApiEndpoint) and trivially-empty inputs (the empty string
// matches the re-parse trigger via Scheme=="" but yields no usable host).
//
// Whitespace is trimmed defensively so the helper is safe in isolation:
// the sole production caller already pre-trims, but this guards future
// callers from accidentally feeding padded input.
func parseCustomUrl(rawCustomUrl string) (*url.URL, bool) {
	rawCustomUrl = strings.TrimSpace(rawCustomUrl)
	parsed, err := url.Parse(rawCustomUrl)
	if err != nil {
		return nil, false
	}
	needsHTTPSPrefix := parsed.Host == "" && parsed.Scheme != "http" && parsed.Scheme != "https"
	if needsHTTPSPrefix {
		reparsed, rerr := url.Parse("https://" + rawCustomUrl)
		if rerr == nil && reparsed.Host != "" {
			parsed = reparsed
		}
	}
	return parsed, true
}

// customUrlHost returns the lowercase hostname (no port) of rawCustomUrl,
// canonicalising schemeless inputs the same way swapHost does so that the
// host-equality gate in authenticate compares apples to apples for
// "api.snyk.io" vs aud "https://api.snyk.io". The boolean return is false
// only when url.Parse fails outright; an empty hostname with ok=true means
// the input was parseable but carried no host (e.g. "/path-only").
func customUrlHost(rawCustomUrl string) (string, bool) {
	parsed, ok := parseCustomUrl(rawCustomUrl)
	if !ok {
		return "", false
	}
	return strings.ToLower(parsed.Hostname()), true
}

// swapHost returns rawCustomUrl with its host replaced by newHost. Scheme
// defaults to https when missing or non-http(s) so the override always
// emits a canonical Snyk endpoint regardless of how the user typed the
// customUrl. Path, query, and fragment are preserved verbatim, including
// for schemeless inputs like "api.eu.snyk.io/v1" (which url.Parse
// classifies as Path-only) — those are re-parsed via parseCustomUrl. If
// rawCustomUrl is wholly unparseable, returns "https://" + newHost as a
// safe fallback.
//
// Any explicit port previously present on rawCustomUrl is intentionally
// DROPPED on host swap. The user's port belonged to the prior deployment
// (e.g. a single-tenant non-443 listener) and may not be valid on the new
// host: forwarding it onto a different deployment can produce a
// physically wrong endpoint such as "https://api.snyk.io:8443/v1" when
// the global instance answers only on the implicit default. Snyk OAuth
// `aud` claims today never carry an explicit port, so the new
// deployment's port is whatever its scheme implies.
//
// swapHost is only invoked from the host-change branch in authenticate
// (the same-host gate short-circuits before reaching it), so dropping
// the port here is always the deployment-correct behavior.
func swapHost(rawCustomUrl, newHost string) string {
	parsed, ok := parseCustomUrl(rawCustomUrl)
	if !ok || parsed.Host == "" {
		return "https://" + newHost
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		parsed.Scheme = "https"
	}
	parsed.Host = newHost
	return parsed.String()
}

func (a *AuthenticationServiceImpl) SetPostCredentialUpdateHook(hook func()) {
	a.postCredentialUpdateHookMu.Lock()
	defer a.postCredentialUpdateHookMu.Unlock()
	a.postCredentialUpdateHook = hook
}

func (a *AuthenticationServiceImpl) UpdateCredentials(newToken string, sendNotification bool, updateApiUrl bool) {
	a.m.Lock()
	defer a.m.Unlock()

	a.updateCredentials(newToken, sendNotification, updateApiUrl)
}

func (a *AuthenticationServiceImpl) updateCredentials(newToken string, sendNotification bool, updateApiUrl bool) {
	conf := a.engine.GetConfiguration()
	oldToken := config.GetToken(conf)
	if oldToken == newToken && !updateApiUrl {
		return
	}

	a.engine.GetLogger().Debug().
		Str("method", "AuthenticationService.updateCredentials").
		Bool("old_token_empty", oldToken == "").
		Bool("new_token_empty", newToken == "").
		Bool("send_notification", sendNotification).
		Bool("update_api_url", updateApiUrl).
		Str("authentication_method", string(config.GetAuthenticationMethodFromConfig(conf))).
		Msg("auth credentials update requested")

	if oldToken != newToken {
		// remove old token from cache, but don't add new token, as we want the entry only when
		// checks are performed - e.g. in IsAuthenticated or Authenticate which call the API to check for real
		a.authCache.Remove(oldToken)
		a.tokenService.SetToken(conf, newToken)
		if config.GetToken(conf) != newToken {
			a.engine.GetLogger().Debug().
				Str("method", "AuthenticationService.updateCredentials").
				Bool("requested_token_empty", newToken == "").
				Bool("current_token_empty", config.GetToken(conf) == "").
				Str("authentication_method", string(config.GetAuthenticationMethodFromConfig(conf))).
				Msg("auth credentials update skipped because token was not applied")
			return
		}
		// Reset the notification cooldown so the user gets immediate feedback after changing credentials
		a.notifDedup.Lock()
		a.notifDedup.lastMsg = ""
		a.notifDedup.lastTime = 0
		a.notifDedup.Unlock()
	}

	a.postCredentialUpdateHookMu.RLock()
	postCredentialUpdateHook := a.postCredentialUpdateHook
	a.postCredentialUpdateHookMu.RUnlock()
	if postCredentialUpdateHook != nil && newToken != "" {
		func() {
			defer func() {
				if r := recover(); r != nil {
					a.engine.GetLogger().Error().Interface("panic", r).Msg("postCredentialUpdateHook panicked")
				}
			}()
			postCredentialUpdateHook()
		}()
	}

	if newToken != "" {
		// Prime ORGANIZATION for hot-path GlobalOrg(); see GetGlobalOrganization.
		_ = types.GetGlobalOrganization(a.engine.GetConfiguration())
	}

	if sendNotification {
		apiUrl := ""
		if updateApiUrl {
			apiUrl = a.configResolver.GetString(types.SettingApiEndpoint, nil)
		}
		a.engine.GetLogger().Debug().
			Str("method", "AuthenticationService.updateCredentials").
			Bool("token_empty", newToken == "").
			Bool("api_url_empty", apiUrl == "").
			Str("authentication_method", string(config.GetAuthenticationMethodFromConfig(conf))).
			Msg("sending auth credentials notification")
		a.notifier.Send(types.AuthenticationParams{Token: newToken, ApiUrl: apiUrl})
	}
}

func (a *AuthenticationServiceImpl) Logout(ctx context.Context) {
	a.previousAuthCtxCancelFuncMu.Lock()
	if a.previousAuthCtxCancelFunc != nil {
		// We don't set it back to nil as then we'd need to handle race conditions and double calling an old cancel function is already safe by the impl.
		a.previousAuthCtxCancelFunc()
	}
	a.previousAuthCtxCancelFuncMu.Unlock()

	a.m.Lock()
	defer a.m.Unlock()

	a.logout(ctx)
}

func (a *AuthenticationServiceImpl) CancelOngoingAuth() {
	a.previousAuthCtxCancelFuncMu.Lock()
	if a.previousAuthCtxCancelFunc != nil {
		a.previousAuthCtxCancelFunc()
	}
	a.previousAuthCtxCancelFuncMu.Unlock()
}

func (a *AuthenticationServiceImpl) logout(ctx context.Context) {
	a.engine.GetConfiguration().ClearCache()
	a.engine.GetLogger().Info().
		Str("method", "AuthenticationService.logout").
		Bool("token_empty", config.GetToken(a.engine.GetConfiguration()) == "").
		Str("authentication_method", string(config.GetAuthenticationMethodFromConfig(a.engine.GetConfiguration()))).
		Msg("clearing authentication credentials")

	if a.authProvider != nil {
		err := a.authProvider.ClearAuthentication(ctx)
		if err != nil {
			a.engine.GetLogger().Warn().Err(err).Str("method", "Logout").Msg("Failed to log out.")
			a.errorReporter.CaptureError(err)
		}
	}
	a.updateCredentials("", true, false)
	a.configureProviders(a.engine.GetConfiguration(), a.engine.GetLogger())

	a.lastUsedTokenMu.Lock()
	a.lastUsedToken = ""
	a.lastUsedTokenMu.Unlock()
}

// IsAuthenticated returns true if the token is verified
// If the token is set, but not valid IsAuthenticated returns false
func (a *AuthenticationServiceImpl) IsAuthenticated() bool {
	a.m.RLock()
	defer a.m.RUnlock()

	return a.isAuthenticated()
}

func (a *AuthenticationServiceImpl) isAuthenticated() bool {
	logger := a.engine.GetLogger().With().Str("method", "AuthenticationService.IsAuthenticated").Logger()

	conf := a.engine.GetConfiguration()
	token := config.GetToken(conf)

	_, isNotExpired := a.authCache.Get(token)
	if isNotExpired {
		logger.Debug().Msg("IsAuthenticated (found in cache)")
		return true
	}

	if token == "" {
		logger.Info().Str("method", "IsAuthenticated").Msg("no credentials found")
		return false
	}

	return a.doAuthCheck(conf, logger)
}

type authCheckResult struct {
	user string
	err  error
}

func (a *AuthenticationServiceImpl) doAuthCheck(conf configuration.Configuration, logger zerolog.Logger) bool {
	a.handleProviderInconsistencies()

	// Coalesce concurrent auth API calls: all in-flight callers share one result.
	token := config.GetToken(conf)
	v, _, _ := a.authCheckGroup.Do(token, func() (interface{}, error) {
		u, e := a.authProvider.GetCheckAuthenticationFunction()(a.engine)
		return &authCheckResult{user: u, err: e}, nil
	})
	ar, ok := v.(*authCheckResult)
	if !ok {
		return false
	}
	user, err := ar.user, ar.err
	if user == "" {
		if a.configResolver.GetBool(types.SettingOffline, nil) || (err != nil && !shouldCauseLogout(err, a.engine.GetLogger())) {
			// Deduplicate balloon notifications from concurrent callers. Identical messages
			// are suppressed for 30s; different error messages are shown immediately so the
			// user sees feedback when the error cause changes (e.g., connectivity → invalid token).
			userMsg := "Could not retrieve authentication status. Most likely this is a temporary error " +
				"caused by connectivity problems. If this message does not go away, please log out and re-authenticate"
			if err != nil {
				userMsg += fmt.Sprintf(" (%s)", err.Error())
			}
			a.notifDedup.Lock()
			sameMsg := a.notifDedup.lastMsg == userMsg
			recentlySent := time.Since(time.Unix(0, a.notifDedup.lastTime)) <= 30*time.Second
			shouldSend := !sameMsg || !recentlySent
			if shouldSend {
				a.notifDedup.lastMsg = userMsg
				a.notifDedup.lastTime = time.Now().UnixNano()
			}
			a.notifDedup.Unlock()
			if shouldSend {
				a.notifier.SendShowMessage(sglsp.MTError, userMsg)
			}

			logger.Info().Msg("not logging out, as we had an error, but returning not authenticated to caller")
			return false
		}

		invalidOAuth2Token, isLegacyTokenErr := config.ParseOAuthToken(token, a.engine.GetLogger())
		isLegacyToken := isLegacyTokenErr != nil

		a.handleEmptyUser(logger, isLegacyToken, invalidOAuth2Token)
		return false
	}
	// We cache the API auth ok for up to 1 minute after last access. If more than a minute has passed, a new check is
	// performed.
	//
	// Cache/track the token that was actually verified above (captured once at function
	// entry), not a fresh config.GetToken(conf) read: a concurrent credentialUpdateWorker
	// write (which bypasses a.m entirely, see lastUsedToken field doc) can rotate the config
	// token between the API call and here, which would otherwise mark an unverified token as
	// authenticated (cache poisoning) or, on the error path above, misjudge a freshly rotated
	// valid token as the failed one and log out a valid session.
	a.authCache.Set(token, true, imcache.WithSlidingExpiration(time.Minute))

	// For API Token and PAT authentication, the user may not have authenticated as part of the authenticate flow; e.g.,
	// they could have pasted the token or PAT in to the IDE. In those cases, this will be the first time they have
	// authenticated using that token or PAT
	a.lastUsedTokenMu.Lock()
	isNewToken := a.lastUsedToken != token
	if isNewToken {
		a.lastUsedToken = token
	}
	a.lastUsedTokenMu.Unlock()
	if isNewToken && config.GetAuthenticationMethodFromConfig(a.engine.GetConfiguration()) != types.OAuthAuthentication {
		a.sendAuthenticationAnalytics()
	}
	logger.Debug().Str("userId", user).Msg("Authenticated, adding to cache.")
	return true
}

// configure providers, if needed, as specified in the config
func (a *AuthenticationServiceImpl) handleProviderInconsistencies() {
	authMethod := config.GetAuthenticationMethodFromConfig(a.engine.GetConfiguration())
	msg := fmt.Sprintf("inconsistent auth provider, resetting (authMethod: %s, authenticator: %s)", authMethod, reflect.TypeOf(a.authProvider))
	var ok bool
	switch {
	case a.authProvider == nil:
		ok = false
		msg = "auth provider is not set, resetting to default"
	case authMethod == types.OAuthAuthentication:
		_, ok = a.authProvider.(*OAuth2Provider)
	case authMethod == types.TokenAuthentication:
		_, ok = a.authProvider.(*CliAuthenticationProvider)
	case authMethod == types.PatAuthentication:
		_, ok = a.authProvider.(*PatAuthenticationProvider)
	case authMethod == types.FakeAuthentication:
		_, fake := a.authProvider.(*FakeAuthenticationProvider)
		_, cli := a.authProvider.(*CliAuthenticationProvider)
		ok = fake || cli
	default:
		ok = false
		msg = fmt.Sprintf("Unsupported authentication method: %s", authMethod)
	}
	if !ok {
		a.engine.GetLogger().Warn().Msg(msg)
		a.configureProviders(a.engine.GetConfiguration(), a.engine.GetLogger())
	}
}

// isTransientNetworkError returns true for errors caused by network-level failures
// that are unrelated to credential validity (DNS, TCP, context cancellation, etc.).
func isTransientNetworkError(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return true
	}
	var netErr *net.OpError
	if errors.As(err, &netErr) {
		return true
	}
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr)
}

func shouldCauseLogout(err error, logger *zerolog.Logger) bool {
	logger.
		Err(err).Str("method", "AuthenticationService.IsAuthenticated").Msg("error while trying to authenticate user")

	errMsg := strings.ToLower(err.Error())

	if isPermanentOAuthRefreshError(errMsg) {
		return true
	}

	// A structured Snyk API error with a definitive auth status code is a permanent failure,
	// even though http.Client.Do always wraps it in a *url.Error (which isTransientNetworkError
	// would otherwise treat as transient network noise).
	var snykErr snyk_errors.Error
	if errors.As(err, &snykErr) && (snykErr.StatusCode == http.StatusUnauthorized || snykErr.StatusCode == http.StatusBadRequest) {
		return true
	}

	// Transient network-level errors must never trigger logout.
	if isTransientNetworkError(err) {
		return false
	}

	var syntaxError *json.SyntaxError
	switch {
	case errors.As(err, &syntaxError):
		return true

	// string matching where we don't have explicit errors
	default:
		switch {
		case strings.Contains(errMsg, "oauth2"):
			return true
		case strings.Contains(errMsg, "(status: 401)"):
			return true
		case strings.Contains(errMsg, "(status: 400)"):
			return true
		case strings.Contains(errMsg, "unexpected end of JSON input"):
			return true
		// 5xx server errors are transient and must not trigger logout.
		case strings.Contains(errMsg, "(status: 5"):
			return false
		case strings.Contains(errMsg, "failed to invoke whoami workflow"):
			return true

		default:
			logger.Err(err).Msg("unspecified error during auth: not logging out")
			return false
		}
	}
}

func isPermanentOAuthRefreshError(errMsg string) bool {
	return strings.Contains(errMsg, "authentication failed") ||
		strings.Contains(errMsg, "invalid_grant") ||
		strings.Contains(errMsg, "token_inactive")
}

func (a *AuthenticationServiceImpl) handleEmptyUser(logger zerolog.Logger, isLegacyToken bool, invalidToken oauth2.Token) {
	logger.Info().Msg("could not authenticate user with current credentials, API returned empty user object")
	logger.Info().Msg("logging out, empty user response")
	a.logout(context.Background())

	// determine the right error message
	if !isLegacyToken {
		// it is an oauth token
		if invalidToken.Expiry.Before(time.Now()) {
			a.handleFailedRefresh()
		} else {
			// access token not expired, but creds still not work
			a.handleInvalidCredentials()
		}
	} else {
		// legacy token does not work
		a.handleInvalidCredentials()
	}
}

func (a *AuthenticationServiceImpl) handleFailedRefresh() {
	// access token expired and refresh failed
	a.sendAuthenticationRequest(ExpirationMsg, "Re-authenticate")
}

func (a *AuthenticationServiceImpl) SetProvider(provider AuthenticationProvider) {
	a.m.Lock()
	defer a.m.Unlock()

	a.setProvider(provider)
}

func (a *AuthenticationServiceImpl) setProvider(provider AuthenticationProvider) {
	a.authProvider = provider
}

func (a *AuthenticationServiceImpl) ConfigureProviders(conf configuration.Configuration, logger *zerolog.Logger) {
	a.m.Lock()
	defer a.m.Unlock()

	a.configureProviders(conf, logger)
}

func (a *AuthenticationServiceImpl) configureProviders(conf configuration.Configuration, logger *zerolog.Logger) {
	authMethod := config.GetAuthenticationMethodFromConfig(conf)
	subLogger := logger.With().
		Str("method", "configureProviders").
		Str("authenticationMethod", string(authMethod)).
		Bool("tokenEmpty", config.GetToken(conf) == "").Logger()

	subLogger.Debug().Msg("configuring providers")

	authMethodChanged := a.provider() == nil || a.provider().AuthenticationMethod() != authMethod

	// always set the provider even if the authentication method didn't change, to make sure that the provider is initialized with current config
	if authMethodChanged {
		var p AuthenticationProvider
		switch authMethod {
		default:
			p = Default(a.engine, a)
			a.setProvider(p)
		case types.TokenAuthentication:
			p = Token(a.engine, a.errorReporter, a.configResolver)
			a.setProvider(p)
		case types.PatAuthentication:
			p = Pat(a.engine, a)
			a.setProvider(p)
		case types.FakeAuthentication:
			a.setProvider(NewFakeCliAuthenticationProvider(a.engine))
		case "":
			// don't do anything
		}
		subLogger.Debug().
			Str("provider_type", fmt.Sprintf("%T", a.provider())).
			Msg("auth provider configured")
	}
	// Check whether we have a valid token for the current auth method
	token := config.GetToken(conf)
	if token != "" && !config.AuthenticationMethodMatchesCredentials(token, authMethod, logger) {
		subLogger.Info().
			Str("provider_type", fmt.Sprintf("%T", a.provider())).
			Msg("configured auth method does not match current token; clearing credentials")
		a.logout(context.Background())
		if authMethodChanged {
			subLogger.Info().Msg("detected auth provider change, logging out and sending re-auth message")
			a.sendAuthenticationRequest(MethodChangedMessage, "Re-authenticate")
		} else {
			subLogger.Info().Msg("detected token change which is incompatible with auth provider.")
			a.handleInvalidCredentials()
		}
	}
}

func (a *AuthenticationServiceImpl) handleInvalidCredentials() {
	a.sendAuthenticationRequest(InvalidCredsMessage, "Authenticate")
}

func (a *AuthenticationServiceImpl) sendAuthenticationRequest(msg string, actionName string) {
	actions := data_structure.OrderedMap[types.MessageAction, types.CommandData]{}
	actions.Add(types.MessageAction(actionName), types.CommandData{
		Title:     actionName,
		CommandId: types.LoginCommand,
	})
	actions.Add("Cancel", types.CommandData{})

	a.notifier.Send(types.ShowMessageRequest{
		Message: msg,
		Type:    types.Warning,
		Actions: &actions,
	})
}
