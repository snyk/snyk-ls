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
	"net/url"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/erni27/imcache"
	"github.com/rs/zerolog"
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
)

const ExpirationMsg = "Your authentication failed due to token expiration. Please re-authenticate to continue using Snyk."
const InvalidCredsMessage = "Your authentication credentials cannot be validated. Automatically clearing credentials. You need to re-authenticate to use Snyk."
const MethodChangedMessage = "Your authentication method has changed. Please re-authenticate to continue using Snyk."

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
	lastUsedToken               string
	m                           sync.RWMutex
	previousAuthCtxCancelFunc   context.CancelFunc
	previousAuthCtxCancelFuncMu sync.Mutex
	postCredentialUpdateHook    func()
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
}

func NewAuthenticationService(engine workflow.Engine, tokenService types.TokenService, authProviders AuthenticationProvider, errorReporter error_reporting.ErrorReporter, notifier noti.Notifier, configResolver types.ConfigResolverInterface) AuthenticationService {
	cache := imcache.New[string, bool]()
	return &AuthenticationServiceImpl{
		authProvider:   authProviders,
		errorReporter:  errorReporter,
		notifier:       notifier,
		engine:         engine,
		tokenService:   tokenService,
		configResolver: configResolver,
		authCache:      cache,
	}
}

func (a *AuthenticationServiceImpl) AuthURL(ctx context.Context) string {
	// no lock should be used here, as this is usually called during authentication flow, which write-locks the mutex
	return a.authProvider.AuthURL(ctx)
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

	a.m.Lock()
	defer a.m.Unlock()

	a.previousAuthCtxCancelFuncMu.Lock()
	ctx, a.previousAuthCtxCancelFunc = context.WithCancel(ctx)
	a.previousAuthCtxCancelFuncMu.Unlock()

	defer a.previousAuthCtxCancelFunc() // need to clean up resources if we weren't interrupted, impl should ensure its safe to double call
	return a.authenticate(ctx)
}

func (a *AuthenticationServiceImpl) authenticate(ctx context.Context) (token string, err error) {
	if a.authProvider == nil {
		err = errors.New("authentication provider is not configured")
		a.engine.GetLogger().Warn().Err(err).Msg("Failed to authenticate: auth provider is nil")
		a.authCache.RemoveAll()
		return "", err
	}

	token, err = a.authProvider.Authenticate(ctx)

	if token == "" || err != nil {
		a.engine.GetLogger().Warn().Err(err).Msgf("Failed to authenticate using auth provider %v", reflect.TypeOf(a.authProvider))
		a.authCache.RemoveAll()
		return token, err
	}

	a.authCache.Set(token, true, imcache.WithSlidingExpiration(time.Minute))

	customUrl := a.configResolver.GetString(types.SettingApiEndpoint, nil)

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
		parsedCustom, perr := url.Parse(strings.TrimSpace(customUrl))
		switch {
		case perr != nil:
			// customUrl is unparseable; fall back to the previous full-string
			// comparison and emit the bare https://<host> override as before.
			if "https://"+newTokenHost != strings.TrimRight(customUrl, "/ ") {
				prioritizedUrl = "https://" + newTokenHost
			}
		case strings.EqualFold(parsedCustom.Host, newTokenHost):
			// Same host (case-insensitive): override is a no-op, fall through
			// to the standard custom-vs-engine resolution.
		default:
			prioritizedUrl = swapHost(strings.TrimSpace(customUrl), newTokenHost)
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
	if len(audiences) == 0 {
		return ""
	}
	raw := strings.TrimSpace(audiences[0])
	if raw == "" {
		return ""
	}
	parsed, perr := url.Parse(raw)
	if perr != nil {
		return ""
	}
	if parsed.Scheme != "" && parsed.Scheme != "http" && parsed.Scheme != "https" {
		logger.Debug().Str("scheme", parsed.Scheme).Msg("unsupported scheme in aud claim; skipping")
		return ""
	}
	host := parsed.Host
	if host == "" {
		// Bare-host fallback (aud="api.eu.snyk.io"); host-shape is enforced
		// downstream by IsValidAuthHost against CONFIG_KEY_ALLOWED_HOST_REGEXP.
		host = parsed.Path
	}
	if host == "" {
		return ""
	}
	host = strings.ToLower(host)
	regex := conf.GetString(auth.CONFIG_KEY_ALLOWED_HOST_REGEXP)
	if regex == "" {
		logger.Debug().Msg("CONFIG_KEY_ALLOWED_HOST_REGEXP unset; skipping API URL discovery")
		return ""
	}
	valid, verr := auth.IsValidAuthHost(host, regex)
	if verr != nil || !valid {
		logger.Warn().Str("host", host).Msg("oauth token aud claim failed allowed-host check; ignoring")
		return ""
	}
	return host
}

// swapHost returns rawCustomUrl with its host replaced by newHost. Scheme
// defaults to https when missing or non-http(s) so the override always emits
// a canonical Snyk endpoint regardless of how the user typed the customUrl.
// Path, query, and fragment are preserved verbatim. If rawCustomUrl is
// unparseable, returns "https://" + newHost as a safe fallback.
func swapHost(rawCustomUrl, newHost string) string {
	parsed, err := url.Parse(rawCustomUrl)
	if err != nil || parsed.Host == "" {
		return "https://" + newHost
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		parsed.Scheme = "https"
	}
	parsed.Host = newHost
	return parsed.String()
}

func (a *AuthenticationServiceImpl) SetPostCredentialUpdateHook(hook func()) {
	a.m.Lock()
	defer a.m.Unlock()
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

	if oldToken != newToken {
		// remove old token from cache, but don't add new token, as we want the entry only when
		// checks are performed - e.g. in IsAuthenticated or Authenticate which call the API to check for real
		a.authCache.Remove(oldToken)
		a.tokenService.SetToken(conf, newToken)
		// Reset the notification cooldown so the user gets immediate feedback after changing credentials
		a.notifDedup.Lock()
		a.notifDedup.lastMsg = ""
		a.notifDedup.lastTime = 0
		a.notifDedup.Unlock()
	}

	if a.postCredentialUpdateHook != nil && newToken != "" {
		func() {
			defer func() {
				if r := recover(); r != nil {
					a.engine.GetLogger().Error().Interface("panic", r).Msg("postCredentialUpdateHook panicked")
				}
			}()
			a.postCredentialUpdateHook()
		}()
	}

	if sendNotification {
		apiUrl := ""
		if updateApiUrl {
			apiUrl = a.configResolver.GetString(types.SettingApiEndpoint, nil)
		}
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

	if a.authProvider != nil {
		err := a.authProvider.ClearAuthentication(ctx)
		if err != nil {
			a.engine.GetLogger().Warn().Err(err).Str("method", "Logout").Msg("Failed to log out.")
			a.errorReporter.CaptureError(err)
		}
	}
	a.updateCredentials("", true, false)
	a.configureProviders(a.engine.GetConfiguration(), a.engine.GetLogger())
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

		invalidOAuth2Token, isLegacyTokenErr := config.ParseOAuthToken(config.GetToken(conf), a.engine.GetLogger())
		isLegacyToken := isLegacyTokenErr != nil

		a.handleEmptyUser(logger, isLegacyToken, invalidOAuth2Token)
		return false
	}
	// We cache the API auth ok for up to 1 minute after last access. If more than a minute has passed, a new check is
	// performed.
	a.authCache.Set(config.GetToken(conf), true, imcache.WithSlidingExpiration(time.Minute))

	// For API Token and PAT authentication, the user may not have authenticated as part of the authenticate flow; e.g.,
	// they could have pasted the token or PAT in to the IDE. In those cases, this will be the first time they have
	// authenticated using that token or PAT
	if a.lastUsedToken != config.GetToken(conf) {
		a.lastUsedToken = config.GetToken(conf)

		if config.GetAuthenticationMethodFromConfig(a.engine.GetConfiguration()) != types.OAuthAuthentication {
			a.sendAuthenticationAnalytics()
		}
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

	// "authentication failed" only appears when the OAuth server explicitly rejected the
	// credentials (e.g. invalid_grant on token refresh). This is a permanent failure and
	// must trigger logout even when wrapped inside a url.Error transport chain.
	if strings.Contains(errMsg, "authentication failed") {
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
	}
	// Check whether we have a valid token for the current auth method
	token := config.GetToken(conf)
	if token != "" && !config.AuthenticationMethodMatchesCredentials(token, authMethod, logger) {
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
