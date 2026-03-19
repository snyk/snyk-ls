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
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/erni27/imcache"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	sglsp "github.com/sourcegraph/go-lsp"
	"golang.org/x/oauth2"

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
	authProvider  AuthenticationProvider
	errorReporter error_reporting.ErrorReporter
	notifier      noti.Notifier
	c             *config.Config
	// key = token, value = isAuthenticated
	authCache *imcache.Cache[string, bool]
	// Last token that was successfully used for authentication. It might have expired (so not be present in authCache).
	lastUsedToken               string
	m                           sync.RWMutex
	previousAuthCtxCancelFunc   context.CancelFunc
	previousAuthCtxCancelFuncMu sync.Mutex
}

func NewAuthenticationService(c *config.Config, authProviders AuthenticationProvider, errorReporter error_reporting.ErrorReporter, notifier noti.Notifier) AuthenticationService {
	cache := imcache.New[string, bool]()
	return &AuthenticationServiceImpl{
		authProvider:  authProviders,
		errorReporter: errorReporter,
		notifier:      notifier,
		c:             c,
		authCache:     cache,
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

// Authenticate starts a new authentication flow, canceling any in-progress flow first.
// a.m.Lock() is held for the duration so that concurrent IsAuthenticated() calls (which
// need a.m.RLock()) cannot interfere with the login flow. The second caller will block
// until the first fully completes; canceling the previous context causes its CLI subprocess
// to be killed promptly so the wait is brief.
//
// previousAuthCtxCancelFuncMu is released before a.m.Lock() is acquired so that a third
// concurrent caller can signal cancellation even while the second is waiting for the lock.
func (a *AuthenticationServiceImpl) Authenticate(_ context.Context) (token string, err error) {
	a.previousAuthCtxCancelFuncMu.Lock()
	if a.previousAuthCtxCancelFunc != nil {
		a.previousAuthCtxCancelFunc()
	}
	a.previousAuthCtxCancelFuncMu.Unlock()

	a.m.Lock()
	defer a.m.Unlock()

	authCtx, cancel := context.WithCancel(context.Background())
	a.previousAuthCtxCancelFuncMu.Lock()
	a.previousAuthCtxCancelFunc = cancel
	a.previousAuthCtxCancelFuncMu.Unlock()

	defer cancel()
	return a.authenticate(authCtx)
}

func (a *AuthenticationServiceImpl) authenticate(ctx context.Context) (token string, err error) {
	ap := a.authProvider

	if ap == nil {
		err = errors.New("authentication provider is not configured")
		a.c.Logger().Warn().Err(err).Msg("Failed to authenticate: auth provider is nil")
		a.authCache.RemoveAll()
		return "", err
	}

	token, err = ap.Authenticate(ctx)

	if token == "" || err != nil {
		a.c.Logger().Warn().Err(err).Msgf("Failed to authenticate using auth provider %v", reflect.TypeOf(ap))
		a.authCache.RemoveAll()
		return token, err
	}

	a.authCache.Set(token, true, imcache.WithSlidingExpiration(time.Minute))

	customUrl := a.c.SnykApi()
	engineUrl := a.c.Engine().GetConfiguration().GetString(configuration.API_URL)
	prioritizedUrl := getPrioritizedApiUrl(customUrl, engineUrl)

	shouldSendUrlUpdatedNotification := prioritizedUrl != customUrl
	if shouldSendUrlUpdatedNotification {
		defer a.notifier.SendShowMessage(sglsp.Info, fmt.Sprintf("The Snyk API Endpoint has been updated to %s.", prioritizedUrl))
		a.c.UpdateApiEndpoints(prioritizedUrl)
		// Reconfigure providers for the new endpoint so all subsequent operations
		// (e.g. workspace scans) use the updated URL rather than the pre-auth one.
		a.configureProviders(a.c)
	}

	a.updateCredentials(token, true, shouldSendUrlUpdatedNotification)
	a.sendAuthenticationAnalytics()
	return token, err
}

func (a *AuthenticationServiceImpl) sendAuthenticationAnalytics() {
	event := analytics2.NewAnalyticsEventParam("authenticated", nil, "")
	// Add the authentication details in the extension fields. We only send the method name; we must not include any
	// authentication tokens.
	event.Extension = map[string]any{
		"auth::auth-type": string(a.c.AuthenticationMethod()),
	}

	// Send to any folder's org, since authentication is not folder-specific, but analytics have to be sent to a
	// specific org, so any folder's org has as good a chance as any other to work and not 404.
	// TODO - This is a temporary solution to avoid inflating analytics counts.
	ws := a.c.Workspace()
	if ws != nil {
		folders := ws.Folders()
		if len(folders) > 0 {
			aFolderOrg := a.c.FolderOrganization(folders[0].Path())
			analytics2.SendAnalytics(a.c.Engine(), a.c.DeviceID(), aFolderOrg, event, nil)
			return
		}
	}

	// Fallback: If no folders, send with global org (user's preferred org from the web UI if not explicitly set)
	analytics2.SendAnalytics(a.c.Engine(), a.c.DeviceID(), a.c.Organization(), event, nil)
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

func (a *AuthenticationServiceImpl) UpdateCredentials(newToken string, sendNotification bool, updateApiUrl bool) {
	a.m.Lock()
	defer a.m.Unlock()

	a.updateCredentials(newToken, sendNotification, updateApiUrl)
}

func (a *AuthenticationServiceImpl) updateCredentials(newToken string, sendNotification bool, updateApiUrl bool) {
	oldToken := a.c.Token()
	if oldToken == newToken && !updateApiUrl {
		return
	}

	if oldToken != newToken {
		// remove old token from cache, but don't add new token, as we want the entry only when
		// checks are performed - e.g. in IsAuthenticated or Authenticate which call the API to check for real
		a.authCache.Remove(oldToken)
		a.c.SetToken(newToken)
	}

	if sendNotification {
		apiUrl := ""
		if updateApiUrl {
			apiUrl = a.c.SnykApi()
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

	// ClearAuthentication removes the token from provider-specific storage (e.g. the CLI
	// config file). It is only called here — on explicit user logout — not from the internal
	// logout() helper. The helper is called from paths that hold a.m.RLock() (e.g. inside
	// isAuthenticated()), where spawning a CLI subprocess would deadlock or cause excessive
	// latency.
	if err := a.authProvider.ClearAuthentication(ctx); err != nil {
		a.c.Logger().Warn().Err(err).Str("method", "Logout").Msg("Failed to log out.")
		a.errorReporter.CaptureError(err)
	}
	a.logout(ctx)
}

func (a *AuthenticationServiceImpl) logout(ctx context.Context) {
	a.c.Engine().GetConfiguration().ClearCache()
	a.updateCredentials("", true, false)
	a.configureProviders(a.c)
}

// IsAuthenticated returns true if the token is verified
// If the token is set, but not valid IsAuthenticated returns false
func (a *AuthenticationServiceImpl) IsAuthenticated() bool {
	a.m.RLock()
	defer a.m.RUnlock()

	return a.isAuthenticated()
}

func (a *AuthenticationServiceImpl) isAuthenticated() bool {
	logger := a.c.Logger().With().Str("method", "AuthenticationService.IsAuthenticated").Logger()

	_, isNotExpired := a.authCache.Get(a.c.Token())
	if isNotExpired {
		logger.Debug().Msg("IsAuthenticated (found in cache)")
		return true
	}

	noToken := !a.c.NonEmptyToken()
	if noToken {
		logger.Info().Str("method", "IsAuthenticated").Msg("no credentials found")
		return false
	}

	a.handleProviderInconsistencies()

	user, err := a.authProvider.GetCheckAuthenticationFunction()()
	if user == "" {
		if a.c.Offline() || (err != nil && !shouldCauseLogout(err, a.c.Logger())) {
			userMsg := "Could not retrieve authentication status. Most likely this is a temporary error " +
				"caused by connectivity problems. If this message does not go away, please log out and re-authenticate"
			if err != nil {
				userMsg += fmt.Sprintf(" (%s)", err.Error())
			}
			a.notifier.SendShowMessage(sglsp.MTError, userMsg)

			logger.Info().Msg("not logging out, as we had an error, but returning not authenticated to caller")
			return false
		}

		invalidOAuth2Token, isLegacyTokenErr := a.c.TokenAsOAuthToken()
		isLegacyToken := isLegacyTokenErr != nil

		a.handleEmptyUser(logger, isLegacyToken, invalidOAuth2Token)
		return false
	}
	// We cache the API auth ok for up to 1 minute after last access. If more than a minute has passed, a new check is
	// performed.
	a.authCache.Set(a.c.Token(), true, imcache.WithSlidingExpiration(time.Minute))

	// For API Token and PAT authentication, the user may not have authenticated as part of the authenticate flow; e.g.,
	// they could have pasted the token or PAT in to the IDE. In those cases, this will be the first time they have
	// authenticated using that token or PAT
	if a.lastUsedToken != a.c.Token() {
		a.lastUsedToken = a.c.Token()

		if a.c.AuthenticationMethod() != types.OAuthAuthentication {
			a.sendAuthenticationAnalytics()
		}
	}
	logger.Debug().Str("userId", user).Msg("Authenticated, adding to cache.")
	return true
}

// configure providers, if needed, as specified in the config
func (a *AuthenticationServiceImpl) handleProviderInconsistencies() {
	msg := fmt.Sprintf("inconsistent auth provider, resetting (authMethod: %s, authenticator: %s)", a.c.AuthenticationMethod(), reflect.TypeOf(a.authProvider))
	var ok bool
	switch {
	case a.authProvider == nil:
		ok = false
		msg = "auth provider is not set, resetting to default"
	case a.c.AuthenticationMethod() == types.OAuthAuthentication:
		_, ok = a.authProvider.(*OAuth2Provider)
	case a.c.AuthenticationMethod() == types.TokenAuthentication:
		_, ok = a.authProvider.(*CliAuthenticationProvider)
	case a.c.AuthenticationMethod() == types.PatAuthentication:
		_, ok = a.authProvider.(*PatAuthenticationProvider)
	case a.c.AuthenticationMethod() == types.FakeAuthentication:
		_, fake := a.authProvider.(*FakeAuthenticationProvider)
		_, cli := a.authProvider.(*CliAuthenticationProvider)
		ok = fake || cli
	default:
		ok = false
		msg = fmt.Sprintf("Unsupported authentication method: %s", a.c.AuthenticationMethod())
	}
	if !ok {
		a.c.Logger().Warn().Msg(msg)
		// Use switchProviderForMethod instead of configureProviders to avoid triggering slow
		// operations (CLI subprocesses) while IsAuthenticated() holds a.m.RLock(). Credential
		// mismatch cleanup happens in configureProviders() when explicitly invoked.
		a.switchProviderForMethod(a.c)
	}
}

func shouldCauseLogout(err error, logger *zerolog.Logger) bool {
	logger.
		Err(err).Str("method", "AuthenticationService.IsAuthenticated").Msg("error while trying to authenticate user")

	var syntaxError *json.SyntaxError
	switch {
	case errors.As(err, &syntaxError):
		return true

	// string matching where we don't have explicit errors
	default:
		errMsg := err.Error()
		switch {
		case strings.Contains(errMsg, "oauth2"):
			return true
		case strings.Contains(errMsg, "(status: 401)"):
			return true
		case strings.Contains(errMsg, "(status: 400)"):
			return true
		case strings.Contains(errMsg, "unexpected end of JSON input"):
			return true
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

func (a *AuthenticationServiceImpl) ConfigureProviders(c *config.Config) {
	a.m.Lock()
	defer a.m.Unlock()

	a.configureProviders(c)
}

// switchProviderForMethod updates the auth provider to match the configured auth method
// without checking credential compatibility or performing logout. It is safe to call in
// contexts where slow operations (such as CLI subprocesses) must not be triggered, for
// example inside IsAuthenticated() which holds a.m.RLock().
func (a *AuthenticationServiceImpl) switchProviderForMethod(c *config.Config) {
	authMethodChanged := a.provider() == nil || a.provider().AuthenticationMethod() != c.AuthenticationMethod()
	if !authMethodChanged {
		return
	}

	c.Logger().Debug().
		Str("method", "switchProviderForMethod").
		Str("authenticationMethod", string(c.AuthenticationMethod())).
		Msg("switching provider for auth method")

	switch c.AuthenticationMethod() {
	default:
		a.setProvider(Default(c, a))
	case types.TokenAuthentication:
		a.setProvider(Token(c, a.errorReporter))
	case types.PatAuthentication:
		a.setProvider(Pat(c, a))
	case types.FakeAuthentication:
		a.setProvider(NewFakeCliAuthenticationProvider(c))
	case "":
		// don't do anything
	}
}

func (a *AuthenticationServiceImpl) configureProviders(c *config.Config) {
	logger := c.Logger().With().
		Str("method", "configureProviders").
		Str("authenticationMethod", string(c.AuthenticationMethod())).
		Bool("tokenEmpty", c.Token() == "").Logger()

	logger.Debug().Msg("configuring providers")

	authMethodChanged := a.provider() == nil || a.provider().AuthenticationMethod() != c.AuthenticationMethod()

	a.switchProviderForMethod(c)

	// Check whether we have a valid token for the current auth method
	if c.NonEmptyToken() && !c.AuthenticationMethodMatchesCredentials() {
		// Clear the in-memory token and cache without running ClearAuthentication() (which spawns a
		// CLI subprocess and can take several seconds). ClearAuthentication() is not needed here
		// because the user will authenticate fresh, and the next auth flow will set a new token.
		// sendNotification=false to avoid overriding a Token=newToken notification that was already
		// sent by a concurrent Authenticate() call, which would cause the IDE to revert to an
		// unauthenticated state immediately after successful auth.
		a.c.Engine().GetConfiguration().ClearCache()
		a.updateCredentials("", false, false)
		if authMethodChanged {
			logger.Info().Msg("detected auth provider change, logging out and sending re-auth message")
			a.sendAuthenticationRequest(MethodChangedMessage, "Re-authenticate")
		} else {
			// Token is incompatible with the current provider but the provider itself has not
			// changed. This happens when the IDE sends a stale/incompatible token via
			// workspace/didChangeConfiguration (e.g. a second config update arriving during an
			// auth-method switch). The token has already been cleared above; no user-facing
			// notification is needed — IsAuthenticated() will return false and the IDE will
			// prompt for re-authentication through normal UI flows.
			logger.Info().Msg("detected token incompatible with auth provider, clearing silently")
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
