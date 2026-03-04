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
	"sync/atomic"
	"time"

	"github.com/erni27/imcache"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/auth"
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

const (
	ExpirationMsg        = "Your authentication failed due to token expiration. Please re-authenticate to continue using Snyk."
	InvalidCredsMessage  = "Your authentication credentials cannot be validated. Automatically clearing credentials. You need to re-authenticate to use Snyk."
	MethodChangedMessage = "Your authentication method has changed. Please re-authenticate to continue using Snyk."
)

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
	// loginInProgress distinguishes login from token refresh in the OAuth credentials callback.
	// During login, the callback skips token storage (the IDE handles it via didChangeConfiguration).
	// During refresh, the callback stores the token immediately.
	loginInProgress atomic.Bool
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
	// no lock is used here; this is called by the provider during its own authentication flow
	return a.authProvider.AuthURL(ctx)
}

func (a *AuthenticationServiceImpl) IsLoginInProgress() bool {
	return a.loginInProgress.Load()
}

func (a *AuthenticationServiceImpl) Provider() AuthenticationProvider {
	a.m.RLock()
	defer a.m.RUnlock()

	return a.authProvider
}

func (a *AuthenticationServiceImpl) provider() AuthenticationProvider {
	return a.authProvider
}

func (a *AuthenticationServiceImpl) Authenticate(ctx context.Context, authMethod string, endpoint string, insecure bool) (AuthenticateResult, error) {
	// Step 1: Cancel any previous in-flight flow and install our cancel function.
	// previousAuthCtxCancelFuncMu is the narrow mutex for cancel function swap only.
	a.previousAuthCtxCancelFuncMu.Lock()
	if a.previousAuthCtxCancelFunc != nil {
		a.previousAuthCtxCancelFunc()
	}
	authCtx, cancel := context.WithCancel(context.Background())
	a.previousAuthCtxCancelFunc = cancel
	a.previousAuthCtxCancelFuncMu.Unlock()

	// Step 2: Release context resources on return. Double-canceling is safe per the context
	// package contract (same guarantee relied on by Logout).
	defer cancel()

	a.loginInProgress.Store(true)
	defer a.loginInProgress.Store(false)

	// Step 3: Create a temporary provider for this auth flow. We do not modify a.authProvider here;
	// no shared state is changed until the IDE sends the token back via didChangeConfiguration.
	provider, authConf, err := a.selectProvider(authMethod, endpoint, insecure)
	if err != nil {
		a.c.Logger().Warn().Err(err).Str("method", "Authenticate").Msg("failed to select auth provider")
		return AuthenticateResult{}, err
	}

	// Step 4: Run the auth flow without holding any mutex.
	return a.authenticate(authCtx, provider, authConf, endpoint)
}

// selectProvider maps the passed authMethod string to the correct provider for the login flow.
// The caller receives a temporary provider that is discarded after the auth flow completes.
// The shared engine configuration is never mutated; each OAuth attempt clones it.
// For OAuth, the cloned configuration is also returned so the caller can read API_URL from it
// after the token has been written by GAF's persistToken. For all other methods, nil is returned.
func (a *AuthenticationServiceImpl) selectProvider(authMethod string, endpoint string, insecure bool) (AuthenticationProvider, configuration.Configuration, error) {
	method := types.AuthenticationMethod(authMethod)

	switch method {
	case types.OAuthAuthentication:
		// Clone the shared engine config so this temporary login provider cannot mutate it.
		// Critically, GAF's Clone() does not copy persistedKeys, so the clone starts with an
		// empty persistedKeys map. Combined with WithoutTokenPersistence() (which skips the
		// PersistInStorage call in the authenticator constructor), this guarantees that
		// persistToken's config.Set(CONFIG_KEY_OAUTH_TOKEN) never triggers a disk write.
		// Without the clone, the shared config already has CONFIG_KEY_OAUTH_TOKEN in its
		// persistedKeys from GAF initialization, and WithoutTokenPersistence() alone would
		// not prevent the disk write because it only skips re-registering the key.
		conf := a.c.Engine().GetConfiguration().Clone()
		conf.Set(configuration.FF_OAUTH_AUTH_FLOW_ENABLED, true)
		authenticator := auth.NewOAuth2AuthenticatorWithOpts(
			conf,
			auth.WithApiURL(endpoint),
			auth.WithoutTokenPersistence(),
			auth.WithOpenBrowserFunc(makeOpenBrowserFunc(a)),
			auth.WithLogger(a.c.Logger()),
			auth.WithHttpClient(a.c.Engine().GetNetworkAccess().GetUnauthorizedHttpClient()),
		)
		p := newOAuthProvider(conf, authenticator, a.c.Logger())
		// Return conf so authenticate() can read API_URL after GAF writes the new token's audience.
		return p, conf, nil
	case types.TokenAuthentication:
		p := NewCliAuthenticationProvider(a.c, a.errorReporter)
		p.Insecure = insecure
		p.Endpoint = endpoint
		return p, nil, nil
	case types.PatAuthentication:
		conf := a.c.Engine().GetConfiguration()
		p := newPatAuthenticationProvider(conf, types.DefaultOpenBrowserFunc, a.c.Logger())
		p.Endpoint = endpoint
		return p, nil, nil
	case types.FakeAuthentication:
		// Reuse the existing provider if it is already a fake authentication type.
		// This allows tests to inject custom fake providers (e.g. slow providers for concurrency testing).
		if existing := a.provider(); existing != nil && existing.AuthenticationMethod() == types.FakeAuthentication {
			return existing, nil, nil
		}
		return NewFakeCliAuthenticationProvider(a.c), nil, nil
	default:
		return nil, nil, fmt.Errorf("unsupported authentication method: %s", authMethod)
	}
}

func (a *AuthenticationServiceImpl) authenticate(ctx context.Context, provider AuthenticationProvider, authConf configuration.Configuration, endpoint string) (AuthenticateResult, error) {
	if provider == nil {
		err := errors.New("authentication provider is not configured")
		a.c.Logger().Warn().Err(err).Msg("Failed to authenticate: auth provider is nil")
		a.authCache.RemoveAll()
		return AuthenticateResult{}, err
	}

	token, err := provider.Authenticate(ctx)

	if token == "" || err != nil {
		a.c.Logger().Warn().Err(err).Msgf("Failed to authenticate using auth provider %v", reflect.TypeOf(provider))
		a.authCache.RemoveAll()
		return AuthenticateResult{}, err
	}

	apiUrl := deriveApiUrl(authConf, endpoint)
	return AuthenticateResult{Token: token, ApiUrl: apiUrl}, nil
}

// makeOpenBrowserFunc returns a browser-open callback that records the auth URL on the current
// provider and then opens the browser. Used by both the temporary login provider (selectProvider)
// and the persistent OAuth provider (Default in auth_configuration.go).
func makeOpenBrowserFunc(svc AuthenticationService) func(string) {
	return func(url string) {
		svc.provider().setAuthUrl(url)
		types.DefaultOpenBrowserFunc(url)
	}
}

// deriveApiUrl reads API_URL from the cloned GAF config (which GAF populates from the new token's
// audience claim after OAuth authentication). If the config is nil or returns an empty string,
// the fallbackEndpoint is used instead (e.g. for Token and PAT flows).
func deriveApiUrl(authConf configuration.Configuration, fallbackEndpoint string) string {
	if authConf != nil {
		if derivedUrl := authConf.GetString(configuration.API_URL); derivedUrl != "" {
			return derivedUrl
		}
	}
	return fallbackEndpoint
}

func (a *AuthenticationServiceImpl) sendAuthenticationAnalytics(authMethod types.AuthenticationMethod) {
	event := analytics2.NewAnalyticsEventParam("authenticated", nil, "")
	// Add the authentication details in the extension fields. We only send the method name; we must not include any
	// authentication tokens.
	event.Extension = map[string]any{
		"auth::auth-type": string(authMethod),
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

func (a *AuthenticationServiceImpl) UpdateCredentials(newToken string, sendNotification bool, persist bool) {
	a.m.Lock()
	defer a.m.Unlock()

	a.updateCredentials(newToken, sendNotification, persist)
}

func (a *AuthenticationServiceImpl) updateCredentials(newToken string, sendNotification bool, persist bool) {
	oldToken := a.c.Token()
	if oldToken == newToken {
		return
	}

	// remove old token from cache, but don't add new token, as we want the entry only when
	// checks are performed - e.g. in IsAuthenticated or Authenticate which call the API to check for real
	a.authCache.Remove(oldToken)
	a.c.SetToken(newToken)

	if sendNotification {
		a.notifier.Send(types.AuthenticationParams{Token: newToken, ApiUrl: a.c.SnykApi(), Persist: persist})
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

func (a *AuthenticationServiceImpl) logout(ctx context.Context) {
	a.c.Engine().GetConfiguration().ClearCache()

	err := a.authProvider.ClearAuthentication(ctx)
	if err != nil {
		a.c.Logger().Warn().Err(err).Str("method", "Logout").Msg("Failed to log out.")
		a.errorReporter.CaptureError(err)
	}
	a.updateCredentials("", false, false)
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

	// Send analytics on the first successful check for any auth method. For Token and PAT the user may
	// have pasted credentials directly into the IDE without going through Authenticate(). For OAuth the
	// token is obtained via Authenticate() but analytics are deferred here so the method is always
	// sourced from the saved config (which is only set after didChangeConfiguration).
	if a.lastUsedToken != a.c.Token() {
		a.lastUsedToken = a.c.Token()
		a.sendAuthenticationAnalytics(a.c.AuthenticationMethod())
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
		a.configureProviders(a.c)
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

func (a *AuthenticationServiceImpl) configureProviders(c *config.Config) {
	logger := c.Logger().With().
		Str("method", "configureProviders").
		Str("authenticationMethod", string(c.AuthenticationMethod())).
		Bool("tokenEmpty", c.Token() == "").Logger()

	logger.Debug().Msg("configuring providers")

	authMethodChanged := a.provider() == nil || a.provider().AuthenticationMethod() != c.AuthenticationMethod()

	// always set the provider even if the authentication method didn't change, to make sure that the provider is initialized with current config
	if authMethodChanged {
		var p AuthenticationProvider
		switch c.AuthenticationMethod() {
		default:
			p = Default(c, a)
			a.setProvider(p)
		case types.TokenAuthentication:
			p = Token(c, a.errorReporter)
			a.setProvider(p)
		case types.PatAuthentication:
			p = Pat(c, a)
			a.setProvider(p)
		case types.FakeAuthentication:
			a.setProvider(NewFakeCliAuthenticationProvider(c))
		case "":
			// don't do anything
		}
	}
	// Check whether we have a valid token for the current auth method
	if c.NonEmptyToken() && !c.AuthenticationMethodMatchesCredentials() {
		a.logout(context.Background())
		if authMethodChanged {
			logger.Info().Msg("detected auth provider change, logging out and sending re-auth message")
			a.sendAuthenticationRequest(MethodChangedMessage, "Re-authenticate")
		} else {
			logger.Info().Msg("detected token change which is incompatible with auth provider.")
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
