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
	"os"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/instrumentation"

	"github.com/erni27/imcache"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/analytics"
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

type AuthenticationServiceImpl struct {
	authProvider  AuthenticationProvider
	errorReporter error_reporting.ErrorReporter
	notifier      noti.Notifier
	c             *config.Config
	// key = token, value = isAuthenticated
	authCache *imcache.Cache[string, bool]
	m         sync.RWMutex
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

func (a *AuthenticationServiceImpl) Provider() AuthenticationProvider {
	a.m.RLock()
	defer a.m.RUnlock()

	return a.authProvider
}

func (a *AuthenticationServiceImpl) provider() AuthenticationProvider {
	return a.authProvider
}

func (a *AuthenticationServiceImpl) Authenticate(ctx context.Context) (token string, err error) {
	a.m.Lock()
	defer a.m.Unlock()

	return a.authenticate(ctx)
}

func (a *AuthenticationServiceImpl) authenticate(ctx context.Context) (token string, err error) {
	token, err = a.authProvider.Authenticate(ctx)

	if token == "" || err != nil {
		a.c.Logger().Warn().Err(err).Msgf("Failed to authenticate using auth provider %v", reflect.TypeOf(a.authProvider))
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
	}

	a.updateCredentials(token, true, shouldSendUrlUpdatedNotification)
	a.configureProviders(a.c)
	a.sendAuthenticationAnalytics(analytics.Success, nil)
	return token, err
}

func (a *AuthenticationServiceImpl) sendAuthenticationAnalytics(status analytics.Status, err error) {
	id, err2 := instrumentation.GetTargetId(os.Args[0], instrumentation.FilesystemTargetId)
	if err2 != nil {
		id = "pkg:filesystem/dummy/dummy"
	}
	event := types.AnalyticsEventParam{
		InteractionType: "authenticated",
		Category:        []string{"auth", string(a.c.AuthenticationMethod())},
		Status:          string(status),
		TargetId:        id,
		TimestampMs:     time.Now().UnixMilli(),
	}

	analytics2.SendAnalytics(a.c, event, err)
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
	// Fedramp and single tenenat environments.
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
	a.m.Lock()
	defer a.m.Unlock()

	a.logout(ctx)
}

func (a *AuthenticationServiceImpl) logout(ctx context.Context) {
	err := a.authProvider.ClearAuthentication(ctx)
	if err != nil {
		a.c.Logger().Warn().Err(err).Str("method", "Logout").Msg("Failed to log out.")
		a.errorReporter.CaptureError(err)
	}
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

	_, found := a.authCache.Get(a.c.Token())
	if found {
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
	// we cache the API auth ok for up to 1 minutes after last access. Afterwards, a new check is performed.
	a.authCache.Set(a.c.Token(), true, imcache.WithSlidingExpiration(time.Minute))
	logger.Debug().Msg("IsAuthenticated: " + user + ", adding to cache.")
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

	authProviderChange := false
	var p AuthenticationProvider
	switch c.AuthenticationMethod() {
	default:
		// if err != nil, previous token was legacy. So we had a provider change
		_, err := c.TokenAsOAuthToken()
		if c.NonEmptyToken() && err != nil {
			authProviderChange = true
		}

		p = Default(c, a)
		a.setProvider(p)
	case types.TokenAuthentication:
		// if err == nil, previous token was oauth2. So we had a provider change
		_, err := c.TokenAsOAuthToken()
		if c.NonEmptyToken() && err == nil {
			authProviderChange = true
		}

		p = Token(c, a.errorReporter)
		a.setProvider(p)
	case types.FakeAuthentication:
		a.setProvider(NewFakeCliAuthenticationProvider(c))
	case "":
		// don't do anything
	}

	if authProviderChange {
		logger.Info().Msg("detected auth provider change, logging out and sending re-auth message")
		a.logout(context.Background())
		a.sendAuthenticationRequest("Your authentication method has changed. Please re-authenticate to continue using Snyk.", "Re-authenticate")
	}
}

func (a *AuthenticationServiceImpl) handleInvalidCredentials() {
	msg := InvalidCredsMessage
	a.sendAuthenticationRequest(msg, "Authenticate")
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
