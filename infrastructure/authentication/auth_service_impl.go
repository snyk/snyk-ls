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

	"github.com/snyk/go-application-framework/pkg/configuration"

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
	provider      AuthenticationProvider
	errorReporter error_reporting.ErrorReporter
	notifier      noti.Notifier
	c             *config.Config
	// key = token, value = isAuthenticated
	authCache *imcache.Cache[string, bool]
	m         sync.Mutex
}

func NewAuthenticationService(c *config.Config, authProviders AuthenticationProvider, errorReporter error_reporting.ErrorReporter, notifier noti.Notifier) AuthenticationService {
	cache := imcache.New[string, bool]()
	return &AuthenticationServiceImpl{
		provider:      authProviders,
		errorReporter: errorReporter,
		notifier:      notifier,
		c:             c,
		authCache:     cache,
	}
}

func (a *AuthenticationServiceImpl) Provider() AuthenticationProvider {
	return a.provider
}

func (a *AuthenticationServiceImpl) Authenticate(ctx context.Context) (token string, err error) {
	token, err = a.provider.Authenticate(ctx)

	if token == "" || err != nil {
		a.c.Logger().Warn().Err(err).Msgf("Failed to authenticate using auth provider %v", reflect.TypeOf(a.provider))
		a.sendAuthenticationAnalytics(analytics.Failure, err)
		return token, err
	}

	customUrl := a.c.SnykApi()
	engineUrl := a.c.Engine().GetConfiguration().GetString(configuration.API_URL)
	prioritizedUrl := getPrioritizedApiUrl(customUrl, engineUrl)

	if prioritizedUrl != customUrl {
		defer a.notifier.SendShowMessage(sglsp.Info, "The Snyk API Endpoint has been updated.")
	}

	a.c.UpdateApiEndpoints(prioritizedUrl)
	a.UpdateCredentials(token, true)
	a.ConfigureProviders(a.c)
	a.sendAuthenticationAnalytics(analytics.Success, nil)
	return token, err
}

func (a *AuthenticationServiceImpl) sendAuthenticationAnalytics(status analytics.Status, err error) {
	logger := a.c.Logger().With().Str("method", "sendAuthenticationAnalytics").Logger()
	event := types.AnalyticsEventParam{
		InteractionType: "authenticated",
		Category:        []string{"auth", string(a.c.AuthenticationMethod())},
		Status:          string(status),
	}

	ic := analytics2.PayloadForAnalyticsEventParam(a.c, event)

	if err != nil {
		ic.AddError(err)
	}

	analyticsRequestBody, err := analytics.GetV2InstrumentationObject(ic)
	if err != nil {
		logger.Err(err).Msg("Failed to get analytics request body")
		return
	}

	bytes, err := json.Marshal(analyticsRequestBody)
	if err != nil {
		logger.Err(err).Msg("Failed to marshal analytics request body")
		return
	}

	err = analytics2.SendAnalyticsToAPI(a.c, bytes)
	if err != nil {
		logger.Err(err).Msg("Failed to send analytics")
	}
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

func (a *AuthenticationServiceImpl) UpdateCredentials(newToken string, sendNotification bool) {
	c := config.CurrentConfig()
	oldToken := c.Token()
	if oldToken == newToken {
		return
	}

	// unlock when leaving if we locked ourselves
	if a.m.TryLock() {
		defer a.m.Unlock()
	}

	// remove old token from cache, but don't add new token, as we want the entry only when
	// checks are performed - e.g. in IsAuthenticated or Authenticate which call the API to check for real
	a.authCache.Remove(oldToken)
	c.SetToken(newToken)

	if sendNotification {
		a.c.Logger().Debug().Str("method", "UpdateCredentials").Str(
			"Sending Url %s",
			a.c.SnykApi(),
		)
		a.notifier.Send(types.AuthenticationParams{Token: newToken, ApiUrl: a.c.SnykApi()})
	}
}

func (a *AuthenticationServiceImpl) Logout(ctx context.Context) {
	if a.m.TryLock() {
		defer a.m.Unlock()
	}
	err := a.provider.ClearAuthentication(ctx)
	if err != nil {
		a.c.Logger().Warn().Err(err).Str("method", "Logout").Msg("Failed to log out.")
		a.errorReporter.CaptureError(err)
	}
	a.UpdateCredentials("", true)
	a.ConfigureProviders(a.c)
}

// IsAuthenticated returns true if the token is verified
// If the token is set, but not valid IsAuthenticated returns false
func (a *AuthenticationServiceImpl) IsAuthenticated() bool {
	logger := a.c.Logger().With().Str("method", "AuthenticationService.IsAuthenticated").Logger()
	if a.m.TryLock() {
		defer a.m.Unlock()
	}

	_, found := a.authCache.Get(a.c.Token())
	if found {
		a.c.Logger().Debug().Msg("IsAuthenticated (found in cache)")
		return true
	}

	noToken := !a.c.NonEmptyToken()
	if noToken {
		logger.Info().Str("method", "IsAuthenticated").Msg("no credentials found")
		return false
	}

	if a.provider == nil {
		a.ConfigureProviders(a.c)
	}

	var user string
	var err error
	user, err = a.provider.GetCheckAuthenticationFunction()()
	if user == "" {
		if a.c.Offline() || (err != nil && !shouldCauseLogout(err, a.c.Logger())) {
			userMsg := fmt.Sprintf("Could not retrieve authentication status. Most likely this is a temporary error "+
				"caused by connectivity problems. If this message does not go away, please log out and re-authenticate (%s)", err.Error())
			a.notifier.SendShowMessage(sglsp.MTError, userMsg)
			a.c.Logger().Info().Msg("not logging out, as we had an error, but returning not authenticated to caller")
			return false
		}

		invalidOAuth2Token, isLegacyTokenErr := a.c.TokenAsOAuthToken()
		isLegacyToken := isLegacyTokenErr != nil

		a.handleEmptyUser(logger, isLegacyToken, invalidOAuth2Token)
		return false
	}
	// we cache the API auth ok for up to 1 minutes after last access. Afterwards, a new check is performed.
	a.authCache.Set(a.c.Token(), true, imcache.WithSlidingExpiration(time.Minute))
	a.c.Logger().Debug().Msg("IsAuthenticated: " + user + ", adding to cache.")
	return true
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

		default:
			return false
		}
	}
}

func (a *AuthenticationServiceImpl) handleEmptyUser(logger zerolog.Logger, isLegacyToken bool, invalidToken oauth2.Token) {
	logger.Info().Msg("could not authenticate user with current credentials, API returned empty user object")
	logger.Info().Msg("logging out, empty user response")
	a.Logout(context.Background())

	// determine the right error message
	if !isLegacyToken {
		// it is an oauth token
		if invalidToken.Expiry.Before(time.Now()) {
			a.handleFailedRefresh()
		} else {
			// access token not expired, but creds still not work
			a.HandleInvalidCredentials()
		}
	} else {
		// legacy token does not work
		a.HandleInvalidCredentials()
	}
}

func (a *AuthenticationServiceImpl) handleFailedRefresh() {
	// access token expired and refresh failed
	a.sendAuthenticationRequest(ExpirationMsg, "Re-authenticate")
}

func (a *AuthenticationServiceImpl) SetProvider(provider AuthenticationProvider) {
	a.provider = provider
}

func (a *AuthenticationServiceImpl) ConfigureProviders(c *config.Config) {
	if a.m.TryLock() {
		defer a.m.Unlock()
	}
	authProviderChange := false
	var p AuthenticationProvider
	switch c.AuthenticationMethod() {
	default:
		// if err != nil, previous token was legacy. So we had a provider change
		_, err := c.TokenAsOAuthToken()
		if err != nil && c.NonEmptyToken() {
			authProviderChange = true
		}

		p = Default(c, a)
		a.SetProvider(p)
	case types.TokenAuthentication:
		// if err == nil, previous token was oauth2. So we had a provider change
		_, err := c.TokenAsOAuthToken()
		if err == nil && c.NonEmptyToken() {
			authProviderChange = true
		}

		p = Token(c, a.errorReporter)
		a.SetProvider(p)
	case types.FakeAuthentication:
		a.SetProvider(NewFakeCliAuthenticationProvider(c))
	case "":
		// don't do anything
	}

	if authProviderChange {
		a.Logout(context.Background())
		a.sendAuthenticationRequest("Your authentication method has changed. Please re-authenticate to continue using Snyk.", "Re-authenticate")
	}
}

func (a *AuthenticationServiceImpl) HandleInvalidCredentials() {
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
