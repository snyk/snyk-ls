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
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"sync"
	"syscall"
	"time"

	"github.com/erni27/imcache"
	"github.com/rs/zerolog"
	"golang.org/x/oauth2"

	"github.com/snyk/snyk-ls/application/config"
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
		return token, err
	}
	a.UpdateCredentials(token, true)
	return token, err
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
		a.notifier.Send(types.AuthenticationParams{Token: newToken})
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

	var user string
	var err error

	user, err = a.provider.GetCheckAuthenticationFunction()()
	if user == "" || err != nil {
		a.c.Logger().
			Err(err).
			Str("method", "AuthenticationService.IsAuthenticated").
			Msg("Failed to get active user")

		invalidToken, isLegacyTokenErr := a.c.TokenAsOAuthToken()

		if logoutCausingError(err) {
			a.handleLogoutCausingError(logger, isLegacyTokenErr, invalidToken)
			return false
		} else {
			// try again
			time.Sleep(2 * time.Second)
			retryUser, retryError := a.provider.GetCheckAuthenticationFunction()()
			if retryUser == "" || retryError != nil {
				// retry failed again, we gotta logout after all
				a.handleLogoutCausingError(logger, isLegacyTokenErr, invalidToken)
				return false
			}
		}
	}
	// we cache the API auth ok for up to 1 minutes after last access. Afterwards, a new check is performed.
	a.authCache.Set(a.c.Token(), true, imcache.WithSlidingExpiration(time.Minute))
	a.c.Logger().Debug().Msg("IsAuthenticated: " + user + ", adding to cache.")
	return true
}

func (a *AuthenticationServiceImpl) handleLogoutCausingError(logger zerolog.Logger, isLegacyTokenErr error, invalidToken oauth2.Token) {
	logger.Debug().Msg("logging out")
	a.Logout(context.Background())

	// determine the right error message
	if isLegacyTokenErr == nil {
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

func logoutCausingError(err error) bool {
	if err == nil {
		return true
	}

	// Check for context cancellation
	if errors.Is(err, context.Canceled) {
		return false
	}

	// Check for timeout errors
	if errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	// Check for URL errors
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return false
	}

	// Check for network operation errors
	var netErr *net.OpError
	if errors.As(err, &netErr) {
		return false
	}

	// Check for DNS errors
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return false
	}

	// Check for system call errors
	var sysCallErr *os.SyscallError
	if errors.As(err, &sysCallErr) {
		return false
	}

	// Check for connection reset error
	if errors.Is(err, syscall.ECONNRESET) {
		return false
	}

	// Check for EOF error
	if errors.Is(err, io.EOF) {
		return false
	}

	// as we can't enforce correct error reporting, let's do a final check on the internet connection, whether it's there
	_, err = http.Get("https://www.google.com")
	return err == nil
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
