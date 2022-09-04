package snyk

import "context"

type AuthenticationService interface {
	// Authenticate attempts to authenticate the user, and sends a notification to the client when successful
	Authenticate(ctx context.Context) (string, error)

	Provider() AuthenticationProvider

	// UpdateToken stores the token in the configuration, and sends a notification to the client if
	// sendNotification is true
	UpdateToken(newToken string, sendNotification bool)
}
