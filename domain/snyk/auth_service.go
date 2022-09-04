package snyk

import "context"

type AuthenticationService interface {
	Authenticate(ctx context.Context) (string, error)
	Provider() AuthenticationProvider
	UpdateToken(newToken string, sendNotification bool)
}
