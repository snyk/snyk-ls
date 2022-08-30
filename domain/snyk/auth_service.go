package snyk

import "context"

type AuthenticationService interface {
	Provider() AuthenticationProvider
	UpdateToken(newToken string, sendNotification bool)
	Logout(ctx context.Context)
}
