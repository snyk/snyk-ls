package snyk

type AuthenticationService interface {
	Provider() AuthenticationProvider
	UpdateToken(newToken string, sendNotification bool)
}
