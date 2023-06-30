/*
 * © 2022 Snyk Limited All rights reserved.
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

package server

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"

	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/handler"
	"github.com/rs/zerolog/log"
	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"golang.org/x/oauth2"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/domain/observability/ux"
	"github.com/snyk/snyk-ls/domain/snyk"
	auth2 "github.com/snyk/snyk-ls/infrastructure/cli/auth"
	"github.com/snyk/snyk-ls/infrastructure/oauth"
	"github.com/snyk/snyk-ls/internal/lsp"
)

const govDomain = "snykgov.io"

var cachedOriginalPath string = os.Getenv("PATH")

func workspaceDidChangeConfiguration(srv *jrpc2.Server) jrpc2.Handler {
	return handler.New(func(ctx context.Context, params lsp.DidChangeConfigurationParams) (bool, error) {
		log.Info().Str("method", "WorkspaceDidChangeConfiguration").Interface("params", params).Msg("RECEIVED")
		defer log.Info().Str("method", "WorkspaceDidChangeConfiguration").Interface("params", params).Msg("DONE")

		emptySettings := lsp.Settings{}
		if !reflect.DeepEqual(params.Settings, emptySettings) {
			// client used settings push
			UpdateSettings(params.Settings)
			return true, nil
		}

		// client expects settings pull. E.g. VS Code uses pull model & sends empty settings when configuration is updated.
		if !config.CurrentConfig().ClientCapabilities().Workspace.Configuration {
			log.Info().Msg("Pull model for workspace configuration not supported, ignoring workspace/didChangeConfiguration notification.")
			return false, nil
		}

		configRequestParams := lsp.ConfigurationParams{
			Items: []lsp.ConfigurationItem{
				{Section: "snyk"},
			},
		}
		res, err := srv.Callback(ctx, "workspace/configuration", configRequestParams)
		if err != nil {
			return false, err
		}

		var fetchedSettings []lsp.Settings
		err = res.UnmarshalResult(&fetchedSettings)
		if err != nil {
			return false, err
		}

		if !reflect.DeepEqual(fetchedSettings[0], emptySettings) {
			UpdateSettings(fetchedSettings[0])
			return true, nil
		}

		return false, nil
	})
}

func InitializeSettings(settings lsp.Settings) {
	writeSettings(settings, true)
	updateAutoAuthentication(settings)
	updateDeviceInformation(settings)
	updateAutoScan(settings)
}

func UpdateSettings(settings lsp.Settings) {
	currentConfig := config.CurrentConfig()
	previouslyEnabledProducts := currentConfig.DisplayableIssueTypes()
	previousAutoScan := currentConfig.IsAutoScanEnabled()

	writeSettings(settings, false)

	// If a product was removed, clear all issues for this product
	ws := workspace.Get()
	if ws != nil {
		newSupportedProducts := currentConfig.DisplayableIssueTypes()
		for removedIssueType, wasSupported := range previouslyEnabledProducts {
			if wasSupported && !newSupportedProducts[removedIssueType] {
				ws.ClearIssuesByType(removedIssueType)
			}
		}
	}

	if currentConfig.IsAutoScanEnabled() != previousAutoScan {
		di.Analytics().ScanModeIsSelected(ux.ScanModeIsSelectedProperties{ScanningMode: settings.ScanningMode})
	}
}

func writeSettings(settings lsp.Settings, initialize bool) {
	emptySettings := lsp.Settings{}
	if reflect.DeepEqual(settings, emptySettings) {
		return
	}
	updateSeverityFilter(settings.FilterSeverity)
	updateProductEnablement(settings)
	updateCliConfig(settings)

	// updateApiEndpoints overwrites the authentication method in certain cases (oauth2)
	// this is why it needs to be called after updateAuthenticationMethod
	updateAuthenticationMethod(settings)
	updateApiEndpoints(settings, initialize)

	// setting the token requires to know the authentication method
	updateToken(settings.Token)

	updateEnvironment(settings)
	updatePath(settings)
	updateTelemetry(settings)
	updateOrganization(settings)
	manageBinariesAutomatically(settings)
	updateTrustedFolders(settings)
	updateSnykCodeSecurity(settings)
	updateSnykCodeQuality(settings)
	updateRuntimeInfo(settings)
	updateAutoScan(settings)
	updateSnykLearnCodeActions(settings)
}

func updateAuthenticationMethod(settings lsp.Settings) {
	if settings.AuthenticationMethod == "" {
		return
	}
	c := config.CurrentConfig()
	c.SetAuthenticationMethod(settings.AuthenticationMethod)
	if config.CurrentConfig().AuthenticationMethod() == lsp.OAuthAuthentication {
		configureOAuth(c, auth.RefreshToken)
	} else {
		cliAuthenticationProvider := auth2.NewCliAuthenticationProvider(di.ErrorReporter())
		di.AuthenticationService().SetProvider(cliAuthenticationProvider)
	}
}

func credentialsUpdateCallback(_ string, value any) {
	newToken, ok := value.(string)
	if !ok {
		msg := fmt.Sprintf("Failed to cast token value of type %T to string", value)
		log.Error().Str("method", "storage callback token").
			Msgf(msg)
		di.ErrorReporter().CaptureError(errors.New(msg))
		return
	}
	go di.AuthenticationService().UpdateCredentials(newToken, true)
}

func configureOAuth(
	c *config.Config,
	customTokenRefresherFunc func(
		ctx context.Context,
		oauthConfig *oauth2.Config,
		token *oauth2.Token,
	) (*oauth2.Token, error),
) {
	engine := c.Engine()
	conf := engine.GetConfiguration()

	authenticationService := di.AuthenticationService()

	openBrowserFunc := func(url string) {
		authenticationService.Provider().SetAuthURL(url)
		snyk.DefaultOpenBrowserFunc(url)
	}
	conf.Set(configuration.FF_OAUTH_AUTH_FLOW_ENABLED, true)

	c.Storage().RegisterCallback(auth.CONFIG_KEY_OAUTH_TOKEN, credentialsUpdateCallback)

	authenticator := auth.NewOAuth2AuthenticatorWithOpts(
		conf,
		auth.WithOpenBrowserFunc(openBrowserFunc),
		auth.WithTokenRefresherFunc(customTokenRefresherFunc),
	)
	oAuthProvider := oauth.NewOAuthProvider(conf, authenticator)
	authenticationService.SetProvider(oAuthProvider)
}

func updateRuntimeInfo(settings lsp.Settings) {
	c := config.CurrentConfig()
	c.SetOsArch(settings.OsArch)
	c.SetOsPlatform(settings.OsPlatform)
	c.SetRuntimeVersion(settings.RuntimeVersion)
	c.SetRuntimeName(settings.RuntimeName)
}

func updateTrustedFolders(settings lsp.Settings) {
	trustedFoldersFeatureEnabled, err := strconv.ParseBool(settings.EnableTrustedFoldersFeature)
	if err == nil {
		config.CurrentConfig().SetTrustedFolderFeatureEnabled(trustedFoldersFeatureEnabled)
	} else {
		config.CurrentConfig().SetTrustedFolderFeatureEnabled(true)
	}

	if settings.TrustedFolders != nil {
		config.CurrentConfig().SetTrustedFolders(settings.TrustedFolders)
	}
}

func updateAutoAuthentication(settings lsp.Settings) {
	// Unless the field is included and set to false, auto-auth should be true by default.
	autoAuth, err := strconv.ParseBool(settings.AutomaticAuthentication)
	if err == nil {
		config.CurrentConfig().SetAutomaticAuthentication(autoAuth)
	} else {
		// When the field is omitted, set to true by default
		config.CurrentConfig().SetAutomaticAuthentication(true)
	}
}

func updateDeviceInformation(settings lsp.Settings) {
	deviceId := strings.TrimSpace(settings.DeviceId)
	if deviceId != "" {
		config.CurrentConfig().SetDeviceID(deviceId)
	}
}

func updateAutoScan(settings lsp.Settings) {
	// Auto scan true by default unless the AutoScan value in the settings is not missing & false
	autoScan := true
	if settings.ScanningMode == "manual" {
		autoScan = false
	}

	config.CurrentConfig().SetAutomaticScanning(autoScan)
}

func updateSnykLearnCodeActions(settings lsp.Settings) {
	enable := true
	if settings.EnableSnykLearnCodeActions == "false" {
		enable = false
	}

	config.CurrentConfig().SetSnykLearnCodeActionsEnabled(enable)
}

func updateToken(token string) {
	// Token was sent from the client, no need to send notification
	di.AuthenticationService().UpdateCredentials(token, false)
}

func updateApiEndpoints(settings lsp.Settings, initialization bool) {
	snykApiUrl := strings.Trim(settings.Endpoint, " ")
	c := config.CurrentConfig()
	endpointsUpdated := c.UpdateApiEndpoints(snykApiUrl)

	if endpointsUpdated && !initialization {
		di.AuthenticationService().Logout(context.Background())
		workspace.Get().ClearIssues(context.Background())
	}

	// overwrite authentication method if gov domain
	if strings.Contains(snykApiUrl, govDomain) {
		settings.AuthenticationMethod = lsp.OAuthAuthentication
		updateAuthenticationMethod(settings)
	}

	// a custom set snyk code api (e.g. for testing) always overwrites automatic config
	if settings.SnykCodeApi != "" {
		c.SetSnykCodeApi(settings.SnykCodeApi)
	}
}

func updateOrganization(settings lsp.Settings) {
	org := strings.TrimSpace(settings.Organization)
	if org != "" {
		config.CurrentConfig().SetOrganization(org)
	}
}

func updateTelemetry(settings lsp.Settings) {
	parseBool, err := strconv.ParseBool(settings.SendErrorReports)
	if err != nil {
		log.Debug().Msgf("couldn't read send error reports %s", settings.SendErrorReports)
	} else {
		config.CurrentConfig().SetErrorReportingEnabled(parseBool)
	}

	parseBool, err = strconv.ParseBool(settings.EnableTelemetry)
	if err != nil {
		log.Debug().Msgf("couldn't read enable telemetry %s", settings.SendErrorReports)
	} else {
		config.CurrentConfig().SetTelemetryEnabled(parseBool)
		if parseBool {
			go di.Analytics().Identify()
		}
	}
}

func manageBinariesAutomatically(settings lsp.Settings) {
	parseBool, err := strconv.ParseBool(settings.ManageBinariesAutomatically)
	if err != nil {
		log.Debug().Msgf("couldn't read manage binaries automatically %s", settings.ManageBinariesAutomatically)
	} else {
		config.CurrentConfig().SetManageBinariesAutomatically(parseBool)
	}
}

func updateSnykCodeSecurity(settings lsp.Settings) {
	parseBool, err := strconv.ParseBool(settings.ActivateSnykCodeSecurity)
	if err != nil {
		log.Debug().Msgf("couldn't read IsSnykCodeSecurityEnabled %s", settings.ActivateSnykCodeSecurity)
	} else {
		config.CurrentConfig().EnableSnykCodeSecurity(parseBool)
	}
}

func updateSnykCodeQuality(settings lsp.Settings) {
	parseBool, err := strconv.ParseBool(settings.ActivateSnykCodeQuality)
	if err != nil {
		log.Debug().Msgf("couldn't read IsSnykCodeQualityEnabled %s", settings.ActivateSnykCodeQuality)
	} else {
		config.CurrentConfig().EnableSnykCodeQuality(parseBool)
	}
}

// TODO store in config, move parsing to CLI
func updatePath(settings lsp.Settings) {
	err := os.Setenv("PATH", cachedOriginalPath+string(os.PathListSeparator)+settings.Path)
	if err != nil {
		log.Err(err).Msgf("couldn't add path %s", settings.Path)
	}
}

// TODO store in config, move parsing to CLI
func updateEnvironment(settings lsp.Settings) {
	envVars := strings.Split(settings.AdditionalEnv, ";")
	for _, envVar := range envVars {
		v := strings.Split(envVar, "=")
		if len(v) != 2 {
			continue
		}
		err := os.Setenv(v[0], v[1])
		if err != nil {
			log.Err(err).Msgf("couldn't set env variable %s", envVar)
		}
	}
}

func updateCliConfig(settings lsp.Settings) {
	var err error
	cliSettings := &config.CliSettings{}
	cliSettings.Insecure, err = strconv.ParseBool(settings.Insecure)
	if err != nil {
		log.Debug().Msg("couldn't parse insecure setting")
	}
	cliSettings.AdditionalOssParameters = strings.Split(settings.AdditionalParams, " ")
	cliSettings.SetPath(settings.CliPath)
	currentConfig := config.CurrentConfig()
	conf := currentConfig.Engine().GetConfiguration()
	conf.Set(configuration.INSECURE_HTTPS, cliSettings.Insecure)
	currentConfig.SetCliSettings(cliSettings)
}

func updateProductEnablement(settings lsp.Settings) {
	parseBool, err := strconv.ParseBool(settings.ActivateSnykCode)
	currentConfig := config.CurrentConfig()
	if err != nil {
		log.Debug().Msg("couldn't parse code setting")
	} else {
		currentConfig.SetSnykCodeEnabled(parseBool)
		currentConfig.EnableSnykCodeQuality(parseBool)
		currentConfig.EnableSnykCodeSecurity(parseBool)
	}
	parseBool, err = strconv.ParseBool(settings.ActivateSnykOpenSource)
	if err != nil {
		log.Debug().Msg("couldn't parse open source setting")
	} else {
		currentConfig.SetSnykOssEnabled(parseBool)
	}
	parseBool, err = strconv.ParseBool(settings.ActivateSnykIac)
	if err != nil {
		log.Debug().Msg("couldn't parse iac setting")
	} else {
		currentConfig.SetSnykIacEnabled(parseBool)
	}
}

func updateSeverityFilter(s lsp.SeverityFilter) {
	log.Debug().Str("method", "updateSeverityFilter").Msgf("Updating severity filter: %v", s)
	modified := config.CurrentConfig().SetSeverityFilter(s)

	if modified {
		ws := workspace.Get()
		if ws == nil {
			return
		}

		for _, folder := range ws.Folders() {
			folder.FilterAndPublishCachedDiagnostics("")
		}
	}
}
