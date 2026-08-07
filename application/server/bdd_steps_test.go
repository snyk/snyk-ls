package server

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/creachadair/jrpc2/server"
	"github.com/cucumber/godog"
	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/domain/ide/command"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/domain/scanstates"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/domain/snyk/persistence"
	"github.com/snyk/snyk-ls/domain/snyk/scanner"
	"github.com/snyk/snyk-ls/infrastructure/authentication"
	"github.com/snyk/snyk-ls/infrastructure/code"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testsupport"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/uri"
)

// bddSteps is the step registry for every .feature file, created fresh per
// scenario so no state leaks across scenarios. Steps drive the real language
// server through the existing test harness rather than a new one; step
// bodies reach scenarioT only via runOnScenarioGoroutine (see below).
type bddSteps struct {
	t *testing.T // suite-level T, used only to spawn per-scenario subtests

	scenarioT    *testing.T
	scenarioDone chan struct{}
	scenarioDied chan struct{}
	stepFunc     chan func() error
	stepResult   chan error

	engine              workflow.Engine
	loc                 server.Local
	jsonRPCRecorder     *testsupport.JsonRPCRecorder
	scanPersister       persistence.ScanSnapshotPersister
	scanStateAggregator scanstates.Aggregator

	initResult  types.InitializeResult
	initialized bool
	dialogHTML  string
	folderPath  types.FilePath

	deltaFileDir     types.FilePath
	deltaFilePath    types.FilePath
	deltaOssFilePath types.FilePath
	lastDiagnostics  []types.Diagnostic
	lastTreeViewHTML string
}

func newBDDSteps(t *testing.T) *bddSteps {
	t.Helper()
	return &bddSteps{t: t}
}

func (s *bddSteps) register(sc *godog.ScenarioContext) {
	sc.Before(s.beforeScenario)
	sc.After(s.afterScenario)
	sc.Given(`^a running language server$`, func() error {
		return s.runOnScenarioGoroutine(s.aRunningLanguageServer)
	})
	// Step, not When: this step is reused as "And" (inheriting Given) in the
	// delta-fail-open scenarios, and Given/When/Then in godog match only their
	// own keyword - "And"/"But" copy the preceding step's keyword.
	sc.Step(`^the editor sends the initialize request$`, func(ctx context.Context) error {
		return s.runOnScenarioGoroutine(func() error { return s.theEditorSendsTheInitializeRequest(ctx) })
	})
	sc.Then(`^the server responds with its capabilities$`, func() error {
		return s.runOnScenarioGoroutine(s.theServerRespondsWithItsCapabilities)
	})
	sc.Given(`^delta findings are enabled for the workspace$`, func() error {
		return s.runOnScenarioGoroutine(s.deltaFindingsAreEnabled)
	})
	// Step, not Given: used as "When" in one scenario and "And" (inheriting
	// Given) in others - see the keyword note above.
	sc.Step(`^(?:the developer has saved|the developer saves) a file with a security issue for the first time$`, func() error {
		return s.runOnScenarioGoroutine(s.developerSavesFileWithSecurityIssue)
	})
	sc.Then(`^the editor is notified of the security issue$`, func() error {
		return s.runOnScenarioGoroutine(s.editorIsNotifiedOfTheSecurityIssue)
	})
	sc.When(`^the editor asks for diagnostics for the whole workspace$`, func(ctx context.Context) error {
		return s.runOnScenarioGoroutine(func() error { return s.editorAsksForWorkspaceDiagnostics(ctx) })
	})
	sc.When(`^the editor asks for diagnostics for that file$`, func(ctx context.Context) error {
		return s.runOnScenarioGoroutine(func() error { return s.editorAsksForFileDiagnostics(ctx) })
	})
	sc.Then(`^the editor is told about the security issue$`, func() error {
		return s.runOnScenarioGoroutine(s.editorIsToldAboutTheSecurityIssue)
	})
	sc.When(`^the editor asks for the issue tree view$`, func(ctx context.Context) error {
		return s.runOnScenarioGoroutine(func() error { return s.editorAsksForTheIssueTreeView(ctx) })
	})
	sc.Then(`^the issue tree view shows the security issue$`, func(ctx context.Context) error {
		return s.runOnScenarioGoroutine(func() error { return s.issueTreeViewShowsTheSecurityIssue(ctx) })
	})
	sc.Given(`^the developer has an established baseline (?:with|for one product with) one known issue$`, func() error {
		return s.runOnScenarioGoroutine(s.developerHasEstablishedBaseline)
	})
	sc.When(`^the developer saves a file that introduces a new issue alongside the known one$`, func() error {
		return s.runOnScenarioGoroutine(s.developerSavesFileWithNewIssueAlongsideKnown)
	})
	sc.Then(`^the editor is notified of only the newly introduced issue$`, func() error {
		return s.runOnScenarioGoroutine(s.editorNotifiedOfOnlyNewIssue)
	})
	sc.When(`^the developer saves a file that produces a new issue in that product and an issue in a product without a baseline$`, func() error {
		return s.runOnScenarioGoroutine(s.developerSavesFileWithMixedProductIssues)
	})
	sc.Then(`^the editor is notified of the newly introduced issue and of the issue from the product without a baseline$`, func() error {
		return s.runOnScenarioGoroutine(s.editorNotifiedOfNewAndUnbaselinedIssues)
	})
	sc.Given(`^a workspace folder is open$`, func() error {
		return s.runOnScenarioGoroutine(s.aWorkspaceFolderIsOpen)
	})
	sc.Then(`^the folder has no Ambient Canary autonomy override$`, func() error {
		return s.runOnScenarioGoroutine(s.theFolderHasNoAmbientCanaryAutonomyOverride)
	})
	sc.When(`^the editor sets the folder's Ambient Canary autonomy to "([^"]*)"$`, func(ctx context.Context, autonomy string) error {
		return s.runOnScenarioGoroutine(func() error { return s.theEditorSetsTheFoldersAmbientCanaryAutonomyTo(ctx, autonomy) })
	})
	sc.Then(`^the folder's effective Ambient Canary autonomy is "([^"]*)"$`, func(autonomy string) error {
		return s.runOnScenarioGoroutine(func() error { return s.theFoldersEffectiveAmbientCanaryAutonomyIs(autonomy) })
	})
	sc.When(`^a developer saves "([^"]*)" as the LLM provider with custom API endpoint "([^"]*)"$`, func(ctx context.Context, provider, endpoint string) error {
		return s.runOnScenarioGoroutine(func() error { return s.aDeveloperSavesTheLlmProviderAndEndpoint(ctx, provider, endpoint) })
	})
	sc.When(`^a developer saves "([^"]*)" as the LLM provider with model "([^"]*)"$`, func(ctx context.Context, provider, model string) error {
		return s.runOnScenarioGoroutine(func() error { return s.aDeveloperSavesTheLlmProviderAndModel(ctx, provider, model) })
	})
	sc.When(`^the developer reopens the Snyk configuration dialog$`, func(ctx context.Context) error {
		return s.runOnScenarioGoroutine(func() error { return s.theDeveloperReopensTheConfigurationDialog(ctx) })
	})
	sc.When(`^a developer reopens the Snyk configuration dialog$`, func(ctx context.Context) error {
		return s.runOnScenarioGoroutine(func() error { return s.theDeveloperReopensTheConfigurationDialog(ctx) })
	})
	sc.When(`^a developer reopens the Snyk configuration dialog without ever choosing an LLM provider$`, func(ctx context.Context) error {
		return s.runOnScenarioGoroutine(func() error { return s.theDeveloperReopensTheConfigurationDialog(ctx) })
	})
	sc.Then(`^the configuration dialog shows "([^"]*)" as the selected LLM provider$`, func(provider string) error {
		return s.runOnScenarioGoroutine(func() error { return s.theDialogShowsTheSelectedLlmProvider(provider) })
	})
	sc.Then(`^the configuration dialog shows "([^"]*)" as the custom API endpoint$`, func(endpoint string) error {
		return s.runOnScenarioGoroutine(func() error { return s.theDialogShowsTheCustomApiEndpoint(endpoint) })
	})
	sc.Then(`^the configuration dialog shows "([^"]*)" as the selected LLM model$`, func(model string) error {
		return s.runOnScenarioGoroutine(func() error { return s.theDialogShowsTheSelectedLlmModel(model) })
	})
	sc.Then(`^the configuration dialog shows no LLM provider selected$`, func() error {
		return s.runOnScenarioGoroutine(s.theDialogShowsNoLlmProviderSelected)
	})
	sc.Then(`^the configuration dialog contains no field for an LLM API key$`, func() error {
		return s.runOnScenarioGoroutine(s.theDialogContainsNoLlmApiKeyField)
	})
}

// beforeScenario runs the scenario as a subtest of the suite-level T so
// t.Cleanup (e.g. setupServer's) fires per scenario, not once at TestBDD's end.
func (s *bddSteps) beforeScenario(ctx context.Context, sc *godog.Scenario) (context.Context, error) {
	ready := make(chan struct{})
	s.scenarioDone = make(chan struct{})
	s.scenarioDied = make(chan struct{})
	s.stepFunc = make(chan func() error)
	s.stepResult = make(chan error)

	go func() {
		defer close(s.scenarioDied)
		s.t.Run(sc.Name, func(subT *testing.T) {
			s.scenarioT = subT
			close(ready)
			for {
				select {
				case fn := <-s.stepFunc:
					s.runStep(fn)
				case <-s.scenarioDone:
					return
				}
			}
		})
	}()
	<-ready
	return ctx, nil
}

func (s *bddSteps) afterScenario(ctx context.Context, sc *godog.Scenario, err error) (context.Context, error) {
	close(s.scenarioDone)
	<-s.scenarioDied
	return ctx, err
}

// reported stops a double-send when fn returns normally instead of exiting
// via Goexit; the same defer also recovers a panic from fn, so every path -
// return, Goexit, panic - sends exactly once, and a panicking step fails
// only its own scenario instead of crashing TestBDD.
//
// runStep also calls s.scenarioT.Fail() on a step error or panic: without
// it, only godog's own goroutine learns of the failure, so the
// per-scenario subtest would report a false PASS in isolation. Fail (not
// FailNow) is safe here since it doesn't call runtime.Goexit.
func (s *bddSteps) runStep(fn func() error) {
	reported := false
	defer func() {
		if r := recover(); r != nil {
			if s.scenarioT != nil {
				s.scenarioT.Fail()
			}
			s.stepResult <- fmt.Errorf("step panicked: %v\n%s", r, debug.Stack())
			return
		}
		if !reported {
			s.stepResult <- fmt.Errorf("step aborted: scenario T.Fatal/FailNow was called")
		}
	}()
	err := fn()
	reported = true
	if err != nil && s.scenarioT != nil {
		s.scenarioT.Fail()
	}
	s.stepResult <- err
}

// runOnScenarioGoroutine hands fn to the scenario's own goroutine and blocks
// for its result. Step definitions must go through this instead of running
// directly on godog's goroutine: helpers like testutil.UnitTestWithEngine and
// setupServer take scenarioT and may call t.Fatal/FailNow, whose
// runtime.Goexit only unwinds the calling goroutine - calling it from
// godog's goroutine would hang the scenario instead of failing it.
func (s *bddSteps) runOnScenarioGoroutine(fn func() error) error {
	select {
	case s.stepFunc <- fn:
	case <-s.scenarioDied:
		return errors.New("scenario goroutine died before it could receive the step")
	}

	select {
	case err := <-s.stepResult:
		return err
	case <-s.scenarioDied:
		return errors.New("scenario goroutine died before it could report the step's result")
	}
}

func (s *bddSteps) aRunningLanguageServer() error {
	engine, tokenService := testutil.UnitTestWithEngine(s.scenarioT)
	// A real GitPersistenceProvider (rather than the NopScanPersister default) so
	// baseline-availability scenarios can exercise ErrBaselineDoesntExist and Add()
	// for real, instead of the no-op persister's trivial always-succeeds behavior.
	s.scanPersister = persistence.NewGitPersistenceProvider(engine.GetLogger(), engine.GetConfiguration())

	// di.TestInit defaults to a NoopStateAggregator, so the real scan pipeline's
	// SetScanInProgress/SetScanDone calls (which gate tree-view rendering) go
	// nowhere. Build a real one - wired with a NoopEmitter so it tracks state
	// without pushing extra notifications the other scenarios don't expect.
	resolver, err := s.newConfigResolver(engine)
	if err != nil {
		return err
	}
	realScanStateAggregator := scanstates.NewScanStateAggregator(engine.GetConfiguration(), engine.GetLogger(), &scanstates.NoopEmitter{}, resolver, engine)

	loc, jsonRPCRecorder, deps := setupServer(s.scenarioT, engine, tokenService, WithDeps(di.Dependencies{
		ScanPersister:       s.scanPersister,
		ConfigResolver:      resolver,
		ScanStateAggregator: realScanStateAggregator,
	}))
	s.engine = engine
	s.loc = loc
	s.jsonRPCRecorder = jsonRPCRecorder
	s.scanStateAggregator = realScanStateAggregator

	// di.TestInit unconditionally installs a CommandServiceMock, which returns
	// (nil, nil) for every command - so workspace/executeCommand(snyk.getTreeView)
	// never reaches the real getTreeViewCommand. Swap in the real service, now that
	// deps (and the workspace registered via config.SetWorkspace) are available.
	issueProvider, ok := config.GetWorkspace(engine.GetConfiguration()).(snyk.IssueProvider)
	if !ok {
		return fmt.Errorf("workspace does not implement snyk.IssueProvider")
	}
	command.SetService(command.NewService(
		engine, engine.GetLogger(), deps.AuthenticationService, deps.FeatureFlagService, deps.Notifier,
		deps.LearnService, issueProvider, nil, nil, deps.LdxSyncService,
		deps.ConfigResolver, deps.ScanStateAggregator.StateSnapshot, nil,
	))

	// Scenarios that save a file through the real didSave pipeline (as opposed to
	// the fake-scanner scenarios, which build a Folder directly) need Snyk Code
	// scanning enabled and an authenticated user, or the scan never runs.
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), true)
	di.AuthenticationService().Provider().(*authentication.FakeAuthenticationProvider).IsAuthenticated = true
	return nil
}

// newConfigResolver mirrors di.TestInit's own resolver construction so the
// ScanStateAggregator built here resolves per-folder settings (e.g. product
// enablement) the same way production code does - a resolver without a
// prefixKeyResolver falls back to schema defaults, ignoring global settings
// set via configresolver.UserGlobalKey.
func (s *bddSteps) newConfigResolver(engine workflow.Engine) (*types.ConfigResolver, error) {
	fs := pflag.NewFlagSet("bdd-delta-fail-open-config", pflag.ContinueOnError)
	types.RegisterAllConfigurations(fs)
	if err := engine.GetConfiguration().AddFlagSet(fs); err != nil {
		return nil, fmt.Errorf("adding flag set failed: %w", err)
	}
	fm := workflow.ConfigurationOptionsFromFlagset(fs)
	resolver := types.NewConfigResolver(engine.GetLogger())
	prefixKeyResolver := configresolver.New(engine.GetConfiguration(), fm)
	resolver.SetPrefixKeyResolver(prefixKeyResolver, engine.GetConfiguration(), fm)
	return resolver, nil
}

func (s *bddSteps) theEditorSendsTheInitializeRequest(ctx context.Context) error {
	rsp, err := s.loc.Client.Call(ctx, "initialize", nil)
	if err != nil {
		return fmt.Errorf("initialize call failed: %w", err)
	}
	if err := rsp.UnmarshalResult(&s.initResult); err != nil {
		return fmt.Errorf("unmarshalling initialize result failed: %w", err)
	}
	s.engine.GetConfiguration().Set(types.SettingIsLspInitialized, true)
	return nil
}

func (s *bddSteps) theServerRespondsWithItsCapabilities() error {
	if s.initResult.ServerInfo.Name != config.LsServerName {
		return fmt.Errorf("expected server info name %q, got %q", config.LsServerName, s.initResult.ServerInfo.Name)
	}
	if s.initResult.ServerInfo.Version != config.LsProtocolVersion {
		return fmt.Errorf("expected protocol version %q, got %q", config.LsProtocolVersion, s.initResult.ServerInfo.Version)
	}
	if s.initResult.Capabilities.TextDocumentSync == nil {
		return fmt.Errorf("expected capabilities to be populated, got a zero value")
	}
	return nil
}

// ensureLspInitialized calls the "initialize" request exactly once per
// scenario, ahead of the first real settings/dialog call. Both
// workspace/didChangeConfiguration and workspace/executeCommand are only
// meaningful after the LSP initialize handshake, mirroring how a real editor
// drives the protocol.
func (s *bddSteps) ensureLspInitialized(ctx context.Context) error {
	if s.initialized {
		return nil
	}
	if _, err := s.loc.Client.Call(ctx, "initialize", types.InitializeParams{}); err != nil {
		return fmt.Errorf("initialize call failed: %w", err)
	}
	s.initialized = true
	return nil
}

// aDeveloperSavesTheLlmProviderAndEndpoint drives the real
// workspace/didChangeConfiguration request an editor sends when a developer
// changes and saves settings in the configuration dialog.
func (s *bddSteps) aDeveloperSavesTheLlmProviderAndEndpoint(ctx context.Context, provider, endpoint string) error {
	if err := s.ensureLspInitialized(ctx); err != nil {
		return err
	}
	params := types.DidChangeConfigurationParams{
		Settings: types.LspConfigurationParam{
			Settings: map[string]*types.ConfigSetting{
				types.SettingLlmProvider: {Value: provider, Changed: true},
				types.SettingLlmBaseUrl:  {Value: endpoint, Changed: true},
			},
		},
	}
	if _, err := s.loc.Client.Call(ctx, "workspace/didChangeConfiguration", params); err != nil {
		return fmt.Errorf("workspace/didChangeConfiguration call failed: %w", err)
	}
	return nil
}

// aDeveloperSavesTheLlmProviderAndModel drives the real
// workspace/didChangeConfiguration request for a provider (e.g. ollama,
// litellm) that remy-cli-extension requires an explicit model for.
func (s *bddSteps) aDeveloperSavesTheLlmProviderAndModel(ctx context.Context, provider, model string) error {
	if err := s.ensureLspInitialized(ctx); err != nil {
		return err
	}
	params := types.DidChangeConfigurationParams{
		Settings: types.LspConfigurationParam{
			Settings: map[string]*types.ConfigSetting{
				types.SettingLlmProvider: {Value: provider, Changed: true},
				types.SettingLlmModel:    {Value: model, Changed: true},
			},
		},
	}
	if _, err := s.loc.Client.Call(ctx, "workspace/didChangeConfiguration", params); err != nil {
		return fmt.Errorf("workspace/didChangeConfiguration call failed: %w", err)
	}
	return nil
}

// theDeveloperReopensTheConfigurationDialog drives the real
// workspace/executeCommand request the menubar sends to render the
// configuration dialog, and stashes the returned HTML for the Then steps.
func (s *bddSteps) theDeveloperReopensTheConfigurationDialog(ctx context.Context) error {
	if err := s.ensureLspInitialized(ctx); err != nil {
		return err
	}
	response, err := s.loc.Client.Call(ctx, "workspace/executeCommand", sglsp.ExecuteCommandParams{
		Command:   types.WorkspaceConfigurationCommand,
		Arguments: []any{},
	})
	if err != nil {
		return fmt.Errorf("workspace/executeCommand call failed: %w", err)
	}
	var html string
	if err := response.UnmarshalResult(&html); err != nil {
		return fmt.Errorf("unmarshalling configuration dialog result failed: %w", err)
	}
	if html == "" {
		return fmt.Errorf("expected non-empty configuration dialog HTML")
	}
	s.dialogHTML = html
	return nil
}

func (s *bddSteps) theDialogShowsTheSelectedLlmProvider(provider string) error {
	needle := `id="llm_provider"`
	idx := strings.Index(s.dialogHTML, needle)
	if idx == -1 {
		return fmt.Errorf("expected an llm_provider field in the configuration dialog HTML")
	}
	// The selected <option> for the chosen provider must carry "selected" within
	// the llm_provider <select> element.
	selectEnd := strings.Index(s.dialogHTML[idx:], "</select>")
	if selectEnd == -1 {
		return fmt.Errorf("expected a closing </select> for the llm_provider field")
	}
	selectHTML := s.dialogHTML[idx : idx+selectEnd]
	optionNeedle := fmt.Sprintf(`value="%s" selected`, provider)
	if !strings.Contains(selectHTML, optionNeedle) {
		return fmt.Errorf("expected provider %q to be selected in the llm_provider field, got: %s", provider, selectHTML)
	}
	return nil
}

func (s *bddSteps) theDialogShowsTheCustomApiEndpoint(endpoint string) error {
	if !strings.Contains(s.dialogHTML, endpoint) {
		return fmt.Errorf("expected custom API endpoint %q to be shown in the configuration dialog HTML", endpoint)
	}
	return nil
}

func (s *bddSteps) theDialogShowsTheSelectedLlmModel(model string) error {
	if !strings.Contains(s.dialogHTML, model) {
		return fmt.Errorf("expected model %q to be shown in the configuration dialog HTML", model)
	}
	return nil
}

func (s *bddSteps) theDialogShowsNoLlmProviderSelected() error {
	needle := `id="llm_provider"`
	idx := strings.Index(s.dialogHTML, needle)
	if idx == -1 {
		return fmt.Errorf("expected an llm_provider field in the configuration dialog HTML")
	}
	selectEnd := strings.Index(s.dialogHTML[idx:], "</select>")
	if selectEnd == -1 {
		return fmt.Errorf("expected a closing </select> for the llm_provider field")
	}
	selectHTML := s.dialogHTML[idx : idx+selectEnd]
	if !strings.Contains(selectHTML, `value="" selected`) {
		return fmt.Errorf("expected no provider (the empty \"Automatic\" option) to be selected, got: %s", selectHTML)
	}
	return nil
}

func (s *bddSteps) theDialogContainsNoLlmApiKeyField() error {
	if strings.Contains(strings.ToLower(s.dialogHTML), "llm_api_key") {
		return fmt.Errorf("configuration dialog must never contain an LLM API key field")
	}
	return nil
}

func (s *bddSteps) aWorkspaceFolderIsOpen() error {
	folderPath := types.FilePath(s.scenarioT.TempDir())
	initParams := types.InitializeParams{
		WorkspaceFolders: []types.WorkspaceFolder{
			{Uri: uri.PathToUri(folderPath), Name: "bdd-folder"},
		},
	}
	if _, err := s.loc.Client.Call(s.scenarioT.Context(), "initialize", initParams); err != nil {
		return fmt.Errorf("initialize call failed: %w", err)
	}

	disableAutoScan(s.scenarioT, s.engine.GetConfiguration())

	if _, err := s.loc.Client.Call(s.scenarioT.Context(), "initialized", types.InitializedParams{}); err != nil {
		return fmt.Errorf("initialized call failed: %w", err)
	}
	types.WaitForLspInitialized(s.engine.GetConfiguration())

	s.folderPath = folderPath
	return nil
}

// waitForFolderConfigNotification polls $/snyk.configuration notifications
// (didChangeConfiguration processing runs in the background) until one
// carrying this scenario's folder satisfies match. Notifications are
// delivered to the test's jrpc2 client on a goroutine per received message,
// so two notifications sent moments apart are not guaranteed to be recorded
// in send order; scanning for a match rather than trusting the recorder's
// last entry keeps the wait correct regardless of that delivery order.
func (s *bddSteps) waitForFolderConfigNotification(match func(types.LspFolderConfig) bool) (types.LspFolderConfig, error) {
	deadline := time.Now().Add(5 * time.Second)
	var lastSeen types.LspFolderConfig
	sawFolder := false
	for {
		notifications := s.jsonRPCRecorder.FindNotificationsByMethod("$/snyk.configuration")
		for _, notification := range notifications {
			var param types.LspConfigurationParam
			if err := notification.UnmarshalParams(&param); err != nil {
				continue
			}
			for _, fc := range param.FolderConfigs {
				if !folderConfigPathsMatch(fc.FolderPath, s.folderPath) {
					continue
				}
				lastSeen = fc
				sawFolder = true
				if match(fc) {
					return fc, nil
				}
			}
		}
		if time.Now().After(deadline) {
			if sawFolder {
				return lastSeen, fmt.Errorf("no matching $/snyk.configuration notification found for folder %s within timeout", s.folderPath)
			}
			return types.LspFolderConfig{}, fmt.Errorf("no $/snyk.configuration notification found for folder %s", s.folderPath)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (s *bddSteps) theFolderHasNoAmbientCanaryAutonomyOverride() error {
	fc, err := s.waitForFolderConfigNotification(func(fc types.LspFolderConfig) bool {
		return fc.Settings[types.SettingAmbientCanaryAutonomy] == nil
	})
	if err != nil {
		return err
	}
	if setting := fc.Settings[types.SettingAmbientCanaryAutonomy]; setting != nil {
		return fmt.Errorf("expected no ambient_canary_autonomy override, got %v", setting.Value)
	}
	return nil
}

func (s *bddSteps) theEditorSetsTheFoldersAmbientCanaryAutonomyTo(ctx context.Context, autonomy string) error {
	s.jsonRPCRecorder.ClearNotifications()
	params := types.DidChangeConfigurationParams{
		Settings: types.LspConfigurationParam{
			FolderConfigs: []types.LspFolderConfig{
				{
					FolderPath: s.folderPath,
					Settings: map[string]*types.ConfigSetting{
						types.SettingAmbientCanaryAutonomy: {Value: autonomy, Changed: true},
					},
				},
			},
		},
	}
	if _, err := s.loc.Client.Call(ctx, "workspace/didChangeConfiguration", params); err != nil {
		return fmt.Errorf("didChangeConfiguration call failed: %w", err)
	}
	return nil
}

func (s *bddSteps) theFoldersEffectiveAmbientCanaryAutonomyIs(autonomy string) error {
	fc, err := s.waitForFolderConfigNotification(func(fc types.LspFolderConfig) bool {
		setting := fc.Settings[types.SettingAmbientCanaryAutonomy]
		return setting != nil && setting.Value == autonomy
	})
	if err != nil {
		return err
	}
	setting := fc.Settings[types.SettingAmbientCanaryAutonomy]
	if setting == nil {
		return fmt.Errorf("expected ambient_canary_autonomy override %q, got no override", autonomy)
	}
	if setting.Value != autonomy {
		return fmt.Errorf("expected ambient_canary_autonomy override %q, got %v", autonomy, setting.Value)
	}
	return nil
}

func (s *bddSteps) deltaFindingsAreEnabled() error {
	s.engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingScanNetNew), true)
	return nil
}

func (s *bddSteps) developerSavesFileWithSecurityIssue() error {
	filePath, fileDir := code.TempWorkdirWithIssues(s.scenarioT)
	s.deltaFilePath = filePath
	s.deltaFileDir = fileDir
	// Nothing in production seeds a folder's scan-state entries (see
	// ScanStateAggregator.Init); without this, SetScanInProgress/SetScanDone
	// find no existing key and silently no-op, so the tree view never sees the
	// folder as scanned. Mirrors the pattern in configuration_test.go.
	s.scanStateAggregator.Init([]types.FilePath{fileDir})
	sendFileSavedMessage(s.scenarioT, s.engine, filePath, fileDir, s.loc)

	// The scan triggered by didSave completes asynchronously. Steps reused as
	// "the developer has saved..." go straight on to a pull/tree-view query with
	// no assertion of their own to retry, so this step must wait for the scan's
	// own push notification (proof the scan finished) before returning.
	if _, found := s.awaitPublishedDiagnostics(filePath); !found {
		return fmt.Errorf("timed out waiting for the scan of %s to complete", filePath)
	}
	return nil
}

// findPublishedDiagnostics returns the most recently recorded
// textDocument/publishDiagnostics payload for filePath. A folder's scan can
// publish more than once (once per product processed), so the latest
// notification is the one reflecting every product's cached issues.
func (s *bddSteps) findPublishedDiagnostics(filePath types.FilePath) ([]types.Diagnostic, bool) {
	notifications := s.jsonRPCRecorder.FindNotificationsByMethod("textDocument/publishDiagnostics")
	var diagnostics []types.Diagnostic
	found := false
	for _, n := range notifications {
		var params types.PublishDiagnosticsParams
		if err := n.UnmarshalParams(&params); err != nil {
			continue
		}
		if params.URI == uri.PathToUri(filePath) {
			diagnostics = params.Diagnostics
			found = true
		}
	}
	return diagnostics, found
}

func (s *bddSteps) editorIsNotifiedOfTheSecurityIssue() error {
	diagnostics, found := s.awaitPublishedDiagnostics(s.deltaFilePath)
	if !found {
		return fmt.Errorf("expected the editor to be notified of the security issue, got no diagnostics published for %s (findings appear to have been filtered out)", s.deltaFilePath)
	}
	if len(diagnostics) == 0 {
		return fmt.Errorf("expected the editor to be notified of the security issue, got an empty diagnostics payload")
	}
	return nil
}

// awaitCondition polls condition until it returns true or 5 seconds elapse.
// It never calls t.Fatal/FailNow - callers turn a timeout into their own
// descriptive error, so a failing scenario reports what was actually wrong
// (e.g. "empty diagnostics payload") instead of a generic aborted-step message.
func (s *bddSteps) awaitCondition(condition func() bool) bool {
	deadline := time.Now().Add(5 * time.Second)
	for {
		if condition() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// awaitPublishedDiagnostics waits for a publishDiagnostics notification for
// filePath to arrive, without asserting on its content - callers decide what
// counts as a passing payload (including an empty one, for RED evidence).
func (s *bddSteps) awaitPublishedDiagnostics(filePath types.FilePath) ([]types.Diagnostic, bool) {
	var diagnostics []types.Diagnostic
	found := s.awaitCondition(func() bool {
		var ok bool
		diagnostics, ok = s.findPublishedDiagnostics(filePath)
		return ok
	})
	return diagnostics, found
}

func (s *bddSteps) editorAsksForWorkspaceDiagnostics(ctx context.Context) error {
	rsp, err := s.loc.Client.Call(ctx, "workspace/diagnostic", types.WorkspaceDiagnosticParams{})
	if err != nil {
		return fmt.Errorf("workspace/diagnostic call failed: %w", err)
	}
	var report types.WorkspaceDiagnosticReport
	if err := rsp.UnmarshalResult(&report); err != nil {
		return fmt.Errorf("unmarshalling workspace/diagnostic result failed: %w", err)
	}
	s.lastDiagnostics = nil
	for _, item := range report.Items {
		if item.URI == uri.PathToUri(s.deltaFilePath) {
			s.lastDiagnostics = append(s.lastDiagnostics, item.Items...)
		}
	}
	return nil
}

func (s *bddSteps) editorAsksForFileDiagnostics(ctx context.Context) error {
	rsp, err := s.loc.Client.Call(ctx, "textDocument/diagnostic", types.DocumentDiagnosticParams{
		TextDocument: sglsp.TextDocumentIdentifier{URI: uri.PathToUri(s.deltaFilePath)},
	})
	if err != nil {
		return fmt.Errorf("textDocument/diagnostic call failed: %w", err)
	}
	var report types.RelatedFullDocumentDiagnosticReport
	if err := rsp.UnmarshalResult(&report); err != nil {
		return fmt.Errorf("unmarshalling textDocument/diagnostic result failed: %w", err)
	}
	s.lastDiagnostics = report.Items
	return nil
}

func (s *bddSteps) editorIsToldAboutTheSecurityIssue() error {
	if len(s.lastDiagnostics) == 0 {
		return fmt.Errorf("expected the editor to be told about the security issue, got an empty diagnostics payload")
	}
	return nil
}

func (s *bddSteps) editorAsksForTheIssueTreeView(ctx context.Context) error {
	rsp, err := s.loc.Client.Call(ctx, "workspace/executeCommand", sglsp.ExecuteCommandParams{
		Command: types.GetTreeView,
	})
	if err != nil {
		return fmt.Errorf("workspace/executeCommand(%s) call failed: %w", types.GetTreeView, err)
	}
	if err := rsp.UnmarshalResult(&s.lastTreeViewHTML); err != nil {
		return fmt.Errorf("unmarshalling %s result failed: %w", types.GetTreeView, err)
	}
	return nil
}

// issueTreeViewShowsTheSecurityIssue re-fetches the tree view HTML until it
// contains the issue. The scan goroutine records SetScanDone (which flips the
// tree's per-product state to "scan complete", the gate for rendering file/issue
// nodes) just after publishing diagnostics, not before - so a tree view fetched
// immediately after the diagnostics-published wait in developerSavesFileWithSecurityIssue
// can still race the aggregator update. Re-fetching tolerates that ordering the
// same way awaitPublishedDiagnostics tolerates the scan's own async completion.
func (s *bddSteps) issueTreeViewShowsTheSecurityIssue(ctx context.Context) error {
	found := s.awaitCondition(func() bool {
		if err := s.editorAsksForTheIssueTreeView(ctx); err != nil {
			return false
		}
		return strings.Contains(s.lastTreeViewHTML, "tree-node-issue")
	})
	if !found {
		return fmt.Errorf("expected the issue tree view to contain a security issue, it did not")
	}
	return nil
}

// developerHasEstablishedBaseline seeds a persisted baseline for product.ProductCode
// containing one known issue, using scanPersister.Add() directly. GitPersistenceProvider's
// commit-hash lookup is a pure in-memory/disk cache populated only by Add() - it never
// shells out to git - so any non-empty commit hash string is sufficient here.
func (s *bddSteps) developerHasEstablishedBaseline() error {
	fileDir := types.FilePath(s.scenarioT.TempDir())
	filePath := types.FilePath(filepath.Join(string(fileDir), "app.go"))
	s.deltaFileDir = fileDir
	s.deltaFilePath = filePath

	// Add() alone never creates the on-disk cache directory - only Init() does,
	// and this step bypasses the normal folder-registration/trust flow that
	// would otherwise call it.
	if err := s.scanPersister.Init([]types.FilePath{fileDir}); err != nil {
		return err
	}

	knownIssue := &snyk.Issue{
		ID:               "known-issue",
		AffectedFilePath: filePath,
		Severity:         types.Medium,
		Product:          product.ProductCode,
		Message:          "known code issue",
		AdditionalData:   snyk.CodeIssueData{Key: "key-known"},
	}
	return s.scanPersister.Add(fileDir, "baseline-1", []types.Issue{knownIssue}, product.ProductCode)
}

// bddFakeScanner is a minimal scanner.Scanner used only for the regression and
// mixed-products BDD scenarios, where the fixed single-issue fake Code API service
// cannot represent two distinct issues (an existing one plus a newly introduced
// one) or two products in a single scan. It calls processResults once per entry in
// scans, exercising the real Folder/persistence/filter chain end to end.
type bddFakeScanner struct {
	scans []types.ScanData
}

func (f *bddFakeScanner) Init(_ context.Context) error { return nil }

func (f *bddFakeScanner) RegisterCancelCallback(types.FilePath, func()) {}

func (f *bddFakeScanner) Scan(ctx context.Context, path types.FilePath, processResults types.ScanResultProcessor, postActionFunc types.PostAction) {
	for _, scanData := range f.scans {
		scanData.Path = path
		scanData.UpdateGlobalCache = true
		processResults(ctx, scanData)
	}
	if postActionFunc != nil {
		postActionFunc()
	}
}

var _ scanner.Scanner = (*bddFakeScanner)(nil)

// runScanWithFakeScanner registers a real Folder backed by sc and triggers a real,
// synchronous scan of s.deltaFilePath through it.
func (s *bddSteps) runScanWithFakeScanner(sc *bddFakeScanner) error {
	conf := s.engine.GetConfiguration()
	folder := workspace.NewFolder(conf, s.engine.GetLogger(), s.deltaFileDir, "Test", sc,
		di.HoverService(), di.ScanNotifier(), di.Notifier(), s.scanPersister,
		di.ScanStateAggregator(), featureflag.NewFakeService(), di.ConfigResolver(), s.engine)
	config.GetWorkspace(conf).AddFolder(folder)

	folderConfig := config.GetFolderConfigFromEngine(s.engine, testutil.DefaultConfigResolver(s.engine), s.deltaFileDir, s.engine.GetLogger())
	di.FeatureFlagService().PopulateFolderConfig(folderConfig)

	folder.ScanFile(s.scenarioT.Context(), s.deltaFilePath)
	return nil
}

func (s *bddSteps) developerSavesFileWithNewIssueAlongsideKnown() error {
	newIssue := &snyk.Issue{
		ID:               "new-issue",
		AffectedFilePath: s.deltaFilePath,
		Severity:         types.High,
		Product:          product.ProductCode,
		Message:          "newly introduced code issue",
		AdditionalData:   snyk.CodeIssueData{Key: "key-new"},
	}
	knownIssue := &snyk.Issue{
		ID:               "known-issue",
		AffectedFilePath: s.deltaFilePath,
		Severity:         types.Medium,
		Product:          product.ProductCode,
		Message:          "known code issue",
		AdditionalData:   snyk.CodeIssueData{Key: "key-known"},
	}
	return s.runScanWithFakeScanner(&bddFakeScanner{scans: []types.ScanData{
		{Product: product.ProductCode, Issues: []types.Issue{newIssue, knownIssue}},
	}})
}

func (s *bddSteps) editorNotifiedOfOnlyNewIssue() error {
	diagnostics, found := s.awaitPublishedDiagnostics(s.deltaFilePath)
	if !found {
		return fmt.Errorf("expected a textDocument/publishDiagnostics notification for %s, got none", s.deltaFilePath)
	}
	if len(diagnostics) != 1 {
		return fmt.Errorf("expected exactly one diagnostic (only the newly introduced issue), got %d: %+v", len(diagnostics), diagnostics)
	}
	if diagnostics[0].Code != "new-issue" {
		return fmt.Errorf("expected the newly introduced issue %q, got %q", "new-issue", diagnostics[0].Code)
	}
	return nil
}

// developerSavesFileWithMixedProductIssues puts the OSS issue on a different
// file than the code issues. documentDiagnosticCache is keyed by file path only
// and holds every product's issues for that path together (see
// updateGlobalCacheAndSeverityCounts), so two products scanning the very same
// path in sequence would overwrite each other's entries - an unrelated,
// pre-existing cache bug this scenario must not depend on. Separate files also
// match reality: OSS findings land on manifest files, Code findings on source.
func (s *bddSteps) developerSavesFileWithMixedProductIssues() error {
	s.deltaOssFilePath = types.FilePath(filepath.Join(string(s.deltaFileDir), "package.json"))

	newCodeIssue := &snyk.Issue{
		ID:               "new-code-issue",
		AffectedFilePath: s.deltaFilePath,
		Severity:         types.High,
		Product:          product.ProductCode,
		Message:          "newly introduced code issue",
		AdditionalData:   snyk.CodeIssueData{Key: "key-new-code"},
	}
	knownCodeIssue := &snyk.Issue{
		ID:               "known-issue",
		AffectedFilePath: s.deltaFilePath,
		Severity:         types.Medium,
		Product:          product.ProductCode,
		Message:          "known code issue",
		AdditionalData:   snyk.CodeIssueData{Key: "key-known"},
	}
	ossIssue := &snyk.Issue{
		ID:               "oss-issue",
		AffectedFilePath: s.deltaOssFilePath,
		Severity:         types.High,
		Product:          product.ProductOpenSource,
		Message:          "issue from a product without a baseline",
		AdditionalData:   snyk.OssIssueData{},
	}
	return s.runScanWithFakeScanner(&bddFakeScanner{scans: []types.ScanData{
		{Product: product.ProductCode, Issues: []types.Issue{newCodeIssue, knownCodeIssue}},
		{Product: product.ProductOpenSource, Issues: []types.Issue{ossIssue}},
	}})
}

func (s *bddSteps) editorNotifiedOfNewAndUnbaselinedIssues() error {
	var codeDiagnostics []types.Diagnostic
	found := s.awaitCondition(func() bool {
		var ok bool
		codeDiagnostics, ok = s.findPublishedDiagnostics(s.deltaFilePath)
		return ok && len(codeDiagnostics) >= 1
	})
	if !found {
		return fmt.Errorf("expected a publishDiagnostics notification for %s with the newly introduced issue, got %+v", s.deltaFilePath, codeDiagnostics)
	}

	// notifierImpl.Send queues onto a buffered channel drained by a single background
	// listener goroutine (see internal/notification/notifier.go): finding the code
	// notification only proves that goroutine has reached that point in the queue,
	// not that it has already drained the oss notification queued right behind it.
	var ossDiagnostics []types.Diagnostic
	found = s.awaitCondition(func() bool {
		var ok bool
		ossDiagnostics, ok = s.findPublishedDiagnostics(s.deltaOssFilePath)
		return ok && len(ossDiagnostics) >= 1
	})
	if !found {
		return fmt.Errorf("expected a publishDiagnostics notification for %s with the unbaselined issue, got none", s.deltaOssFilePath)
	}

	diagnostics := append(append([]types.Diagnostic{}, codeDiagnostics...), ossDiagnostics...)
	ids := map[string]bool{}
	for _, d := range diagnostics {
		ids[fmt.Sprint(d.Code)] = true
	}
	for _, want := range []string{"new-code-issue", "oss-issue"} {
		if !ids[want] {
			return fmt.Errorf("expected diagnostic %q among %+v", want, diagnostics)
		}
	}
	if ids["known-issue"] {
		return fmt.Errorf("expected the known baselined issue to be filtered out, but found it among %+v", diagnostics)
	}
	return nil
}

// Test_BDDSteps_PerScenarioCleanup guards against setupServer's t.Cleanup
// firing once for the whole TestBDD run instead of once per scenario.
func Test_BDDSteps_PerScenarioCleanup(t *testing.T) {
	s := newBDDSteps(t)
	ctx := context.Background()

	ctx, err := s.beforeScenario(ctx, &godog.Scenario{Name: "scenario one"})
	require.NoError(t, err)
	require.NoError(t, s.aRunningLanguageServer())
	firstClient := s.loc.Client

	_, err = s.afterScenario(ctx, &godog.Scenario{Name: "scenario one"}, nil)
	require.NoError(t, err)

	assert.True(t, firstClient.IsStopped(), "expected scenario one's server to be torn down before scenario two starts")

	ctx, err = s.beforeScenario(ctx, &godog.Scenario{Name: "scenario two"})
	require.NoError(t, err)
	require.NoError(t, s.aRunningLanguageServer())
	secondClient := s.loc.Client

	assert.False(t, secondClient.IsStopped(), "expected scenario two's own server to still be running, independently of scenario one's teardown")
	assert.NotSame(t, firstClient, secondClient)

	_, err = s.afterScenario(ctx, &godog.Scenario{Name: "scenario two"}, nil)
	require.NoError(t, err)

	assert.True(t, secondClient.IsStopped(), "expected scenario two's server to be torn down by its own After hook")
}

// Test_BDDSteps_ScenarioSubtestFailsOnStepErrorHelper is not a real test: it
// exists only so Test_BDDSteps_ScenarioSubtest_FailsOnStepError can run it in
// a subprocess and inspect its exit code/output. A real scenario subtest
// failure propagates to the Go test that spawned it (that's the whole point
// being verified), so it must happen in an isolated process rather than
// failing this package's own test run.
func Test_BDDSteps_ScenarioSubtestFailsOnStepErrorHelper(t *testing.T) {
	if os.Getenv("BDD_STEPS_HELPER_PROCESS") != "1" {
		t.Skip("only runs as a subprocess of Test_BDDSteps_ScenarioSubtest_FailsOnStepError")
	}
	s := newBDDSteps(t)
	ctx := context.Background()

	ctx, err := s.beforeScenario(ctx, &godog.Scenario{Name: "scenario with a failing step"})
	require.NoError(t, err)

	stepErr := s.runOnScenarioGoroutine(func() error { return fmt.Errorf("boom") })
	require.Error(t, stepErr)

	// afterScenario passes the step error through unchanged (godog's own
	// convention for reporting it to the suite) - that's not what's under
	// test here, so it's deliberately ignored.
	_, _ = s.afterScenario(ctx, &godog.Scenario{Name: "scenario with a failing step"}, stepErr)
}

// Test_BDDSteps_ScenarioSubtest_FailsOnStepError guards the false-PASS case
// described on runStep's comment.
func Test_BDDSteps_ScenarioSubtest_FailsOnStepError(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^Test_BDDSteps_ScenarioSubtestFailsOnStepErrorHelper$", "-test.v")
	cmd.Env = append(os.Environ(), "BDD_STEPS_HELPER_PROCESS=1")
	out, err := cmd.CombinedOutput()

	assert.Error(t, err, "expected the helper process to exit non-zero because its scenario subtest failed:\n%s", out)
	assert.Contains(t, string(out), "--- FAIL: Test_BDDSteps_ScenarioSubtestFailsOnStepErrorHelper/scenario_with_a_failing_step")
}

// Test_BDDSteps_RunOnScenarioGoroutine_SurvivesGoexit guards the Goexit case
// described on runOnScenarioGoroutine, using a bare runtime.Goexit to stand
// in for t.Fatal.
func Test_BDDSteps_RunOnScenarioGoroutine_SurvivesGoexit(t *testing.T) {
	s := &bddSteps{
		stepFunc:   make(chan func() error),
		stepResult: make(chan error),
	}
	go func() {
		for fn := range s.stepFunc {
			s.runStep(fn)
		}
	}()

	done := make(chan error, 1)
	go func() {
		done <- s.runOnScenarioGoroutine(func() error {
			runtime.Goexit()
			return nil // unreachable
		})
	}()

	select {
	case err := <-done:
		assert.Error(t, err, "expected an error instead of the step's zero-value result once its goroutine exited via Goexit")
	case <-time.After(5 * time.Second):
		t.Fatal("runOnScenarioGoroutine hung after the step's own goroutine called runtime.Goexit (this is what t.Fatal does internally) - it must report an error instead")
	}
}

// Test_BDDSteps_RunOnScenarioGoroutine_SurvivesPanic guards against a genuine
// panic() in a step body (or something it calls) crashing the whole TestBDD
// process instead of failing just that one scenario.
func Test_BDDSteps_RunOnScenarioGoroutine_SurvivesPanic(t *testing.T) {
	s := &bddSteps{
		stepFunc:   make(chan func() error),
		stepResult: make(chan error),
	}
	go func() {
		for fn := range s.stepFunc {
			s.runStep(fn)
		}
	}()

	done := make(chan error, 1)
	go func() {
		done <- s.runOnScenarioGoroutine(func() error {
			panic("boom")
		})
	}()

	select {
	case err := <-done:
		assert.Error(t, err, "expected an error instead of a crashed test binary once the step panicked")
		assert.Contains(t, err.Error(), "boom")
	case <-time.After(5 * time.Second):
		t.Fatal("runOnScenarioGoroutine hung after the step's own goroutine panicked - it must report an error instead")
	}
}

// Test_BDDSteps_RunOnScenarioGoroutine_ReturnsPromptlyWhenScenarioAlreadyDied
// guards against a hang when the scenario goroutine spawned in beforeScenario
// dies (e.g. panics during s.t.Run's own setup) before it ever reaches the
// select loop that reads s.stepFunc: without an escape hatch on scenarioDied,
// runOnScenarioGoroutine's unbuffered send would block forever.
func Test_BDDSteps_RunOnScenarioGoroutine_ReturnsPromptlyWhenScenarioAlreadyDied(t *testing.T) {
	s := &bddSteps{
		scenarioDied: make(chan struct{}),
		stepFunc:     make(chan func() error),
		stepResult:   make(chan error),
	}
	close(s.scenarioDied)

	done := make(chan error, 1)
	go func() {
		done <- s.runOnScenarioGoroutine(func() error { return nil })
	}()

	select {
	case err := <-done:
		assert.Error(t, err, "expected an error instead of a hang once the scenario goroutine had already died")
	case <-time.After(5 * time.Second):
		t.Fatal("runOnScenarioGoroutine hung after the scenario goroutine had already died before reading the step")
	}
}

// Test_BDDSteps_RunStep_PanicIncludesStackTrace guards against the panic
// recovery in runStep discarding the stack trace Go would otherwise print
// for an unrecovered panic, which makes real panics hard to diagnose.
func Test_BDDSteps_RunStep_PanicIncludesStackTrace(t *testing.T) {
	s := &bddSteps{
		stepFunc:   make(chan func() error),
		stepResult: make(chan error),
	}
	go func() {
		for fn := range s.stepFunc {
			s.runStep(fn)
		}
	}()

	done := make(chan error, 1)
	go func() {
		done <- s.runOnScenarioGoroutine(func() error {
			panic("boom")
		})
	}()

	select {
	case err := <-done:
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "goroutine", "expected the panic error to include a stack trace")
	case <-time.After(5 * time.Second):
		t.Fatal("runOnScenarioGoroutine hung after the step's own goroutine panicked")
	}
}

// Test_BDDSteps_RunOnScenarioGoroutine_ReturnsStepResult proves the goroutine
// bridge passes through the step's return value unchanged on the normal path.
func Test_BDDSteps_RunOnScenarioGoroutine_ReturnsStepResult(t *testing.T) {
	s := &bddSteps{
		stepFunc:   make(chan func() error),
		stepResult: make(chan error),
	}
	go func() {
		for fn := range s.stepFunc {
			s.runStep(fn)
		}
	}()

	wantErr := fmt.Errorf("boom")
	err := s.runOnScenarioGoroutine(func() error { return wantErr })
	assert.Equal(t, wantErr, err)

	err = s.runOnScenarioGoroutine(func() error { return nil })
	assert.NoError(t, err)
}
