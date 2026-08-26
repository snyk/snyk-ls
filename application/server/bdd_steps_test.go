package server

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/creachadair/jrpc2/server"
	"github.com/cucumber/godog"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/object"
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
	"github.com/snyk/snyk-ls/domain/snyk/remediation"
	"github.com/snyk/snyk-ls/domain/snyk/scanner"
	"github.com/snyk/snyk-ls/infrastructure/authentication"
	"github.com/snyk/snyk-ls/infrastructure/code"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	"github.com/snyk/snyk-ls/infrastructure/snyk_api"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/observability/performance"
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
	tokenService        types.TokenService
	loc                 server.Local
	jsonRPCRecorder     *testsupport.JsonRPCRecorder
	deps                di.Dependencies
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
	// expectedNewIssueCode is the diagnostic code editorNotifiedOfOnlyNewIssue
	// requires; scenarios set it to the finding they deliberately introduced.
	expectedNewIssueCode string

	savedLlmProvider    string
	savedLlmModel       string
	fixCapturedProvider string
	fixCapturedModel    string
	fixCommandErr       error
}

func newBDDSteps(t *testing.T) *bddSteps {
	t.Helper()
	return &bddSteps{t: t}
}

func (s *bddSteps) register(sc *godog.ScenarioContext) {
	sc.Before(s.beforeScenario)
	sc.After(s.afterScenario)
	sc.Given(`^a running language server$`, func() error {
		return s.runOnScenarioGoroutine(func() error { return s.startLanguageServer() })
	})
	sc.Given(`^a running language server that finds one issue in every source file$`, func() error {
		return s.runOnScenarioGoroutine(func() error {
			return s.startLanguageServer(WithProductScanners(bddPerFileScanner{}))
		})
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
	sc.Given(`^delta findings are switched to "New new issues" globally$`, func() error {
		return s.runOnScenarioGoroutine(s.deltaFindingsAreEnabled)
	})
	sc.Given(`^delta findings are switched to "New new issues" at the workspace folder level$`, func() error {
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
	sc.Given(`^the developer has a Code issue found by Snyk$`, func() error {
		return s.runOnScenarioGoroutine(s.developerHasACodeIssueFoundBySnyk)
	})
	sc.When(`^the developer asks Snyk to fix the issue with AI$`, func(ctx context.Context) error {
		return s.runOnScenarioGoroutine(func() error { return s.theDeveloperAsksSnykToFixTheIssueWithAi(ctx) })
	})
	sc.Then(`^the editor receives a structured AI fix result for the issue$`, func() error {
		return s.runOnScenarioGoroutine(s.theEditorReceivesAStructuredAiFixResultForTheIssue)
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
	sc.Given(`^the developer has an established baseline for "([^"]*)" with one known issue$`, func(product string) error {
		return s.runOnScenarioGoroutine(func() error { return s.developerHasEstablishedBaselineForProduct(product) })
	})
	sc.When(`^the developer saves a file that introduces a new issue alongside the known one$`, func() error {
		return s.runOnScenarioGoroutine(s.developerSavesFileWithNewIssueAlongsideKnown)
	})
	sc.Then(`^the editor is notified of only the newly introduced issue$`, func() error {
		return s.runOnScenarioGoroutine(s.editorNotifiedOfOnlyNewIssue)
	})
	sc.When(`^the developer saves a file that produces a new "([^"]*)" issue and an "([^"]*)" issue$`, func(product1, product2 string) error {
		return s.runOnScenarioGoroutine(func() error { return s.developerSavesFileWithProductIssues(product1, product2) })
	})
	sc.Then(`^the editor is notified of both the newly introduced "([^"]*)" issue and the "([^"]*)" issue$`, func(product1, product2 string) error {
		return s.runOnScenarioGoroutine(func() error { return s.editorNotifiedOfBothProductIssues(product1, product2) })
	})
	sc.Given(`^the developer opens a repository whose base branch carries a file named after a Windows device$`, func() error {
		return s.runOnScenarioGoroutine(s.developerOpensRepositoryWithDeviceFileNameOnBaseBranch)
	})
	sc.When(`^the developer scans the whole repository$`, func(ctx context.Context) error {
		return s.runOnScenarioGoroutine(func() error { return s.developerScansTheWholeRepository(ctx) })
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
	sc.Then(`^the configuration dialog shows "([^"]*)" as the custom (?:API endpoint|LLM provider's API endpoint)$`, func(endpoint string) error {
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
	sc.When(`^the developer asks Snyk to autonomously fix a folder$`, func(ctx context.Context) error {
		return s.runOnScenarioGoroutine(func() error { return s.theDeveloperAsksSnykToFixAFolder(ctx) })
	})
	sc.Then(`^the fix runs with the developer's chosen LLM provider and model$`, func() error {
		return s.runOnScenarioGoroutine(s.theFixRunsWithTheChosenProviderAndModel)
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

// runStep sends exactly one result on every exit path - return, panic, or a
// scenarioT.Fatal/FailNow Goexit - and calls scenarioT.Fail() on error or
// panic so the per-scenario subtest reflects the failure instead of reporting
// a false PASS.
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

func (s *bddSteps) startLanguageServer(serverOpts ...ServerTestOption) error {
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

	baseDeps := di.TestInit(s.scenarioT, engine, tokenService, &di.Dependencies{
		ScanPersister:       s.scanPersister,
		ConfigResolver:      resolver,
		ScanStateAggregator: realScanStateAggregator,
	})

	// di.TestInit unconditionally installs a CommandServiceMock, which returns
	// (nil, nil) for every command - so workspace/executeCommand(snyk.getTreeView)
	// never reaches the real getTreeViewCommand. Swap in the real service, now that
	// deps (and the workspace registered via config.SetWorkspace) are available.
	realWorkspace := config.GetWorkspace(engine.GetConfiguration())
	issueProvider, ok := realWorkspace.(snyk.IssueProvider)
	if !ok {
		return fmt.Errorf("workspace does not implement snyk.IssueProvider")
	}
	// A real FolderRemediator (built the same way application/di/init.go builds
	// it for production) so snyk.remediationAgent.fixFolder scenarios exercise
	// the real command -> remyProvider.FixFolder wiring instead of failing with
	// "remediation agent is not enabled".
	folderRemediator, ok := remediation.NewRemyProvider(engine, nil).(remediation.FolderRemediator)
	if !ok {
		return fmt.Errorf("remediation.NewRemyProvider did not return a FolderRemediator")
	}
	// A real *code.Scanner (built the same way domain/ide/command/code_fix_diffs_test.go
	// builds one) so snyk.code.fixDiffs scenarios exercise the real command ->
	// AiFixHandler -> GetAutofixDiffs wiring instead of failing on a nil scanner.
	codeErrorReporter := code.NewCodeErrorReporter(error_reporting.NewTestErrorReporter(engine))
	fixDiffsCodeScanner := code.New(
		engine, performance.NewInstrumentor(), &snyk_api.FakeApiClient{CodeEnabled: true}, codeErrorReporter, nil,
		baseDeps.FeatureFlagService, baseDeps.Notifier, code.NewCodeInstrumentor(), codeErrorReporter,
		code.NewFakeCodeScannerClient, resolver, testutil.NewDrainedProgressTracker(),
	)
	baseDeps.CommandService = command.NewService(
		engine, engine.GetLogger(), baseDeps.AuthenticationService, baseDeps.FeatureFlagService, baseDeps.Notifier,
		baseDeps.LearnService, issueProvider, fixDiffsCodeScanner, nil, baseDeps.LdxSyncService,
		baseDeps.ConfigResolver, baseDeps.ScanStateAggregator.StateSnapshot, folderRemediator, baseDeps.ScanCtx,
	)

	loc, jsonRPCRecorder, deps := setupServer(s.scenarioT, engine, tokenService, append([]ServerTestOption{WithDeps(baseDeps)}, serverOpts...)...)
	// setupServer's own di.TestInit call unconditionally builds and registers a
	// second, empty workspace (config.SetWorkspace has no override option), which
	// would silently orphan the issueProvider baked into baseDeps.CommandService
	// above. Nothing has added a folder yet at this point, so restoring
	// realWorkspace here is safe and keeps every later config.GetWorkspace call
	// (folder registration, and the CommandService's own issue lookups)
	// consistent with the same workspace instance.
	config.SetWorkspace(engine.GetConfiguration(), realWorkspace)
	s.engine = engine
	s.tokenService = tokenService
	s.loc = loc
	s.jsonRPCRecorder = jsonRPCRecorder
	s.deps = deps
	s.scanStateAggregator = realScanStateAggregator

	// Scenarios that save a file through the real didSave pipeline (as opposed to
	// the fake-scanner scenarios, which build a Folder directly) need Snyk Code
	// scanning enabled and an authenticated user, or the scan never runs.
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), true)
	deps.AuthenticationService.Provider().(*authentication.FakeAuthenticationProvider).IsAuthenticated = true
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
	s.savedLlmProvider = provider
	s.savedLlmModel = model
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
	if !strings.Contains(selectHTML, "selected") {
		return fmt.Errorf("expected an option to be selected in the llm_provider field")
	}
	return nil
}

func (s *bddSteps) theDialogContainsNoLlmApiKeyField() error {
	if strings.Contains(strings.ToLower(s.dialogHTML), "llm_api_key") {
		return fmt.Errorf("configuration dialog must never contain an LLM API key field")
	}
	return nil
}

// developerOpensRepositoryWithDeviceFileNameOnBaseBranch builds the customer's
// repository: master carries the reserved device name plus a file with an
// already-known finding, and the checked-out feature branch drops the reserved
// name and adds a file with a new finding. Nothing writes a reserved device
// name to disk, so this runs on every platform.
func (s *bddSteps) developerOpensRepositoryWithDeviceFileNameOnBaseBranch() error {
	repoPath := s.newScenarioRepoPath()
	repo := testutil.InitGitRepo(s.scenarioT, repoPath)
	storer := repo.Storer

	knownBlob := testutil.WriteGitBlob(s.scenarioT, storer, bddDummySource)
	buildTree := testutil.WriteGitTree(s.scenarioT, storer, []object.TreeEntry{
		{Name: "prn.sh", Mode: filemode.Regular, Hash: testutil.WriteGitBlob(s.scenarioT, storer, bddBuildScriptSource)},
	})
	scriptsTree := testutil.WriteGitTree(s.scenarioT, storer, []object.TreeEntry{
		{Name: "build", Mode: filemode.Dir, Hash: buildTree},
	})
	masterCommit := testutil.CommitGitTree(s.scenarioT, repo, testutil.WriteGitTree(s.scenarioT, storer, []object.TreeEntry{
		{Name: bddKnownFindingFile, Mode: filemode.Regular, Hash: knownBlob},
		{Name: "scripts", Mode: filemode.Dir, Hash: scriptsTree},
	}))

	featureTree := testutil.WriteGitTree(s.scenarioT, storer, []object.TreeEntry{
		{Name: bddKnownFindingFile, Mode: filemode.Regular, Hash: knownBlob},
		{Name: bddNewFindingFile, Mode: filemode.Regular, Hash: testutil.WriteGitBlob(s.scenarioT, storer, bddDummySource)},
	})
	testutil.CommitGitTreeOnBranch(s.scenarioT, repo, plumbing.NewBranchReferenceName("feature"), featureTree, masterCommit)

	// Checking out the feature branch is just writing its two files.
	for _, name := range []string{bddKnownFindingFile, bddNewFindingFile} {
		if err := writeScenarioFile(repoPath, name, bddDummySource); err != nil {
			return err
		}
	}

	s.deltaFileDir = repoPath
	s.deltaFilePath = types.FilePath(filepath.Join(string(repoPath), bddNewFindingFile))
	s.expectedNewIssueCode = bddNewFindingFile
	return s.openScenarioRepo(repoPath)
}

const (
	bddDummySource       = "public class Dummy {}\n"
	bddBuildScriptSource = "#!/bin/sh\necho build\n"
	// One finding per source file, named after it, so the delta between the base
	// branch and the working tree is exactly the file the feature branch added.
	bddKnownFindingFile = "Known.java"
	bddNewFindingFile   = "New.java"
)

// bddPerFileScanner reports one finding per .java file it finds under the path
// it is handed. Only the product scanner is substituted: the real
// DelegatingConcurrentScanner still clones the base branch and diffs against it,
// which is the code this scenario exists to exercise.
type bddPerFileScanner struct{}

func (bddPerFileScanner) Product() product.Product { return product.ProductCode }

func (bddPerFileScanner) IsEnabledForFolder(*types.FolderConfig) bool { return true }

func (bddPerFileScanner) Scan(_ context.Context, pathToScan types.FilePath) ([]types.Issue, error) {
	var issues []types.Issue
	err := filepath.WalkDir(string(pathToScan), func(p string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() || filepath.Ext(p) != code.FakeFileExtension {
			return nil //nolint:nilerr // an unreadable entry is simply not a finding
		}
		issues = append(issues, &snyk.Issue{
			ID:               filepath.Base(p),
			AffectedFilePath: types.FilePath(p),
			ContentRoot:      pathToScan,
			Severity:         types.High,
			Product:          product.ProductCode,
			Message:          "finding in " + filepath.Base(p),
			AdditionalData:   snyk.CodeIssueData{Key: "key-" + filepath.Base(p)},
		})
		return nil
	})
	return issues, err
}

func (s *bddSteps) newScenarioRepoPath() types.FilePath {
	repoPath := types.FilePath(s.scenarioT.TempDir())
	if canonical, err := filepath.EvalSymlinks(string(repoPath)); err == nil {
		repoPath = types.FilePath(canonical)
	}
	return repoPath
}

func writeScenarioFile(repoPath types.FilePath, name, content string) error {
	onDisk := filepath.Join(string(repoPath), filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(onDisk), 0o755); err != nil {
		return fmt.Errorf("creating %s failed: %w", filepath.Dir(onDisk), err)
	}
	if err := os.WriteFile(onDisk, []byte(content), 0o600); err != nil {
		return fmt.Errorf("writing %s failed: %w", onDisk, err)
	}
	return nil
}

// openScenarioRepo opens repoPath the way an editor does: initialize carrying
// the workspace folder, initialized, then the base branch over the settings
// channel. The server builds the folder and its scanner itself, so registration
// (including the persister's cache directory) runs for real.
func (s *bddSteps) openScenarioRepo(repoPath types.FilePath) error {
	ctx := s.scenarioT.Context()
	initParams := types.InitializeParams{
		WorkspaceFolders: []types.WorkspaceFolder{
			{Uri: uri.PathToUri(repoPath), Name: "bdd-device-name-repo"},
		},
	}
	if _, err := s.loc.Client.Call(ctx, "initialize", initParams); err != nil {
		return fmt.Errorf("initialize call failed: %w", err)
	}
	// Simulates an org policy locking auto-scan off, so the scan this scenario
	// triggers explicitly is the only one running.
	disableAutoScan(s.scenarioT, s.engine.GetConfiguration())
	if _, err := s.loc.Client.Call(ctx, "initialized", types.InitializedParams{}); err != nil {
		return fmt.Errorf("initialized call failed: %w", err)
	}
	types.WaitForLspInitialized(s.engine.GetConfiguration())

	settings := types.DidChangeConfigurationParams{
		Settings: types.LspConfigurationParam{
			FolderConfigs: []types.LspFolderConfig{
				{
					FolderPath: repoPath,
					Settings: map[string]*types.ConfigSetting{
						types.SettingBaseBranch:      {Value: "master", Changed: true},
						types.SettingReferenceBranch: {Value: "master", Changed: true},
					},
				},
			},
		},
	}
	if _, err := s.loc.Client.Call(ctx, "workspace/didChangeConfiguration", settings); err != nil {
		return fmt.Errorf("workspace/didChangeConfiguration call failed: %w", err)
	}

	s.folderPath = repoPath
	return nil
}

func (s *bddSteps) developerScansTheWholeRepository(ctx context.Context) error {
	if _, err := s.loc.Client.Call(ctx, "workspace/executeCommand", sglsp.ExecuteCommandParams{
		Command: types.WorkspaceScanCommand,
	}); err != nil {
		return fmt.Errorf("workspace/executeCommand(%s) call failed: %w", types.WorkspaceScanCommand, err)
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
	sendFileSavedMessage(s.scenarioT, s.engine, filePath, fileDir, s.loc, s.deps)

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

// theDeveloperAsksSnykToFixTheIssueWithAi drives the real snyk.code.fixDiffs command end
// to end: real LSP request -> real command dispatch -> the real codeFixDiffs command ->
// the real AiFixHandler state machine -> the real Notifier. GetAutofixDiffs is driven to
// its deterministic, network-free error branch (no bundle hash registered for the issue's
// content root), the same way domain/ide/command/code_fix_diffs_test.go's
// Test_codeFixDiffs_Execute_SendsAiFixNotification does, so the scenario is fast and
// reliable without a real Code Scanner backend.
func (s *bddSteps) theDeveloperAsksSnykToFixTheIssueWithAi(ctx context.Context) error {
	s.scenarioT.Cleanup(code.ResetHTMLRenderer)

	diagnostics, found := s.awaitPublishedDiagnostics(s.deltaFilePath)
	if !found || len(diagnostics) == 0 {
		return fmt.Errorf("expected the editor to have been notified of the security issue, got no diagnostics published for %s", s.deltaFilePath)
	}
	// Diagnostic.Data.Id carries the same occurrence-unique key
	// (AdditionalData.Key) that the workspace's IssueProvider looks issues up
	// by (see Folder.Issue) - so the fix command must be addressed by that key.
	issueID := diagnostics[0].Data.Id
	if issueID == "" {
		return fmt.Errorf("expected the scanned issue's diagnostic to carry a non-empty id, got none")
	}

	s.jsonRPCRecorder.ClearNotifications()
	if _, err := s.loc.Client.Call(ctx, "workspace/executeCommand", sglsp.ExecuteCommandParams{
		Command:   types.CodeFixDiffsCommand,
		Arguments: []any{issueID},
	}); err != nil {
		return fmt.Errorf("workspace/executeCommand(%s) call failed: %w", types.CodeFixDiffsCommand, err)
	}
	return nil
}

// waitForAiFixNotification polls for the $/snyk.aiFix notification the codeFixDiffs
// command sends once its (synchronous, in this deterministic-error scenario) background
// fix attempt finishes.
func (s *bddSteps) waitForAiFixNotification() (types.AiFixNotification, error) {
	var aiFix types.AiFixNotification
	found := s.awaitCondition(func() bool {
		notifications := s.jsonRPCRecorder.FindNotificationsByMethod("$/snyk.aiFix")
		if len(notifications) == 0 {
			return false
		}
		return notifications[len(notifications)-1].UnmarshalParams(&aiFix) == nil
	})
	if !found {
		return types.AiFixNotification{}, fmt.Errorf("no $/snyk.aiFix notification received within timeout")
	}
	return aiFix, nil
}

func (s *bddSteps) theEditorReceivesAStructuredAiFixResultForTheIssue() error {
	aiFix, err := s.waitForAiFixNotification()
	if err != nil {
		return err
	}
	if aiFix.IssueId == "" {
		return fmt.Errorf("expected the $/snyk.aiFix notification to identify the issue, got an empty issue id")
	}
	if aiFix.Status == "" {
		return fmt.Errorf("expected the $/snyk.aiFix notification to carry a fix status, got an empty status")
	}
	if aiFix.Fixes == nil {
		return fmt.Errorf("expected the $/snyk.aiFix notification to carry a fix results list, got none")
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
		s.deps.HoverService, s.deps.ScanNotifier, s.deps.Notifier, s.scanPersister,
		s.scanStateAggregator, featureflag.NewFakeService(), s.deps.ConfigResolver, s.engine)
	config.GetWorkspace(conf).AddFolder(folder)

	folderConfig := config.GetFolderConfigFromEngine(s.engine, testutil.DefaultConfigResolver(s.engine), s.deltaFileDir, s.engine.GetLogger())
	s.deps.FeatureFlagService.PopulateFolderConfig(folderConfig)

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
	s.expectedNewIssueCode = "new-issue"
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

// developerHasACodeIssueFoundBySnyk seeds a real Code issue into a real Folder via the
// existing fake-scanner harness (runScanWithFakeScanner/bddFakeScanner) rather than driving
// the real Code scanner's full didSave pipeline: that pipeline's background
// reference-branch scan (DelegatingConcurrentScanner.Scan's scanBaseBranch) races the
// freshly-cached issue and can clear it before this scenario's fix command runs, since
// code.TempWorkdirWithIssues's throwaway git repo has no commits for the base scan to
// check out.
func (s *bddSteps) developerHasACodeIssueFoundBySnyk() error {
	fileDir := types.FilePath(s.scenarioT.TempDir())
	filePath := types.FilePath(filepath.Join(string(fileDir), "app.go"))
	s.deltaFileDir = fileDir
	s.deltaFilePath = filePath

	issue := &snyk.Issue{
		ID:               "code-issue-ai-fix",
		AffectedFilePath: filePath,
		Severity:         types.High,
		Product:          product.ProductCode,
		Message:          "a code security issue",
		AdditionalData:   snyk.CodeIssueData{Key: "key-ai-fix"},
	}
	return s.runScanWithFakeScanner(&bddFakeScanner{scans: []types.ScanData{
		{Product: product.ProductCode, Issues: []types.Issue{issue}},
	}})
}

// editorNotifiedOfOnlyNewIssue asserts across every file the editor was told
// about, not just deltaFilePath: with the pre-existing and the new finding in
// different files, a per-file check would pass even when no baseline exists at
// all and delta fails open, because the new file has one finding either way.
func (s *bddSteps) editorNotifiedOfOnlyNewIssue() error {
	if _, found := s.awaitPublishedDiagnostics(s.deltaFilePath); !found {
		return fmt.Errorf("expected a textDocument/publishDiagnostics notification for %s, got none", s.deltaFilePath)
	}

	// A base branch scan runs after the working scan has already published, so
	// the delta-filtered republish arrives later; poll for the settled state.
	var withFindings []string
	var total int
	settled := s.awaitCondition(func() bool {
		withFindings, total = s.filesWithFindings()
		return total == 1
	})
	if !settled {
		return fmt.Errorf("expected exactly one diagnostic in the whole workspace (only the newly introduced issue), got %d across %v", total, withFindings)
	}

	diagnostics := s.latestDiagnosticsByFile()[string(uri.PathToUri(s.deltaFilePath))]
	if len(diagnostics) != 1 {
		return fmt.Errorf("expected the one remaining diagnostic to be on %s, it was on %v", s.deltaFilePath, withFindings)
	}
	if diagnostics[0].Code != s.expectedNewIssueCode {
		return fmt.Errorf("expected the newly introduced issue %q, got %q", s.expectedNewIssueCode, diagnostics[0].Code)
	}
	return nil
}

// filesWithFindings returns the files the editor currently shows findings for,
// and how many diagnostics that is in total.
func (s *bddSteps) filesWithFindings() (files []string, total int) {
	for path, diagnostics := range s.latestDiagnosticsByFile() {
		if len(diagnostics) > 0 {
			files = append(files, path)
			total += len(diagnostics)
		}
	}
	sort.Strings(files)
	return files, total
}

// latestDiagnosticsByFile returns the most recent publishDiagnostics payload per
// URI. A folder republishes per product, so only the last one per file counts.
func (s *bddSteps) latestDiagnosticsByFile() map[string][]types.Diagnostic {
	latest := map[string][]types.Diagnostic{}
	for _, n := range s.jsonRPCRecorder.FindNotificationsByMethod("textDocument/publishDiagnostics") {
		var params types.PublishDiagnosticsParams
		if err := n.UnmarshalParams(&params); err != nil {
			continue
		}
		latest[string(params.URI)] = params.Diagnostics
	}
	return latest
}

// theDeveloperAsksSnykToFixAFolder drives the real snyk.remediationAgent.fixFolder
// command end to end: real LSP request -> real command dispatch -> real
// remyProvider.FixFolder -> real gafRunner -> real buildRemyFixConfig -> a real
// workflow.Engine invocation. Only the "fix" workflow itself is substituted -
// it is an externally-downloaded CLI extension, not a compiled dependency of
// snyk-ls - and it captures the exact provider/model config keys it receives
// instead of running an LLM, proving the real wiring rather than stubbing out
// buildRemyFixConfig/gafRunner themselves.
func (s *bddSteps) theDeveloperAsksSnykToFixAFolder(ctx context.Context) error {
	if err := s.ensureLspInitialized(ctx); err != nil {
		return err
	}

	repoDir, err := createGitRepoForFix(s.scenarioT)
	if err != nil {
		return fmt.Errorf("failed to create git repo for fix: %w", err)
	}

	fixWorkflowID := workflow.NewWorkflowIdentifier("fix")
	if _, ok := s.engine.GetWorkflow(fixWorkflowID); !ok {
		flagset := workflow.ConfigurationOptionsFromFlagset(pflag.NewFlagSet("", pflag.ContinueOnError))
		callback := func(invocation workflow.InvocationContext, _ []workflow.Data) ([]workflow.Data, error) {
			s.fixCapturedProvider = invocation.GetConfiguration().GetString("provider")
			s.fixCapturedModel = invocation.GetConfiguration().GetString("model")
			return nil, nil
		}
		if _, err := s.engine.Register(fixWorkflowID, flagset, callback); err != nil {
			return fmt.Errorf("failed to register test fix workflow: %w", err)
		}
	}

	folderURI := string(uri.PathToUri(types.FilePath(repoDir)))
	_, callErr := s.loc.Client.Call(ctx, "workspace/executeCommand", sglsp.ExecuteCommandParams{
		Command:   types.RemediationAgentFixFolderCommand,
		Arguments: []any{folderURI},
	})
	s.fixCommandErr = callErr
	return nil
}

func (s *bddSteps) theFixRunsWithTheChosenProviderAndModel() error {
	if s.fixCommandErr != nil {
		return fmt.Errorf("snyk.remediationAgent.fixFolder call failed: %w", s.fixCommandErr)
	}
	if s.fixCapturedProvider != s.savedLlmProvider {
		return fmt.Errorf("expected the fix workflow to receive provider %q, got %q", s.savedLlmProvider, s.fixCapturedProvider)
	}
	if s.fixCapturedModel != s.savedLlmModel {
		return fmt.Errorf("expected the fix workflow to receive model %q, got %q", s.savedLlmModel, s.fixCapturedModel)
	}
	return nil
}

func (s *bddSteps) developerHasEstablishedBaselineForProduct(productName string) error {
	var p product.Product
	switch productName {
	case "Code":
		p = product.ProductCode
	case "Open Source":
		p = product.ProductOpenSource
	default:
		return fmt.Errorf("unknown product: %q", productName)
	}

	fileDir := types.FilePath(s.scenarioT.TempDir())
	filePath := types.FilePath(filepath.Join(string(fileDir), "app.go"))
	s.deltaFileDir = fileDir
	s.deltaFilePath = filePath

	if err := s.scanPersister.Init([]types.FilePath{fileDir}); err != nil {
		return err
	}

	knownIssue := &snyk.Issue{
		ID:               "known-issue",
		AffectedFilePath: filePath,
		Severity:         types.Medium,
		Product:          p,
		Message:          fmt.Sprintf("known %s issue", productName),
		AdditionalData:   snyk.CodeIssueData{Key: "key-known"},
	}
	return s.scanPersister.Add(fileDir, "baseline-1", []types.Issue{knownIssue}, p)
}

// developerSavesFileWithProductIssues puts each product's issue on its own file.
// documentDiagnosticCache is keyed by file path only and holds every product's
// issues for that path together (see updateGlobalCacheAndSeverityCounts), so two
// products scanning the very same path in sequence would overwrite each other's
// entries - an unrelated, pre-existing cache bug this scenario must not depend on.
func (s *bddSteps) developerSavesFileWithProductIssues(product1, product2 string) error {
	var p1, p2 product.Product
	switch product1 {
	case "Code":
		p1 = product.ProductCode
	case "Open Source":
		p1 = product.ProductOpenSource
	default:
		return fmt.Errorf("unknown product: %q", product1)
	}
	switch product2 {
	case "Code":
		p2 = product.ProductCode
	case "Open Source":
		p2 = product.ProductOpenSource
	default:
		return fmt.Errorf("unknown product: %q", product2)
	}

	filePath := s.deltaFilePath
	if filePath == "" {
		filePath = types.FilePath(filepath.Join(string(s.deltaFileDir), "app.go"))
	}

	ossFilePath := types.FilePath(filepath.Join(string(s.deltaFileDir), "package.json"))
	s.deltaOssFilePath = ossFilePath

	newIssue1 := &snyk.Issue{
		ID:               fmt.Sprintf("new-%s-issue", strings.ToLower(product1)),
		AffectedFilePath: filePath,
		Severity:         types.High,
		Product:          p1,
		Message:          fmt.Sprintf("newly introduced %s issue", product1),
		AdditionalData:   snyk.CodeIssueData{Key: fmt.Sprintf("key-new-%s", strings.ToLower(product1))},
	}

	knownIssue := &snyk.Issue{
		ID:               "known-issue",
		AffectedFilePath: filePath,
		Severity:         types.Medium,
		Product:          p1,
		Message:          fmt.Sprintf("known %s issue", product1),
		AdditionalData:   snyk.CodeIssueData{Key: "key-known"},
	}

	newIssue2 := &snyk.Issue{
		ID:               fmt.Sprintf("new-%s-issue", strings.ToLower(product2)),
		AffectedFilePath: ossFilePath,
		Severity:         types.High,
		Product:          p2,
		Message:          fmt.Sprintf("issue from %s without a baseline", product2),
		AdditionalData:   snyk.OssIssueData{},
	}

	return s.runScanWithFakeScanner(&bddFakeScanner{scans: []types.ScanData{
		{Product: p1, Issues: []types.Issue{newIssue1, knownIssue}},
		{Product: p2, Issues: []types.Issue{newIssue2}},
	}})
}

func (s *bddSteps) editorNotifiedOfBothProductIssues(product1, product2 string) error {
	var filePath1 types.FilePath
	var filePath2 types.FilePath

	switch product1 {
	case "Code":
		filePath1 = s.deltaFilePath
	case "Open Source":
		filePath1 = s.deltaOssFilePath
	default:
		return fmt.Errorf("unknown product: %q", product1)
	}

	switch product2 {
	case "Code":
		filePath2 = s.deltaFilePath
	case "Open Source":
		filePath2 = s.deltaOssFilePath
	default:
		return fmt.Errorf("unknown product: %q", product2)
	}

	var diagnostics1, diagnostics2 []types.Diagnostic
	found := s.awaitCondition(func() bool {
		var ok bool
		diagnostics1, ok = s.findPublishedDiagnostics(filePath1)
		return ok && len(diagnostics1) >= 1
	})
	if !found {
		return fmt.Errorf("expected a publishDiagnostics notification for %s with a %s issue, got none", filePath1, product1)
	}

	found = s.awaitCondition(func() bool {
		var ok bool
		diagnostics2, ok = s.findPublishedDiagnostics(filePath2)
		return ok && len(diagnostics2) >= 1
	})
	if !found {
		return fmt.Errorf("expected a publishDiagnostics notification for %s with a %s issue, got none", filePath2, product2)
	}

	return nil
}

// createGitRepoForFix creates a minimal git repo in a temp dir so
// snyk.remediationAgent.fixFolder's git-repo-root and clean-worktree guards
// are satisfied. Returns the CANONICAL path (symlinks resolved) so it agrees
// with what git and the production code resolve.
func createGitRepoForFix(t *testing.T) (string, error) {
	t.Helper()
	dir := t.TempDir()
	if canonical, err := filepath.EvalSymlinks(dir); err == nil {
		dir = canonical
	}
	run := func(args ...string) error {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("git %v: %w (%s)", args, err, out)
		}
		return nil
	}
	for _, args := range [][]string{
		{"init"},
		{"config", "user.email", "test@example.com"},
		{"config", "user.name", "Test"},
		{"config", "core.checkStat", "minimal"},
	} {
		if err := run(args...); err != nil {
			return "", err
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n"), 0o600); err != nil {
		return "", err
	}
	if err := run("add", "."); err != nil {
		return "", err
	}
	if err := run("commit", "-m", "init"); err != nil {
		return "", err
	}
	return dir, nil
}

// Test_BDDSteps_PerScenarioCleanup proves setupServer's t.Cleanup fires once
// per scenario (via the sc.Before/sc.After t.Run bridge in beforeScenario/
// afterScenario), not once for the whole TestBDD run. It drives two
// scenarios' lifecycles directly against the real bddSteps/setupServer code
// path and asserts the first scenario's server connection is already closed
// before the second scenario starts.
func Test_BDDSteps_PerScenarioCleanup(t *testing.T) {
	s := newBDDSteps(t)
	ctx := context.Background()

	ctx, err := s.beforeScenario(ctx, &godog.Scenario{Name: "scenario one"})
	require.NoError(t, err)
	require.NoError(t, s.startLanguageServer())
	firstClient := s.loc.Client

	_, err = s.afterScenario(ctx, &godog.Scenario{Name: "scenario one"}, nil)
	require.NoError(t, err)

	assert.True(t, firstClient.IsStopped(), "expected scenario one's server to be torn down before scenario two starts")

	ctx, err = s.beforeScenario(ctx, &godog.Scenario{Name: "scenario two"})
	require.NoError(t, err)
	require.NoError(t, s.startLanguageServer())
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
