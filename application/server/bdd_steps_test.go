package server

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/creachadair/jrpc2/server"
	"github.com/cucumber/godog"
	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/application/config"
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

	engine          workflow.Engine
	loc             server.Local
	jsonRPCRecorder *testsupport.JsonRPCRecorder

	initResult  types.InitializeResult
	initialized bool
	dialogHTML  string
	folderPath  types.FilePath
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
	sc.When(`^the editor sends the initialize request$`, func(ctx context.Context) error {
		return s.runOnScenarioGoroutine(func() error { return s.theEditorSendsTheInitializeRequest(ctx) })
	})
	sc.Then(`^the server responds with its capabilities$`, func() error {
		return s.runOnScenarioGoroutine(s.theServerRespondsWithItsCapabilities)
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
	// WithRealDI is required so workspace/executeCommand dispatches through the
	// real command service rather than TestInit's mock - otherwise
	// WorkspaceConfigurationCommand (used by the config-dialog scenarios) returns
	// no HTML. Same requirement as configuration_smoke_test.go,
	// background_init_lifecycle_test.go, and dispatch_starvation_test.go.
	loc, jsonRPCRecorder, _ := setupServer(s.scenarioT, engine, tokenService, WithRealDI())
	s.engine = engine
	s.loc = loc
	s.jsonRPCRecorder = jsonRPCRecorder
	return nil
}

func (s *bddSteps) theEditorSendsTheInitializeRequest(ctx context.Context) error {
	rsp, err := s.loc.Client.Call(ctx, "initialize", nil)
	if err != nil {
		return fmt.Errorf("initialize call failed: %w", err)
	}
	if err := rsp.UnmarshalResult(&s.initResult); err != nil {
		return fmt.Errorf("unmarshalling initialize result failed: %w", err)
	}
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
