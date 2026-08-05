package server

import (
	"context"
	"fmt"
	"testing"

	"github.com/creachadair/jrpc2/server"
	"github.com/cucumber/godog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/testsupport"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

// bddSteps is the shared step registry for every .feature file in this
// repository. One instance is created per scenario (see TestBDD), so no
// state leaks between scenarios. Steps drive the real language server via
// the existing unexported test harness (setupServer, testutil.UnitTestWithEngine,
// testsupport.JsonRPCRecorder) instead of a second, divergent one.
//
// Each scenario gets its own *testing.T (scenarioT), created via a t.Run
// bridge in beforeScenario/afterScenario, so setupServer's t.Cleanup fires
// when that one scenario ends rather than piling up until TestBDD returns.
type bddSteps struct {
	t *testing.T // suite-level T, used only to spawn per-scenario subtests

	scenarioT    *testing.T
	scenarioDone chan struct{}
	scenarioDied chan struct{}

	engine          workflow.Engine
	loc             server.Local
	jsonRPCRecorder *testsupport.JsonRPCRecorder

	initResult types.InitializeResult
}

func newBDDSteps(t *testing.T) *bddSteps {
	t.Helper()
	return &bddSteps{t: t}
}

func (s *bddSteps) register(sc *godog.ScenarioContext) {
	sc.Before(s.beforeScenario)
	sc.After(s.afterScenario)
	sc.Given(`^a running language server$`, s.aRunningLanguageServer)
	sc.When(`^the editor sends the initialize request$`, s.theEditorSendsTheInitializeRequest)
	sc.Then(`^the server responds with its capabilities$`, s.theServerRespondsWithItsCapabilities)
}

// beforeScenario gives the upcoming scenario its own *testing.T by running it
// as a subtest of the suite-level T. The subtest function blocks on
// scenarioDone, which afterScenario closes once the scenario's steps have
// run, so subtest-registered t.Cleanup callbacks (e.g. setupServer's) fire
// per scenario instead of only once at the end of TestBDD.
func (s *bddSteps) beforeScenario(ctx context.Context, sc *godog.Scenario) (context.Context, error) {
	ready := make(chan struct{})
	s.scenarioDone = make(chan struct{})
	s.scenarioDied = make(chan struct{})

	go func() {
		defer close(s.scenarioDied)
		s.t.Run(sc.Name, func(subT *testing.T) {
			s.scenarioT = subT
			close(ready)
			<-s.scenarioDone
		})
	}()
	<-ready
	return ctx, nil
}

// afterScenario unblocks the subtest spawned by beforeScenario and waits for
// it (and any t.Cleanup it registered) to finish before the next scenario
// starts.
func (s *bddSteps) afterScenario(ctx context.Context, sc *godog.Scenario, err error) (context.Context, error) {
	close(s.scenarioDone)
	<-s.scenarioDied
	return ctx, err
}

func (s *bddSteps) aRunningLanguageServer() error {
	engine, tokenService := testutil.UnitTestWithEngine(s.scenarioT)
	loc, jsonRPCRecorder, _ := setupServer(s.scenarioT, engine, tokenService)
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
	if s.initResult.ServerInfo.Name == "" {
		return fmt.Errorf("expected server info to be populated, got %+v", s.initResult.ServerInfo)
	}
	if s.initResult.ServerInfo.Version != config.LsProtocolVersion {
		return fmt.Errorf("expected protocol version %q, got %q", config.LsProtocolVersion, s.initResult.ServerInfo.Version)
	}
	if s.initResult.Capabilities.TextDocumentSync == nil {
		return fmt.Errorf("expected capabilities to be populated, got a zero value")
	}
	return nil
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
