package server

import (
	"context"
	"fmt"
	"runtime"
	"testing"
	"time"

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
//
// godog invokes registered Given/When/Then functions on its own goroutine,
// which is not the goroutine s.t.Run spawns to own scenarioT. Step bodies
// route through runOnScenarioGoroutine (via stepFunc/stepResult) specifically
// because they call helpers (testutil.UnitTestWithEngine, setupServer) that
// take scenarioT and can call t.Fatal/t.FailNow on it: FailNow's
// runtime.Goexit only unwinds the goroutine that called it, so calling it
// directly from godog's goroutine would Goexit the wrong goroutine and hang
// the scenario's own goroutine forever instead of failing the subtest.
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

	initResult types.InitializeResult
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
}

// beforeScenario gives the upcoming scenario its own *testing.T by running it
// as a subtest of the suite-level T. The subtest function loops, executing
// step bodies handed to it over stepFunc, until scenarioDone is closed, so
// subtest-registered t.Cleanup callbacks (e.g. setupServer's) fire per
// scenario instead of only once at the end of TestBDD.
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

// afterScenario unblocks the subtest spawned by beforeScenario and waits for
// it (and any t.Cleanup it registered) to finish before the next scenario
// starts.
func (s *bddSteps) afterScenario(ctx context.Context, sc *godog.Scenario, err error) (context.Context, error) {
	close(s.scenarioDone)
	<-s.scenarioDied
	return ctx, err
}

// runStep executes fn on the goroutine that owns scenarioT (see
// beforeScenario) and reports its result over stepResult. If fn reaches
// scenarioT.Fatal/FailNow, runtime.Goexit unwinds this call without fn ever
// returning; the deferred send below still runs (Goexit always runs deferred
// calls while unwinding the goroutine), so runOnScenarioGoroutine's caller is
// unblocked with an error instead of hanging forever.
func (s *bddSteps) runStep(fn func() error) {
	reported := false
	defer func() {
		if !reported {
			s.stepResult <- fmt.Errorf("step aborted: scenario T.Fatal/FailNow was called")
		}
	}()
	err := fn()
	reported = true
	s.stepResult <- err
}

// runOnScenarioGoroutine hands fn to the scenario's own goroutine and blocks
// for its result. Step definitions that pass s.scenarioT into helpers which
// may call t.Fatal (testutil.UnitTestWithEngine, setupServer) must go through
// this instead of running directly on godog's goroutine - see the bddSteps
// doc comment.
func (s *bddSteps) runOnScenarioGoroutine(fn func() error) error {
	s.stepFunc <- fn
	return <-s.stepResult
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

// Test_BDDSteps_RunOnScenarioGoroutine_SurvivesGoexit proves that a step body
// which reaches t.Fatal/t.FailNow through helpers like setupServer or
// testutil.UnitTestWithEngine (both take scenarioT and can fail it) does not
// hang the suite. FailNow's runtime.Goexit only unwinds the goroutine that
// called it, so running the step body on a goroutine other than the one that
// owns scenarioT (the one godog's ScenarioContext hooks run step definitions
// on, vs. the one s.t.Run spawned for scenarioT) would Goexit the wrong
// goroutine and leave the scenario's own goroutine blocked forever. This
// simulates that failure with a bare runtime.Goexit (standing in for
// t.Fatal's implementation) and asserts runOnScenarioGoroutine still reports
// an error instead of hanging.
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

// Test_BDDSteps_RunOnScenarioGoroutine_ReturnsStepResult proves the normal,
// non-failing path is unaffected by the goroutine bridge: the step's actual
// return value reaches the caller unchanged.
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
