package server

import (
	"context"
	"fmt"
	"testing"

	"github.com/creachadair/jrpc2/server"
	"github.com/cucumber/godog"

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
// ponytail: every step reuses the suite-level *testing.T (setupServer's
// t.Cleanup calls all run at TestBDD's end, not per scenario). Fine while
// harness.feature has one scenario; if a later feature file's scenario count
// makes that a resource problem, close loc explicitly in an AfterScenario hook.
type bddSteps struct {
	t *testing.T

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
	sc.Given(`^a running language server$`, s.aRunningLanguageServer)
	sc.When(`^the editor sends the initialize request$`, s.theEditorSendsTheInitializeRequest)
	sc.Then(`^the server responds with its capabilities$`, s.theServerRespondsWithItsCapabilities)
}

func (s *bddSteps) aRunningLanguageServer() error {
	engine, tokenService := testutil.UnitTestWithEngine(s.t)
	loc, jsonRPCRecorder, _ := setupServer(s.t, engine, tokenService)
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
