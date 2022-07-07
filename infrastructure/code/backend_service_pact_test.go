package code

import (
	"context"
	"fmt"
	"testing"

	"github.com/pact-foundation/pact-go/dsl"
	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/domain/observability/error_reporting"
	"github.com/snyk/snyk-ls/domain/observability/performance"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/util"
)

const (
	consumer     = "SnykLS"
	pactDir      = "./pacts"
	pactProvider = "SnykCodeApi"

	uuidMatcher = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
)

// Common test data
var pact dsl.Pact
var client *SnykCodeHTTPClient

func TestSnykCodeBackendServicePact(t *testing.T) { // nolint:gocognit // this is a test wrapper function
	testutil.NotOnWindows(t, "we don't have a pact cli")
	testutil.UnitTest(t)

	setupPact()
	defer pact.Teardown()

	defer func() {
		if err := pact.WritePact(); err != nil {
			t.Fatal(err)
		}
	}()

	t.Run("Create bundle", func(t *testing.T) {
		pact.AddInteraction().Given("New bundle").UponReceiving("Create bundle").WithRequest(dsl.Request{
			Method:  "POST",
			Path:    dsl.String("/bundle"),
			Headers: getPutPostHeaderMatcher(),
			Body:    getPutPostBodyMatcher(),
		}).WillRespondWith(dsl.Response{
			Status: 200,
			Headers: dsl.MapMatcher{
				"Content-Type": dsl.String("application/json"),
			},
			Body: dsl.Match(bundleResponse{}),
		})

		test := func() error {
			files := make(map[string]string)
			files[path1] = util.Hash([]byte(content))
			bundleHash, missingFiles, err := client.CreateBundle(context.Background(), files)

			if err != nil {
				return err
			}
			if bundleHash == "" {
				return fmt.Errorf("bundleHash is null")
			}
			if len(missingFiles) == 0 {
				return fmt.Errorf("missingFiles are empty")
			}

			return nil
		}

		err := pact.Verify(test)

		if err != nil {
			t.Fatalf("Error on verify: %v", err)
		}
	})

	t.Run("Extend bundle", func(*testing.T) {
		bundleHash := "faa6b7161c14f933ef4ca79a18ad9283eab362d5e6d3a977125eb95b37c377d8"

		pact.AddInteraction().Given("Existing bundle").UponReceiving("Extend bundle").WithRequest(dsl.Request{
			Method:  "PUT",
			Path:    dsl.Term("/bundle/"+bundleHash, "/bundle/[A-Fa-f0-9]{64}"),
			Headers: getPutPostHeaderMatcher(),
			Body:    getPutPostBodyMatcher(),
		}).WillRespondWith(dsl.Response{
			Status: 200,
			Headers: dsl.MapMatcher{
				"Content-Type": dsl.String("application/json"),
			},
			Body: dsl.Match(bundleResponse{}),
		})

		test := func() error {
			filesExtend := createTestExtendMap()
			var removedFiles []string

			bundleHash, missingFiles, err := client.ExtendBundle(context.Background(), bundleHash, filesExtend, removedFiles)

			if err != nil {
				return err
			}
			if bundleHash == "" {
				return fmt.Errorf("bundleHash is null")
			}
			if len(missingFiles) == 0 {
				return fmt.Errorf("missingFiles are empty")
			}

			return nil
		}

		err := pact.Verify(test)

		if err != nil {
			t.Fatalf("Error on verify: %v", err)
		}
	})

	t.Run("Analysis", func(*testing.T) {
		bundleHash := "faa6b7161c14f933ef4ca79a18ad9283eab362d5e6d3a977125eb95b37c377d8"

		pact.AddInteraction().Given("Existing bundle").UponReceiving("Run analysis").WithRequest(dsl.Request{
			Method:  "POST",
			Path:    dsl.String("/analysis"),
			Headers: getPutPostHeaderMatcher(),
			Body:    getPutPostBodyMatcher(),
		}).WillRespondWith(dsl.Response{
			Status: 200,
			Headers: dsl.MapMatcher{
				"Content-Type": dsl.String("application/json"),
			},
			Body: dsl.Match(SarifResponse{}),
		})

		test := func() error {
			analysisOptions := AnalysisOptions{
				bundleHash:   bundleHash,
				shardKey:     "shardKey",
				limitToFiles: []sglsp.DocumentURI{},
				severity:     0,
			}

			issues, _, err := client.RunAnalysis(context.Background(), analysisOptions)

			if err != nil {
				return err
			}
			if issues != nil {
				returnValue := assert.NotEqual(t, 0, len(issues))
				if returnValue {
					return fmt.Errorf("Issues length is not 0")
				}
			}

			return nil
		}

		err := pact.Verify(test)

		if err != nil {
			t.Fatalf("Error on verify: %v", err)
		}
	})

	t.Run("Get filters", func(*testing.T) {
		pact.AddInteraction().UponReceiving("Get filters").WithRequest(dsl.Request{
			Method: "GET",
			Path:   dsl.String("/filters"),
			Headers: dsl.MapMatcher{
				"Content-Type":    dsl.String("application/json"),
				"snyk-request-id": getSnykRequestIdMatcher(),
			},
		}).WillRespondWith(dsl.Response{
			Status: 200,
			Headers: dsl.MapMatcher{
				"Content-Type": dsl.String("application/json"),
			},
			Body: dsl.Match(filtersResponse{}),
		})

		test := func() error {
			if _, _, err := client.GetFilters(context.Background()); err != nil {
				return err
			}

			return nil
		}

		err := pact.Verify(test)

		assert.NoError(t, err)
	})
}

func setupPact() {
	pact = dsl.Pact{
		Consumer: consumer,
		Provider: pactProvider,
		PactDir:  pactDir,
	}

	// Proactively start service to get access to the port
	pact.Setup(true)

	client = NewHTTPRepository(fmt.Sprintf("http://localhost:%d", pact.Server.Port), performance.NewTestInstrumentor(), error_reporting.NewTestErrorReporter())
}

func getPutPostHeaderMatcher() dsl.MapMatcher {
	return dsl.MapMatcher{
		"Content-Type":     dsl.String("application/octet-stream"),
		"Content-Encoding": dsl.String("gzip"),
		"Session-Token":    dsl.Regex("fc763eba-0905-41c5-a27f-3934ab26786c", uuidMatcher),
		"snyk-request-id":  getSnykRequestIdMatcher(),
	}
}

func getPutPostBodyMatcher() dsl.Matcher {
	return dsl.Like(make([]byte, 1))
}

func getSnykRequestIdMatcher() dsl.Matcher {
	return dsl.Regex("fc763eba-0905-41c5-a27f-3934ab26786c", uuidMatcher)
}
