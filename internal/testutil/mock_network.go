/*
 * © 2025 Snyk Limited
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

package testutil

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/golang/mock/gomock"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
)

// MockTransport is an HTTP transport that fails on any real request
type MockTransport struct {
	t *testing.T
}

func (m *MockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Use Errorf instead of Fatalf to avoid panic in goroutines after test completion
	m.t.Errorf("mock transport: attempted real HTTP call to %s in unit test - this should not happen", req.URL)
	return nil, fmt.Errorf("mock transport: attempted real HTTP call to %s in unit test", req.URL)
}

// createMockHTTPClient creates an HTTP client that fails on any real request
func createMockHTTPClient(t *testing.T) *http.Client {
	t.Helper()
	return &http.Client{
		Transport: &MockTransport{t: t},
	}
}

// SetupEngineMockWithNetworkAccess creates a mock engine with mock network access
// that prevents real HTTP calls in unit tests
func SetupEngineMockWithNetworkAccess(t *testing.T) (*mocks.MockEngine, configuration.Configuration) {
	t.Helper()
	ctrl := gomock.NewController(t)
	mockEngine := mocks.NewMockEngine(ctrl)
	engineConfig := configuration.NewWithOpts(configuration.WithAutomaticEnv())

	// Mock GetConfiguration
	mockEngine.EXPECT().GetConfiguration().Return(engineConfig).AnyTimes()

	// Mock GetLogger - return nil as the engine logger is optional
	mockEngine.EXPECT().GetLogger().Return(nil).AnyTimes()

	// Mock SetLogger (called during config initialization)
	mockEngine.EXPECT().SetLogger(gomock.Any()).AnyTimes()

	// Create mock network access
	mockNetworkAccess := mocks.NewMockNetworkAccess(ctrl)
	mockHTTPClient := createMockHTTPClient(t)

	// Mock network access methods to return our mock HTTP client
	mockNetworkAccess.EXPECT().GetHttpClient().Return(mockHTTPClient).AnyTimes()
	mockNetworkAccess.EXPECT().GetUnauthorizedHttpClient().Return(mockHTTPClient).AnyTimes()
	mockNetworkAccess.EXPECT().AddHeaderField(gomock.Any(), gomock.Any()).AnyTimes()

	// Mock GetNetworkAccess to return our mock network access
	mockEngine.EXPECT().GetNetworkAccess().Return(mockNetworkAccess).AnyTimes()

	// Mock Init
	mockEngine.EXPECT().Init().Return(nil).AnyTimes()

	// Mock GetRuntimeInfo (can return nil for tests)
	mockEngine.EXPECT().GetRuntimeInfo().Return(nil).AnyTimes()

	// Mock SetRuntimeInfo
	mockEngine.EXPECT().SetRuntimeInfo(gomock.Any()).AnyTimes()

	return mockEngine, engineConfig
}
