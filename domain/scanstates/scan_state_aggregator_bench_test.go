/*
 * © 2026 Snyk Limited
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

package scanstates

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"

	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
)

func newBenchEngine(b *testing.B) workflow.Engine {
	b.Helper()
	ctrl := gomock.NewController(b)
	conf := configuration.NewWithOpts()
	fs := pflag.NewFlagSet("bench", pflag.ContinueOnError)
	types.RegisterAllConfigurations(fs)
	if err := conf.AddFlagSet(fs); err != nil {
		b.Fatalf("AddFlagSet: %v", err)
	}
	logger := zerolog.Nop()
	eng := mocks.NewMockEngine(ctrl)
	eng.EXPECT().GetConfiguration().Return(conf).AnyTimes()
	eng.EXPECT().GetLogger().Return(&logger).AnyTimes()
	return eng
}

func newBenchConfigResolver(b *testing.B, eng workflow.Engine) types.ConfigResolverInterface {
	b.Helper()
	conf := eng.GetConfiguration()
	fs := pflag.NewFlagSet("bench-resolver", pflag.ContinueOnError)
	types.RegisterAllConfigurations(fs)
	if err := conf.AddFlagSet(fs); err != nil {
		b.Fatalf("AddFlagSet: %v", err)
	}
	fm := workflow.ConfigurationOptionsFromFlagset(fs)
	prefixKeyResolver := configresolver.New(conf, fm)
	logger := zerolog.Nop()
	resolver := types.NewConfigResolver(&logger)
	resolver.SetPrefixKeyResolver(prefixKeyResolver, conf, fm)
	// Enable all products so they appear in scan states
	conf.Set(configresolver.UserGlobalKey(types.SettingSnykOssEnabled), true)
	conf.Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), true)
	conf.Set(configresolver.UserGlobalKey(types.SettingSnykIacEnabled), true)
	conf.Set(configresolver.UserGlobalKey(types.SettingSnykSecretsEnabled), true)
	return resolver
}

func BenchmarkStateSnapshot(b *testing.B) {
	eng := newBenchEngine(b)
	logger := zerolog.Nop()
	resolver := newBenchConfigResolver(b, eng)

	ctrl := gomock.NewController(b)
	emitter := NewMockScanStateChangeEmitter(ctrl)
	emitter.EXPECT().Emit(gomock.Any()).AnyTimes()

	agg := &ScanStateAggregator{
		referenceScanStates:        make(scanStateMap),
		workingDirectoryScanStates: make(scanStateMap),
		scanStateChangeEmitter:     emitter,
		conf:                       eng.GetConfiguration(),
		logger:                     &logger,
		engine:                     eng,
		configResolver:             resolver,
	}

	folders := []types.FilePath{"/bench/folder1", "/bench/folder2"}
	products := []product.Product{
		product.ProductOpenSource,
		product.ProductCode,
		product.ProductInfrastructureAsCode,
		product.ProductSecrets,
	}
	for _, f := range folders {
		for _, p := range products {
			key := folderProductKey{FolderPath: f, Product: p}
			agg.referenceScanStates[key] = &scanState{Status: InProgress}
			agg.workingDirectoryScanStates[key] = &scanState{Status: InProgress}
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = agg.StateSnapshot()
	}
}
