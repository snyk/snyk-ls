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

package types_test

import (
	"testing"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"

	"github.com/snyk/snyk-ls/internal/types"
)

func newResolverForBench(b *testing.B) (*types.ConfigResolver, configuration.Configuration) {
	b.Helper()
	conf := configuration.NewWithOpts()
	fs := pflag.NewFlagSet("bench", pflag.ContinueOnError)
	types.RegisterAllConfigurations(fs)
	if err := conf.AddFlagSet(fs); err != nil {
		b.Fatalf("AddFlagSet: %v", err)
	}
	fm := workflow.ConfigurationOptionsFromFlagset(fs)
	prefixKeyResolver := configresolver.New(conf, fm)
	logger := zerolog.Nop()
	resolver := types.NewConfigResolver(&logger)
	resolver.SetPrefixKeyResolver(prefixKeyResolver, conf, fm)
	return resolver, conf
}

func BenchmarkGetBool(b *testing.B) {
	resolver, _ := newResolverForBench(b)
	fc := &types.FolderConfig{FolderPath: "/bench/folder"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = resolver.GetBool(types.SettingSnykOssEnabled, fc)
	}
}

func BenchmarkDisplayableIssueTypesForFolder(b *testing.B) {
	resolver, _ := newResolverForBench(b)
	fc := &types.FolderConfig{FolderPath: "/bench/folder"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = resolver.DisplayableIssueTypesForFolder(fc)
	}
}
