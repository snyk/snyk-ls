/*
 * © 2022 Snyk Limited All rights reserved.
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

package performance

import (
	"context"
	"errors"

	context2 "github.com/snyk/snyk-ls/internal/context"
)

// GetContextWithTraceId Returns a child context with "trace_id" set to the given traceId
func GetContextWithTraceId(ctx context.Context, traceId string) context.Context {
	return context.WithValue(ctx, context2.TraceID("trace_id"), traceId)
}

func GetTraceId(ctx context.Context) (string, error) {
	v, ok := ctx.Value(context2.TraceID("trace_id")).(string)
	if !ok {
		return "", errors.New("\"trace_id\" context key not found")
	}

	return v, nil
}
