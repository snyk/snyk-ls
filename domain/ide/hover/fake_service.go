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

package hover

import (
	sglsp "github.com/sourcegraph/go-lsp"

	ux2 "github.com/snyk/snyk-ls/domain/observability/ux"
)

type FakeHoverService struct {
	hovers chan DocumentHovers
	calls  int
}

func NewFakeHoverService() *FakeHoverService {
	return &FakeHoverService{
		calls:  0,
		hovers: make(chan DocumentHovers, 10000),
	}
}

func (t *FakeHoverService) DeleteHover(_ sglsp.DocumentURI) {
	//TODO implement me
	panic("implement me")
}

func (t *FakeHoverService) Channel() chan DocumentHovers {
	t.calls++
	return t.hovers
}

func (t *FakeHoverService) ClearAllHovers() {
	for len(t.hovers) > 0 {
		<-t.hovers
	}
}

func (t *FakeHoverService) GetHover(_ sglsp.DocumentURI, pos sglsp.Position) Result {
	//TODO implement me
	panic("implement me")
}

func (t *FakeHoverService) SetAnalytics(_ ux2.Analytics) {
	//TODO implement me
	panic("implement me")
}

func (t *FakeHoverService) Calls() int {
	return t.calls
}
