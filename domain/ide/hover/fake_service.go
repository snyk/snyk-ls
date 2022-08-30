package hover

import (
	sglsp "github.com/sourcegraph/go-lsp"

	ux2 "github.com/snyk/snyk-ls/domain/observability/ux"
)

type FakeHoverService struct {
	hovers chan DocumentHovers
}

func NewFakeHoverService() *FakeHoverService {
	return &FakeHoverService{
		hovers: make(chan DocumentHovers, 10000),
	}
}

func (t FakeHoverService) DeleteHover(documentUri sglsp.DocumentURI) {
	//TODO implement me
	panic("implement me")
}

func (t FakeHoverService) Channel() chan DocumentHovers {
	return t.hovers
}

func (t FakeHoverService) ClearAllHovers() {
	for len(t.hovers) > 0 {
		<-t.hovers
	}
}

func (t FakeHoverService) GetHover(fileUri sglsp.DocumentURI, pos sglsp.Position) Result {
	//TODO implement me
	panic("implement me")
}

func (t FakeHoverService) SetAnalytics(analytics ux2.Analytics) {
	//TODO implement me
	panic("implement me")
}
