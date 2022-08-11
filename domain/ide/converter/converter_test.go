package converter

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/testutil"
)

func TestToHovers(t *testing.T) {
	testutil.UnitTest(t)
	testIssue := snyk.Issue{FormattedMessage: "<br><br/><br />"}
	hovers := ToHovers([]snyk.Issue{testIssue})
	assert.Equal(t, "\n\n\n\n\n\n", hovers[0].Message)
}
