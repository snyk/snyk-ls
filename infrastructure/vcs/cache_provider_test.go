package vcs

import (
	"github.com/google/uuid"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_LoadCache(t *testing.T) {
	cp := CurrentCache()
	issueList := []snyk.Issue{
		{
			GlobalIdentity: uuid.New().String(),
		},
	}

	err := cp.LoadCache()
	err = cp.AddToCache("C:\\Users\\shawky\\work\\snyk-ls", "eab0f18c4432b2a41e0f8e6c9831fe84be92b3db", issueList)

	assert.Nil(t, err)
}
