package router

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLookupOrgByIP_Success(t *testing.T) {
	org, err := lookupOrgByIP("8.8.8.8")
	assert.NoError(t, err)
	assert.Equal(t, "Google LLC", *org)
}

func TestLookupOrgByIP_Failure(t *testing.T) {
	org, err := lookupOrgByIP("fail")
	assert.Error(t, err)
	assert.Nil(t, org)
}
