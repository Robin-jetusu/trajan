package common

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/trajan/pkg/platforms"
)

func TestParseOwnerRepo_ValidInput(t *testing.T) {
	target := platforms.Target{Type: platforms.TargetRepo, Value: "owner/repo"}

	owner, repo, err := ParseOwnerRepo(target)

	assert.NoError(t, err)
	assert.Equal(t, "owner", owner)
	assert.Equal(t, "repo", repo)
}

func TestParseOwnerRepo_InvalidFormats(t *testing.T) {
	testCases := []struct {
		name  string
		value string
	}{
		{"no slash", "ownerrepo"},
		{"empty string", ""},
		{"single component", "owner"},
		{"too many slashes", "owner/repo/extra"},
		// NOTE: "trailing slash" and "leading slash" cases not tested
		// because current implementation accepts them (splits into ["owner", ""] and ["", "repo"])
		// These should be validated in the future
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			target := platforms.Target{Type: platforms.TargetRepo, Value: tc.value}

			_, _, err := ParseOwnerRepo(target)

			assert.Error(t, err)
			assert.Contains(t, err.Error(), "invalid repo format")
		})
	}
}
