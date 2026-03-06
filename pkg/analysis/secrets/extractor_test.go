package secrets

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractSecrets_BasicWorkflow(t *testing.T) {
	yaml := `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
      - run: ./deploy.sh
        env:
          API_KEY: ${{ secrets.API_KEY }}
          DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}
`
	refs, err := ExtractSecrets("ci.yml", []byte(yaml))
	require.NoError(t, err)
	require.Len(t, refs, 3)

	names := make(map[string]bool)
	for _, ref := range refs {
		names[ref.Name] = true
	}
	assert.True(t, names["GITHUB_TOKEN"])
	assert.True(t, names["API_KEY"])
	assert.True(t, names["DEPLOY_TOKEN"])
}

func TestExtractSecrets_DuplicateSecrets(t *testing.T) {
	yaml := `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    env:
      TOKEN: ${{ secrets.GITHUB_TOKEN }}
    steps:
      - uses: actions/checkout@v4
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
`
	refs, err := ExtractSecrets("ci.yml", []byte(yaml))
	require.NoError(t, err)
	require.Len(t, refs, 1) // Deduplicated
	assert.Equal(t, "GITHUB_TOKEN", refs[0].Name)
	assert.Len(t, refs[0].Locations, 2) // Two locations tracked
}

func TestExtractSecrets_EmptyWorkflow(t *testing.T) {
	yaml := `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "no secrets"
`
	refs, err := ExtractSecrets("ci.yml", []byte(yaml))
	require.NoError(t, err)
	assert.Len(t, refs, 0)
}

func TestExtractSecrets_InvalidYAML(t *testing.T) {
	yaml := `invalid: yaml: content: [[[`
	_, err := ExtractSecrets("invalid.yml", []byte(yaml))
	assert.Error(t, err)
}

func TestExtractSecrets_SecretInRunCommand(t *testing.T) {
	yaml := `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "Deploying with ${{ secrets.DEPLOY_KEY }}"
          ./deploy.sh
`
	refs, err := ExtractSecrets("ci.yml", []byte(yaml))
	require.NoError(t, err)
	require.Len(t, refs, 1)
	assert.Equal(t, "DEPLOY_KEY", refs[0].Name)
}

func TestExtractSecrets_SecretInIfCondition(t *testing.T) {
	yaml := `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Deploy
        if: ${{ secrets.ENABLE_DEPLOY == 'true' }}
        run: ./deploy.sh
`
	refs, err := ExtractSecrets("ci.yml", []byte(yaml))
	require.NoError(t, err)
	require.Len(t, refs, 1)
	assert.Equal(t, "ENABLE_DEPLOY", refs[0].Name)
}

func TestExtractSecrets_BooleanAndExpression(t *testing.T) {
	yaml := `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Deploy
        if: ${{ secrets.PROD_KEY && secrets.STAGING_KEY }}
        run: ./deploy.sh
`
	refs, err := ExtractSecrets("ci.yml", []byte(yaml))
	require.NoError(t, err)
	require.Len(t, refs, 2)
	names := make(map[string]bool)
	for _, ref := range refs {
		names[ref.Name] = true
	}
	assert.True(t, names["PROD_KEY"])
	assert.True(t, names["STAGING_KEY"])
}

func TestExtractSecrets_BooleanOrExpression(t *testing.T) {
	yaml := `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    env:
      TOKEN: ${{ secrets.CUSTOM_TOKEN || 'default' }}
    steps:
      - run: ./deploy.sh
`
	refs, err := ExtractSecrets("ci.yml", []byte(yaml))
	require.NoError(t, err)
	require.Len(t, refs, 1)
	assert.Equal(t, "CUSTOM_TOKEN", refs[0].Name)
}

func TestExtractSecrets_NoFalsePositiveInLiteral(t *testing.T) {
	yaml := `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "This mentions secrets.TOKEN but is not a reference"
`
	refs, err := ExtractSecrets("ci.yml", []byte(yaml))
	require.NoError(t, err)
	// Should not extract secrets.TOKEN from plain string literal
	assert.Len(t, refs, 0)
}
