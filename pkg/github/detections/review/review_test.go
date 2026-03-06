package review

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/trajan/pkg/analysis"
	"github.com/praetorian-inc/trajan/pkg/detections"
)

// TestReviewInjection_Vulnerable_PullRequestReview tests detection of review.body injection
func TestReviewInjection_Vulnerable_PullRequestReview(t *testing.T) {
	workflow := `
name: Review Handler
on: pull_request_review
jobs:
  process:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.review.body }}"
`

	g, err := analysis.BuildGraph("owner/repo", "review.yml", []byte(workflow))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	require.Len(t, findings, 1)
	assert.Equal(t, detections.VulnReviewInjection, findings[0].Type)
	assert.Equal(t, detections.SeverityHigh, findings[0].Severity)
	assert.Contains(t, findings[0].Evidence, "github.event.review.body")
}

// TestReviewInjection_Vulnerable_ReviewComment tests detection of review_comment.body injection
func TestReviewInjection_Vulnerable_ReviewComment(t *testing.T) {
	workflow := `
name: Comment Handler
on: pull_request_review_comment
jobs:
  process:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.review_comment.body }}"
`

	g, err := analysis.BuildGraph("owner/repo", "comment.yml", []byte(workflow))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	require.Len(t, findings, 1)
	assert.Equal(t, detections.VulnReviewInjection, findings[0].Type)
	assert.Equal(t, detections.SeverityHigh, findings[0].Severity)
	assert.Contains(t, findings[0].Evidence, "github.event.review_comment.body")
}

// TestReviewInjection_Safe_NoInjection tests that safe workflows are not flagged
func TestReviewInjection_Safe_NoInjection(t *testing.T) {
	workflow := `
name: Safe Review Handler
on: pull_request_review
jobs:
  process:
    runs-on: ubuntu-latest
    steps:
      - run: echo "Processing review"
`

	g, err := analysis.BuildGraph("owner/repo", "safe.yml", []byte(workflow))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	require.Len(t, findings, 0, "Expected no findings for safe workflow")
}
