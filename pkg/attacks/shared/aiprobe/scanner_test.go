package aiprobe

import (
	"context"
	"testing"
	"time"

	"github.com/praetorian-inc/julius/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProbeEndpoints_EmptyList(t *testing.T) {
	results, err := ProbeEndpoints(context.Background(), nil, DefaultScanConfig())
	require.NoError(t, err)
	assert.Empty(t, results.Probed)
	assert.Empty(t, results.Endpoints)
	assert.Equal(t, 0, results.Summary.EndpointsDiscovered)
}

func TestProbeEndpoints_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	endpoints := []DiscoveredEndpoint{
		{URL: "http://unreachable.test:11434", Confidence: "high"},
	}

	_, err := ProbeEndpoints(ctx, endpoints, DefaultScanConfig())
	assert.ErrorIs(t, err, context.Canceled)
}

func TestSelectBestResult(t *testing.T) {
	tests := []struct {
		name     string
		results  []types.Result
		wantSvc  string
		wantSpec int
	}{
		{
			name: "single result",
			results: []types.Result{
				{Service: "ollama", Specificity: 80},
			},
			wantSvc:  "ollama",
			wantSpec: 80,
		},
		{
			name: "picks highest specificity",
			results: []types.Result{
				{Service: "generic-openai", Specificity: 25},
				{Service: "ollama", Specificity: 90},
				{Service: "vllm", Specificity: 50},
			},
			wantSvc:  "ollama",
			wantSpec: 90,
		},
		{
			name: "equal specificity keeps first",
			results: []types.Result{
				{Service: "svc-a", Specificity: 50},
				{Service: "svc-b", Specificity: 50},
			},
			wantSvc:  "svc-a",
			wantSpec: 50,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			best := selectBestResult(tt.results)
			assert.Equal(t, tt.wantSvc, best.Service)
			assert.Equal(t, tt.wantSpec, best.Specificity)
		})
	}
}

func TestComputeSummary(t *testing.T) {
	results := &ScanResults{
		Endpoints: []DiscoveredEndpoint{
			{URL: "http://a:11434"},
			{URL: "http://b:8000"},
			{URL: "http://c:4000"},
		},
		Probed: []ProbeResult{
			{Reachable: true, Service: "ollama"},
			{Reachable: true, Service: "vllm"},
			{Reachable: false, Service: ""},
		},
	}

	summary := computeSummary(results)
	assert.Equal(t, 3, summary.EndpointsDiscovered)
	assert.Equal(t, 3, summary.EndpointsProbed)
	assert.Equal(t, 2, summary.EndpointsReachable)
	assert.Equal(t, 2, summary.ServicesIdentified)
}

func TestComputeSummary_DuplicateServices(t *testing.T) {
	results := &ScanResults{
		Endpoints: []DiscoveredEndpoint{
			{URL: "http://a:11434"},
			{URL: "http://b:11434"},
		},
		Probed: []ProbeResult{
			{Reachable: true, Service: "ollama"},
			{Reachable: true, Service: "ollama"},
		},
	}

	summary := computeSummary(results)
	assert.Equal(t, 1, summary.ServicesIdentified, "same service on different hosts counts once")
}

func TestDefaultScanConfig(t *testing.T) {
	cfg := DefaultScanConfig()
	assert.Equal(t, 5*time.Second, cfg.Timeout)
	assert.Equal(t, 10, cfg.Concurrency)
}

func TestSelectBestResult_SingleResult(t *testing.T) {
	// Verify selectBestResult handles single-element slice correctly
	results := []types.Result{{Service: "ollama", Specificity: 80}}
	best := selectBestResult(results)
	assert.Equal(t, "ollama", best.Service)
	assert.Equal(t, 80, best.Specificity)
}

// Integration tests requiring network access and real AI services
// should be placed in a separate file with a //go:build integration
// directive at the top of that file.
