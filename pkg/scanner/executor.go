// pkg/scanner/executor.go
package scanner

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"

	"github.com/praetorian-inc/trajan/pkg/analysis"
	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/platforms"
)

// DetectionExecutor orchestrates plugin execution across workflows
type DetectionExecutor struct {
	plugins          []detections.Detection
	concurrency      int64
	cache            *ScanResultCache
	metadata         map[string]interface{} // Platform-level context (runners, etc.) — flows into per-workflow graphs
	instanceMetadata map[string]interface{} // Instance-level context (e.g., jenkins_client) — only used for instance-level detections
	mu               sync.Mutex             // Protects workflows map updates
}

// ExecutionResult contains findings and any errors encountered
type ExecutionResult struct {
	Findings []detections.Finding
	Errors   []error
}

// NewDetectionExecutor creates a new plugin executor with the given plugins
func NewDetectionExecutor(plugins []detections.Detection, concurrency int) *DetectionExecutor {
	if concurrency <= 0 {
		concurrency = 10 // Default from Chariot convention
	}
	return &DetectionExecutor{
		plugins:     plugins,
		concurrency: int64(concurrency),
		metadata:    make(map[string]interface{}),
	}
}

// SetMetadata sets platform-level context that will be passed to all graphs
func (e *DetectionExecutor) SetMetadata(key string, value interface{}) {
	if e.metadata == nil {
		e.metadata = make(map[string]interface{})
	}
	e.metadata[key] = value
}

// SetInstanceMetadata sets instance-level context used only for instance-level detections.
// Unlike SetMetadata, values set here do NOT flow into per-workflow graphs.
func (e *DetectionExecutor) SetInstanceMetadata(key string, value interface{}) {
	if e.instanceMetadata == nil {
		e.instanceMetadata = make(map[string]interface{})
	}
	e.instanceMetadata[key] = value
}

// Execute runs all plugins against workflows and returns findings with any errors
func (e *DetectionExecutor) Execute(ctx context.Context, workflows map[string][]platforms.Workflow) (*ExecutionResult, error) {
	g, gCtx := errgroup.WithContext(ctx)
	sem := semaphore.NewWeighted(e.concurrency)

	var mu sync.Mutex
	result := &ExecutionResult{
		Findings: make([]detections.Finding, 0),
		Errors:   make([]error, 0),
	}

	for repoSlug, wfs := range workflows {
		repoSlug := repoSlug // Capture loop variable
		wfs := wfs

		for _, wf := range wfs {
			wf := wf

			// Acquire semaphore before spawning goroutine
			if err := sem.Acquire(gCtx, 1); err != nil {
				return result, err
			}

			g.Go(func() error {
				defer sem.Release(1)
				defer func() {
					if r := recover(); r != nil {
						// Safety net: catch any panics that slip through
						panicErr := fmt.Errorf("panic in workflow execution for %s: %v", repoSlug, r)
						mu.Lock()
						result.Errors = append(result.Errors, panicErr)
						mu.Unlock()
						slog.Error("workflow execution panic",
							"repo", repoSlug,
							"panic", r)
					}
				}()

				// Check cache before executing
				if e.cache != nil {
					if cached, ok := e.cache.Get(repoSlug, wf.Path, string(wf.Content)); ok {
						mu.Lock()
						result.Findings = append(result.Findings, cached...)
						mu.Unlock()
						return nil
					}
				}

				findings, errs := e.executeOnWorkflow(gCtx, repoSlug, wf, workflows)

				// Store in cache
				if e.cache != nil {
					e.cache.Set(repoSlug, wf.Path, string(wf.Content), findings)
				}

				mu.Lock()
				result.Findings = append(result.Findings, findings...)
				result.Errors = append(result.Errors, errs...)
				mu.Unlock()

				// Log errors as warnings
				for _, err := range errs {
					slog.Warn("workflow execution error", "error", err)
				}

				return nil
			})
		}
	}

	if err := g.Wait(); err != nil {
		return result, err
	}

	// Run instance-level detections (e.g., Jenkins live detections that only
	// need platform metadata, not parsed workflow content).
	if len(e.instanceMetadata) > 0 {
		instanceGraph := graph.NewGraph()
		for k, v := range e.instanceMetadata {
			instanceGraph.SetMetadata(k, v)
		}
		for _, plugin := range e.plugins {
			pFindings, err := plugin.Detect(ctx, instanceGraph)
			if err != nil {
				slog.Warn("instance-level detection error", "plugin", plugin.Name(), "error", err)
				continue
			}
			result.Findings = append(result.Findings, pFindings...)
		}
	}

	return result, nil
}

// executeOnWorkflow returns findings and any errors encountered
// Also extracts included workflows from graph and adds them to workflows map
func (e *DetectionExecutor) executeOnWorkflow(ctx context.Context, repoSlug string, wf platforms.Workflow, workflows map[string][]platforms.Workflow) ([]detections.Finding, []error) {
	var findings []detections.Finding
	var errs []error

	// Merge executor metadata with workflow-specific metadata
	// Workflow metadata (e.g., gitlab_client) takes precedence
	mergedMetadata := make(map[string]interface{})
	for k, v := range e.metadata {
		mergedMetadata[k] = v
	}
	if wf.Metadata != nil {
		for k, v := range wf.Metadata {
			mergedMetadata[k] = v
		}
	}

	graph, err := analysis.BuildGraph(repoSlug, wf.Path, wf.Content, mergedMetadata)
	if err != nil {
		return nil, []error{fmt.Errorf("building graph for %s/%s: %w", repoSlug, wf.Path, err)}
	}

	// Extract included workflows from graph and add to workflows map
	// This populates the map with workflows from external repositories
	includedWorkflows := graph.GetIncludedWorkflows(repoSlug)
	if len(includedWorkflows) > 0 {
		// Group workflows by repo slug
		workflowsByRepo := make(map[string][]platforms.Workflow)
		for _, incWf := range includedWorkflows {
			workflowsByRepo[incWf.RepoSlug] = append(workflowsByRepo[incWf.RepoSlug], incWf)
		}

		// Thread-safe append to workflows map
		e.mu.Lock()
		for slug, wfs := range workflowsByRepo {
			workflows[slug] = append(workflows[slug], wfs...)
		}
		e.mu.Unlock()
	}

	for _, plugin := range e.plugins {
		func() {
			defer func() {
				if r := recover(); r != nil {
					// Capture panic as an error - don't crash the scan
					errs = append(errs, fmt.Errorf("plugin %s on %s/%s: panic: %v", plugin.Name(), repoSlug, wf.Path, r))
					slog.Warn("plugin panic recovered",
						"plugin", plugin.Name(),
						"repo", repoSlug,
						"workflow", wf.Path,
						"panic", r)
				}
			}()

			pFindings, err := plugin.Detect(ctx, graph)
			if err != nil {
				errs = append(errs, fmt.Errorf("plugin %s on %s/%s: %w", plugin.Name(), repoSlug, wf.Path, err))
				return
			}
			findings = append(findings, pFindings...)
		}()
	}

	return findings, errs
}
