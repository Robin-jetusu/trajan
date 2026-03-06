// pkg/gitlab/include_resolver.go
package gitlab

import (
	"context"
	"fmt"

	"github.com/praetorian-inc/trajan/pkg/analysis/parser"
)

// IncludeResolver resolves GitLab CI include directives recursively.
// This resolver is not thread-safe and should not be shared across goroutines.
type IncludeResolver struct {
	client     *Client
	projectID  int
	defaultRef string
	cache      map[string]*parser.NormalizedWorkflow // Stores parsed workflows to avoid re-parsing
	processed  map[string]bool                       // Tracks processed includes for cycle detection
	maxDepth   int
}

// IncludedWorkflow represents a resolved included workflow
type IncludedWorkflow struct {
	Source   string // Cache key (for deduplication)
	Path     string // Clean file path (for display)
	Type     string // local, project, template
	Content  []byte // Raw YAML content before parsing
	Workflow *parser.NormalizedWorkflow
	Includes []*IncludedWorkflow
}

// NewIncludeResolver creates a new include resolver
func NewIncludeResolver(client *Client, projectID int, ref string) *IncludeResolver {
	return &IncludeResolver{
		client:     client,
		projectID:  projectID,
		defaultRef: ref,
		cache:      make(map[string]*parser.NormalizedWorkflow),
		processed:  make(map[string]bool),
		maxDepth:   10,
	}
}

// getDisplayPath extracts the display path from a GitLab include directive
// This avoids parsing the cache key which breaks if paths contain colons
func getDisplayPath(inc parser.GitLabInclude) string {
	switch inc.Type {
	case parser.IncludeTypeLocal:
		return inc.Path
	case parser.IncludeTypeProject:
		return inc.Path
	case parser.IncludeTypeTemplate:
		return inc.Template
	case parser.IncludeTypeRemote:
		return inc.Remote
	default:
		return ""
	}
}

// makeKey generates a unique cache key for an include
func (r *IncludeResolver) makeKey(inc parser.GitLabInclude) string {
	switch inc.Type {
	case parser.IncludeTypeLocal:
		return fmt.Sprintf("local:%d:%s:%s", r.projectID, inc.Path, r.defaultRef)
	case parser.IncludeTypeProject:
		ref := inc.Ref
		if ref == "" {
			ref = "HEAD"
		}
		return fmt.Sprintf("project:%s:%s:%s", inc.Project, inc.Path, ref)
	case parser.IncludeTypeTemplate:
		return fmt.Sprintf("template:0:%s", inc.Template)
	default:
		return fmt.Sprintf("unknown:%s", inc.Path)
	}
}

// fetchLocal fetches a local include from the same repository
func (r *IncludeResolver) fetchLocal(ctx context.Context, path string) ([]byte, error) {
	return r.client.GetWorkflowFile(ctx, r.projectID, path, r.defaultRef)
}

// fetchProject fetches an include from another GitLab project
func (r *IncludeResolver) fetchProject(ctx context.Context, projectPath, filePath, ref string) ([]byte, error) {
	if projectPath == "" {
		return nil, fmt.Errorf("project path cannot be empty")
	}
	if filePath == "" {
		return nil, fmt.Errorf("file path cannot be empty")
	}

	// Get project by path
	project, err := r.client.GetProject(ctx, projectPath)
	if err != nil {
		return nil, fmt.Errorf("getting project %s: %w", projectPath, err)
	}

	// Use provided ref or default to HEAD
	if ref == "" {
		ref = "HEAD"
	}

	// Fetch file from project
	return r.client.GetWorkflowFile(ctx, project.ID, filePath, ref)
}

// fetchTemplate fetches a GitLab official template
func (r *IncludeResolver) fetchTemplate(ctx context.Context, templateName string) ([]byte, error) {
	if templateName == "" {
		return nil, fmt.Errorf("template name cannot be empty")
	}
	return r.client.GetTemplate(ctx, templateName)
}

// resolveInclude resolves a single include directive
func (r *IncludeResolver) resolveInclude(ctx context.Context, inc parser.GitLabInclude, depth int) (*IncludedWorkflow, error) {
	// Check depth limit
	if depth >= r.maxDepth {
		return nil, fmt.Errorf("max include depth %d exceeded", r.maxDepth)
	}

	// Generate cache key
	key := r.makeKey(inc)

	// Check if already processed (cycle detection)
	if r.processed[key] {
		return nil, nil // Skip, already processed
	}
	r.processed[key] = true

	// Fetch content based on type
	var content []byte
	var err error

	switch inc.Type {
	case parser.IncludeTypeLocal:
		content, err = r.fetchLocal(ctx, inc.Path)
	case parser.IncludeTypeProject:
		content, err = r.fetchProject(ctx, inc.Project, inc.Path, inc.Ref)
	case parser.IncludeTypeTemplate:
		content, err = r.fetchTemplate(ctx, inc.Template)
	case parser.IncludeTypeRemote:
		// Skip remote includes for security
		return nil, nil
	default:
		return nil, fmt.Errorf("unknown include type: %s", inc.Type)
	}

	if err != nil {
		return nil, fmt.Errorf("fetching include %s: %w", key, err)
	}

	// Parse the included file
	gitlabParser := parser.NewGitLabParser()
	normalized, err := gitlabParser.Parse(content)
	if err != nil {
		return nil, fmt.Errorf("parsing include %s: %w", key, err)
	}

	// Cache the parsed workflow
	r.cache[key] = normalized

	// Recursively resolve nested includes
	var nestedIncludes []*IncludedWorkflow
	if rawGitLabCI, ok := normalized.Raw.(*parser.GitLabCI); ok {
		if len(rawGitLabCI.Includes) > 0 {
			for _, nestedInc := range rawGitLabCI.Includes {
				nestedResult, err := r.resolveInclude(ctx, nestedInc, depth+1)
				if err != nil {
					// TODO: Consider logging nested include errors for better visibility
					// Current behavior: graceful degradation - skip failed includes and continue
					continue
				}
				if nestedResult != nil {
					nestedIncludes = append(nestedIncludes, nestedResult)
				}
			}
		}
	}

	return &IncludedWorkflow{
		Source:   key,
		Path:     getDisplayPath(inc),
		Type:     string(inc.Type),
		Content:  content, // Store raw YAML before parsing
		Workflow: normalized,
		Includes: nestedIncludes,
	}, nil
}

// ResolveIncludes resolves multiple include directives
func (r *IncludeResolver) ResolveIncludes(ctx context.Context, includes []parser.GitLabInclude) ([]*IncludedWorkflow, error) {
	var resolved []*IncludedWorkflow

	for _, inc := range includes {
		result, err := r.resolveInclude(ctx, inc, 0)
		if err != nil {
			// Log warning but continue - graceful degradation
			// In production, use structured logging
			continue
		}

		// Skip nil results (remote includes, already processed)
		if result != nil {
			resolved = append(resolved, result)
		}
	}

	return resolved, nil
}
