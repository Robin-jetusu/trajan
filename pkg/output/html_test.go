package output

import (
	"strings"
	"testing"
	"time"

	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/platforms"
)

func TestGenerateHTML_BasicStructure(t *testing.T) {
	result := &platforms.ScanResult{
		Repositories: []platforms.Repository{
			{Owner: "owner", Name: "repo"},
		},
		Workflows: map[string][]platforms.Workflow{
			"owner/repo": {
				{Name: "test.yml", Path: ".github/workflows/test.yml"},
			},
		},
	}

	findings := []detections.Finding{
		{
			Type:        detections.VulnActionsInjection,
			Severity:    detections.SeverityHigh,
			Confidence:  detections.ConfidenceHigh,
			Platform:    "github",
			Repository:  "owner/repo",
			Workflow:    "test.yml",
			Job:         "build",
			Step:        "Run tests",
			Line:        42,
			Evidence:    "Untrusted input used in run",
			Remediation: "Use environment variables instead",
		},
	}

	htmlBytes, err := GenerateHTML(result, findings)
	if err != nil {
		t.Fatalf("GenerateHTML failed: %v", err)
	}

	html := string(htmlBytes)

	// Verify basic HTML structure
	if !strings.Contains(html, "<!DOCTYPE html>") {
		t.Error("Missing DOCTYPE declaration")
	}
	if !strings.Contains(html, "<html") {
		t.Error("Missing html tag")
	}
	if !strings.Contains(html, "</html>") {
		t.Error("Missing closing html tag")
	}

	// Verify title
	if !strings.Contains(html, "Trajan Security Report") {
		t.Error("Missing report title")
	}

	// Verify embedded CSS (self-contained requirement)
	if !strings.Contains(html, "<style>") {
		t.Error("Missing embedded CSS")
	}
	if !strings.Contains(html, "</style>") {
		t.Error("Missing closing style tag")
	}

	// Verify no external dependencies
	if strings.Contains(html, `href="http`) || strings.Contains(html, `src="http`) {
		t.Error("HTML contains external dependencies - must be self-contained")
	}
}

func TestGenerateHTML_ExecutiveSummary(t *testing.T) {
	result := &platforms.ScanResult{
		Repositories: []platforms.Repository{
			{Owner: "owner", Name: "repo1"},
			{Owner: "owner", Name: "repo2"},
		},
		Workflows: map[string][]platforms.Workflow{
			"owner/repo1": {
				{Name: "ci.yml", Path: ".github/workflows/ci.yml"},
				{Name: "deploy.yml", Path: ".github/workflows/deploy.yml"},
			},
			"owner/repo2": {
				{Name: "test.yml", Path: ".github/workflows/test.yml"},
			},
		},
	}

	findings := []detections.Finding{
		{Type: detections.VulnActionsInjection, Severity: detections.SeverityCritical, Repository: "owner/repo1"},
		{Type: detections.VulnPwnRequest, Severity: detections.SeverityHigh, Repository: "owner/repo1"},
		{Type: detections.VulnTOCTOU, Severity: detections.SeverityMedium, Repository: "owner/repo2"},
		{Type: detections.VulnUnpinnedAction, Severity: detections.SeverityLow, Repository: "owner/repo2"},
	}

	htmlBytes, err := GenerateHTML(result, findings)
	if err != nil {
		t.Fatalf("GenerateHTML failed: %v", err)
	}

	html := string(htmlBytes)

	// Verify summary statistics
	if !strings.Contains(html, "Total Findings") || !strings.Contains(html, "4") {
		t.Error("Missing or incorrect total findings count")
	}
	if !strings.Contains(html, "2") && !strings.Contains(html, "Repositories") {
		t.Error("Missing or incorrect repository count")
	}
	if !strings.Contains(html, "3") && !strings.Contains(html, "Workflows") {
		t.Error("Missing or incorrect workflow count")
	}

	// Verify severity breakdown
	severities := []string{"Critical", "High", "Medium", "Low"}
	for _, sev := range severities {
		if !strings.Contains(html, sev) {
			t.Errorf("Missing severity level: %s", sev)
		}
	}
}

func TestGenerateHTML_SeverityBadges(t *testing.T) {
	result := &platforms.ScanResult{
		Repositories: []platforms.Repository{
			{Owner: "owner", Name: "repo"},
		},
	}

	findings := []detections.Finding{
		{Type: detections.VulnActionsInjection, Severity: detections.SeverityCritical, Repository: "owner/repo"},
		{Type: detections.VulnPwnRequest, Severity: detections.SeverityHigh, Repository: "owner/repo"},
		{Type: detections.VulnTOCTOU, Severity: detections.SeverityMedium, Repository: "owner/repo"},
		{Type: detections.VulnUnpinnedAction, Severity: detections.SeverityLow, Repository: "owner/repo"},
		{Type: detections.VulnAnonymousDefinition, Severity: detections.SeverityInfo, Repository: "owner/repo"},
	}

	htmlBytes, err := GenerateHTML(result, findings)
	if err != nil {
		t.Fatalf("GenerateHTML failed: %v", err)
	}

	html := string(htmlBytes)

	// Verify color-coded severity badges are present
	// We expect CSS classes for each severity level
	expectedClasses := []string{"severity-critical", "severity-high", "severity-medium", "severity-low", "severity-info"}
	for _, class := range expectedClasses {
		if !strings.Contains(html, class) {
			t.Errorf("Missing severity badge class: %s", class)
		}
	}
}

func TestGenerateHTML_FindingsDetails(t *testing.T) {
	result := &platforms.ScanResult{
		Repositories: []platforms.Repository{
			{Owner: "owner", Name: "repo"},
		},
	}

	finding := detections.Finding{
		Type:        detections.VulnActionsInjection,
		Severity:    detections.SeverityHigh,
		Confidence:  detections.ConfidenceHigh,
		Platform:    "github",
		Repository:  "owner/repo",
		Workflow:    "ci.yml",
		Job:         "build",
		Step:        "Run tests",
		Line:        42,
		Evidence:    "Untrusted input ${{ github.event.issue.title }} used in run command",
		Remediation: "Use environment variables to pass untrusted data",
	}

	findings := []detections.Finding{finding}

	htmlBytes, err := GenerateHTML(result, findings)
	if err != nil {
		t.Fatalf("GenerateHTML failed: %v", err)
	}

	html := string(htmlBytes)

	// Verify finding details are present
	detailStrings := []string{
		"actions_injection",
		"owner/repo",
		"ci.yml",
		"build",
		"Run tests",
		"42",
		"Untrusted input",
		"Use environment variables",
	}

	for _, detail := range detailStrings {
		if !strings.Contains(html, detail) {
			t.Errorf("Missing finding detail: %s", detail)
		}
	}

	// Verify collapsible sections using details/summary
	if !strings.Contains(html, "<details>") {
		t.Error("Missing collapsible details element")
	}
	if !strings.Contains(html, "<summary>") {
		t.Error("Missing summary element for collapsible section")
	}
}

func TestGenerateHTML_EmptyFindings(t *testing.T) {
	result := &platforms.ScanResult{
		Repositories: []platforms.Repository{
			{Owner: "owner", Name: "repo"},
		},
		Workflows: map[string][]platforms.Workflow{
			"owner/repo": {
				{Name: "ci.yml", Path: ".github/workflows/ci.yml"},
			},
		},
	}

	findings := []detections.Finding{}

	htmlBytes, err := GenerateHTML(result, findings)
	if err != nil {
		t.Fatalf("GenerateHTML failed: %v", err)
	}

	html := string(htmlBytes)

	// Verify it handles zero findings gracefully
	if !strings.Contains(html, "No vulnerabilities found") && !strings.Contains(html, "0") {
		t.Error("Should indicate no vulnerabilities found")
	}

	// Should still be valid HTML
	if !strings.Contains(html, "<!DOCTYPE html>") {
		t.Error("Missing DOCTYPE even with no findings")
	}
}

func TestGenerateHTML_GroupedByRepository(t *testing.T) {
	result := &platforms.ScanResult{
		Repositories: []platforms.Repository{
			{Owner: "owner", Name: "repo1"},
			{Owner: "owner", Name: "repo2"},
		},
	}

	findings := []detections.Finding{
		{Repository: "owner/repo1", Type: detections.VulnActionsInjection, Severity: detections.SeverityHigh},
		{Repository: "owner/repo1", Type: detections.VulnPwnRequest, Severity: detections.SeverityHigh},
		{Repository: "owner/repo2", Type: detections.VulnTOCTOU, Severity: detections.SeverityMedium},
	}

	htmlBytes, err := GenerateHTML(result, findings)
	if err != nil {
		t.Fatalf("GenerateHTML failed: %v", err)
	}

	html := string(htmlBytes)

	// Verify findings are grouped by repository
	if !strings.Contains(html, "owner/repo1") {
		t.Error("Missing repo1 in grouped findings")
	}
	if !strings.Contains(html, "owner/repo2") {
		t.Error("Missing repo2 in grouped findings")
	}

	// Verify repo1 appears before its findings in the HTML
	repo1Idx := strings.Index(html, "owner/repo1")
	actionsInjectionIdx := strings.Index(html, "actions_injection")
	if repo1Idx == -1 || actionsInjectionIdx == -1 || repo1Idx > actionsInjectionIdx {
		t.Error("Findings not properly grouped under repository headings")
	}
}

func TestGenerateHTML_Timestamp(t *testing.T) {
	result := &platforms.ScanResult{
		Repositories: []platforms.Repository{
			{Owner: "owner", Name: "repo"},
		},
	}

	findings := []detections.Finding{}

	before := time.Now()
	htmlBytes, err := GenerateHTML(result, findings)
	_ = before // Use variable to avoid unused error

	if err != nil {
		t.Fatalf("GenerateHTML failed: %v", err)
	}

	html := string(htmlBytes)

	// Verify report includes generation timestamp
	// Should contain year at minimum
	currentYear := time.Now().Format("2006")
	if !strings.Contains(html, currentYear) {
		t.Error("Missing generation timestamp")
	}

	// Verify timestamp is reasonable (within test execution window)
	// This is a loose check - just ensure some time representation exists
	if !strings.Contains(html, "Generated") && !strings.Contains(html, "Scan Date") && !strings.Contains(html, "Report Date") {
		t.Error("Missing timestamp label")
	}
}
func TestGenerateHTML_SeverityChart(t *testing.T) {
	result := &platforms.ScanResult{
		Repositories: []platforms.Repository{
			{Owner: "owner", Name: "repo"},
		},
	}

	findings := []detections.Finding{
		{Severity: detections.SeverityCritical, Repository: "owner/repo"},
		{Severity: detections.SeverityCritical, Repository: "owner/repo"},
		{Severity: detections.SeverityHigh, Repository: "owner/repo"},
		{Severity: detections.SeverityMedium, Repository: "owner/repo"},
	}

	htmlBytes, err := GenerateHTML(result, findings)
	if err != nil {
		t.Fatalf("GenerateHTML failed: %v", err)
	}

	html := string(htmlBytes)

	// Verify inline SVG chart (no external dependencies)
	if !strings.Contains(html, "<svg") {
		t.Error("Missing inline SVG severity chart")
	}
	if !strings.Contains(html, "</svg>") {
		t.Error("Missing closing SVG tag")
	}

	// Verify SVG is inline, not external reference
	if strings.Contains(html, `<img src="`) || strings.Contains(html, `<object data="`) {
		t.Error("SVG should be inline, not external reference")
	}
}
