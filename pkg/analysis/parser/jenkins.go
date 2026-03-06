// Package parser provides workflow parsing for multiple CI/CD platforms
package parser

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"regexp"
	"strings"
)

// JenkinsParser implements WorkflowParser for Jenkins
type JenkinsParser struct{}

// NewJenkinsParser creates a new Jenkins parser
func NewJenkinsParser() *JenkinsParser {
	return &JenkinsParser{}
}

// Platform returns the platform identifier
func (p *JenkinsParser) Platform() string {
	return "jenkins"
}

// CanParse returns true if this parser can handle the given file path
func (p *JenkinsParser) CanParse(path string) bool {
	return path == "Jenkinsfile" || strings.Contains(path, "config.xml")
}

// Parse parses Jenkins workflow content (either config.xml or raw Groovy Jenkinsfile)
func (p *JenkinsParser) Parse(data []byte) (*NormalizedWorkflow, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty Jenkins configuration")
	}

	trimmed := strings.TrimSpace(string(data))
	if strings.HasPrefix(trimmed, "<?xml") || strings.HasPrefix(trimmed, "<") {
		return p.parseConfigXML(data)
	}
	return p.parseGroovy(trimmed)
}

// ---------------------------------------------------------------------------
// XML config.xml parsing
// ---------------------------------------------------------------------------

// jenkinsFlowDefinition is used to parse pipeline config.xml
type jenkinsFlowDefinition struct {
	XMLName    xml.Name `xml:"flow-definition"`
	Definition struct {
		Script string `xml:"script"`
	} `xml:"definition"`
}

// jenkinsFreestyleProject is used to parse freestyle job config.xml
type jenkinsFreestyleProject struct {
	XMLName      xml.Name `xml:"project"`
	AssignedNode string   `xml:"assignedNode"`
	Label        string   `xml:"label"`
	Builders     struct {
		ShellTasks []struct {
			Command string `xml:"command"`
		} `xml:"hudson.tasks.Shell"`
		BatchTasks []struct {
			Command string `xml:"command"`
		} `xml:"hudson.tasks.BatchFile"`
	} `xml:"builders"`
}

func (p *JenkinsParser) parseConfigXML(data []byte) (*NormalizedWorkflow, error) {
	// Normalize XML 1.1 to 1.0 — Jenkins API/UI creates XML 1.1 which Go stdlib doesn't support
	data = bytes.Replace(data, []byte(`<?xml version='1.1'`), []byte(`<?xml version='1.0'`), 1)
	data = bytes.Replace(data, []byte(`<?xml version="1.1"`), []byte(`<?xml version="1.0"`), 1)

	// Try pipeline flow-definition first
	var flowDef jenkinsFlowDefinition
	if err := xml.Unmarshal(data, &flowDef); err == nil && flowDef.Definition.Script != "" {
		// Pipeline job — extract the Groovy script and parse it
		return p.parseGroovy(flowDef.Definition.Script)
	}

	// Try freestyle project
	var freestyle jenkinsFreestyleProject
	if err := xml.Unmarshal(data, &freestyle); err != nil {
		return nil, fmt.Errorf("parsing Jenkins config.xml: %w", err)
	}

	return p.convertFreestyle(&freestyle), nil
}

func (p *JenkinsParser) convertFreestyle(f *jenkinsFreestyleProject) *NormalizedWorkflow {
	wf := &NormalizedWorkflow{
		Platform: "jenkins",
		Name:     "freestyle",
		Triggers: []string{"push"},
		Jobs:     make(map[string]*NormalizedJob),
		Env:      make(map[string]string),
	}

	agent := f.AssignedNode
	if agent == "" {
		agent = f.Label
	}

	job := &NormalizedJob{
		ID:       "freestyle",
		Name:     "freestyle",
		RunsOn:   agent,
		Steps:    make([]*NormalizedStep, 0),
		Env:      make(map[string]string),
		Services: make(map[string]*NormalizedService),
	}

	for i, sh := range f.Builders.ShellTasks {
		job.Steps = append(job.Steps, &NormalizedStep{
			Name: fmt.Sprintf("sh-%d", i),
			Run:  sh.Command,
		})
	}
	for i, bat := range f.Builders.BatchTasks {
		job.Steps = append(job.Steps, &NormalizedStep{
			Name: fmt.Sprintf("bat-%d", i),
			Run:  bat.Command,
		})
	}

	wf.Jobs["freestyle"] = job
	return wf
}

// ---------------------------------------------------------------------------
// Groovy DSL parsing (declarative and scripted)
// ---------------------------------------------------------------------------

// Regex patterns for Groovy DSL parsing
var (
	reAgentAny    = regexp.MustCompile(`(?m)^\s*agent\s+any\s*$`)
	reAgentNone   = regexp.MustCompile(`(?m)^\s*agent\s+none\s*$`)
	reAgentLabel  = regexp.MustCompile(`agent\s*\{\s*label\s+['"]([^'"]+)['"]\s*\}`)
	reAgentDocker = regexp.MustCompile(`agent\s*\{\s*docker\s+['"]([^'"]+)['"]\s*\}`)
	reNodeAgent   = regexp.MustCompile(`node\s*\(\s*['"]([^'"]*)['"]\s*\)`)
	reEnvKey      = regexp.MustCompile(`(\w+)\s*=\s*['"]([^'"]*?)['"]`)
	reStage       = regexp.MustCompile(`stage\s*\(\s*['"]([^'"]+)['"]\s*\)`)
	reWhenBlock   = regexp.MustCompile(`when\s*\{`)
	reParameters  = regexp.MustCompile(`\bparameters\s*\{`)
)

func (p *JenkinsParser) parseGroovy(script string) (*NormalizedWorkflow, error) {
	wf := &NormalizedWorkflow{
		Platform: "jenkins",
		Jobs:     make(map[string]*NormalizedJob),
		Env:      make(map[string]string),
	}

	// Determine if declarative (has pipeline { }) or scripted
	pipelineStart := strings.Index(script, "pipeline {")
	if pipelineStart == -1 {
		pipelineStart = strings.Index(script, "pipeline{")
	}

	if pipelineStart != -1 {
		p.parseDeclarative(script, wf)
	} else {
		p.parseScripted(script, wf)
	}

	if len(wf.Triggers) == 0 {
		wf.Triggers = []string{"push"}
	}

	return wf, nil
}

// parseDeclarative handles declarative pipeline syntax
func (p *JenkinsParser) parseDeclarative(script string, wf *NormalizedWorkflow) {
	// Global agent
	globalAgent := p.extractGlobalAgent(script)

	// Environment block at pipeline level
	wf.Env = p.extractEnvBlock(script, "pipeline")

	// Triggers: check for parameters block
	if reParameters.MatchString(script) {
		wf.Triggers = append(wf.Triggers, "parameterized")
	}

	// Find all stage blocks
	stages := p.extractStages(script)
	for i, stage := range stages {
		jobID := fmt.Sprintf("stage-%d", i)
		job := &NormalizedJob{
			ID:       jobID,
			Name:     stage.name,
			RunsOn:   globalAgent,
			Steps:    make([]*NormalizedStep, 0),
			Env:      p.extractEnvBlock(stage.body, "stage"),
			Services: make(map[string]*NormalizedService),
		}

		// Stage-level agent override
		if sa := p.extractStageAgent(stage.body); sa != "" {
			job.RunsOn = sa
		}

		// Condition from when block
		if reWhenBlock.MatchString(stage.body) {
			whenBody := extractBraceBlock(stage.body, "when")
			job.Condition = strings.TrimSpace(whenBody)
		}

		// Extract sh/bat steps
		job.Steps = p.extractShSteps(stage.body)

		wf.Jobs[jobID] = job
	}
}

// parseScripted handles scripted pipeline syntax: node('label') { ... }
func (p *JenkinsParser) parseScripted(script string, wf *NormalizedWorkflow) {
	agent := ""
	if m := reNodeAgent.FindStringSubmatch(script); m != nil {
		agent = m[1]
	}

	job := &NormalizedJob{
		ID:       "scripted",
		Name:     "scripted",
		RunsOn:   agent,
		Steps:    p.extractShSteps(script),
		Env:      make(map[string]string),
		Services: make(map[string]*NormalizedService),
	}

	wf.Jobs["scripted"] = job
}

// ---------------------------------------------------------------------------
// Agent extraction helpers
// ---------------------------------------------------------------------------

func (p *JenkinsParser) extractGlobalAgent(script string) string {
	// Find pipeline block body first to scope the search
	pipelineBody := extractBraceBlock(script, "pipeline")
	if pipelineBody == "" {
		pipelineBody = script
	}
	return p.extractAgentFromText(pipelineBody)
}

func (p *JenkinsParser) extractStageAgent(stageBody string) string {
	return p.extractAgentFromText(stageBody)
}

func (p *JenkinsParser) extractAgentFromText(text string) string {
	if reAgentAny.MatchString(text) {
		return "any"
	}
	if reAgentNone.MatchString(text) {
		return "none"
	}
	if m := reAgentLabel.FindStringSubmatch(text); m != nil {
		return m[1]
	}
	if m := reAgentDocker.FindStringSubmatch(text); m != nil {
		return m[1]
	}
	return ""
}

// ---------------------------------------------------------------------------
// Stage extraction
// ---------------------------------------------------------------------------

type stageInfo struct {
	name string
	body string
}

// extractStages finds all stage('Name') { ... } blocks
func (p *JenkinsParser) extractStages(script string) []stageInfo {
	var stages []stageInfo
	idxs := reStage.FindAllStringIndex(script, -1)
	for _, idx := range idxs {
		matchStr := script[idx[0]:idx[1]]
		m := reStage.FindStringSubmatch(matchStr)
		if m == nil {
			continue
		}
		stageName := m[1]

		// Find the opening brace after the stage(...)
		rest := script[idx[1]:]
		braceIdx := strings.Index(rest, "{")
		if braceIdx == -1 {
			continue
		}
		body := extractBraceContent(rest[braceIdx:])
		stages = append(stages, stageInfo{name: stageName, body: body})
	}
	return stages
}

// ---------------------------------------------------------------------------
// Environment block extraction
// ---------------------------------------------------------------------------

// extractEnvBlock finds an environment { ... } block and parses KEY = 'val' pairs.
// The scope parameter is unused (for clarity) but signals intent.
func (p *JenkinsParser) extractEnvBlock(text, _ string) map[string]string {
	env := make(map[string]string)
	envBody := extractBraceBlock(text, "environment")
	if envBody == "" {
		return env
	}
	for _, m := range reEnvKey.FindAllStringSubmatch(envBody, -1) {
		env[m[1]] = m[2]
	}
	return env
}

// ---------------------------------------------------------------------------
// sh / bat step extraction
// ---------------------------------------------------------------------------

// extractShSteps finds all sh and bat commands in the given text block.
// It handles: sh 'cmd', sh "cmd", sh ”'cmd”', sh """cmd"""
func (p *JenkinsParser) extractShSteps(text string) []*NormalizedStep {
	var steps []*NormalizedStep
	i := 0
	for i < len(text) {
		// Look for next sh or bat keyword
		shIdx := -1
		shKind := ""
		for _, kw := range []string{"sh ", "sh\t", "sh(", "bat ", "bat\t", "bat("} {
			idx := strings.Index(text[i:], kw)
			if idx != -1 && (shIdx == -1 || idx < shIdx) {
				shIdx = idx
				shKind = strings.TrimRight(kw, " \t(")
			}
		}
		if shIdx == -1 {
			break
		}
		absIdx := i + shIdx + len(shKind)
		i = absIdx

		// Skip whitespace and optional '('
		for i < len(text) && (text[i] == ' ' || text[i] == '\t' || text[i] == '(') {
			i++
		}
		if i >= len(text) {
			break
		}

		cmd, advance := extractQuotedString(text, i)
		if advance == 0 {
			i++
			continue
		}
		i += advance

		steps = append(steps, &NormalizedStep{
			Name: fmt.Sprintf("%s-step-%d", shKind, len(steps)),
			Run:  cmd,
		})
	}
	return steps
}

// ---------------------------------------------------------------------------
// Brace matching and quoted string helpers
// ---------------------------------------------------------------------------

// extractBraceBlock finds the first occurrence of `keyword {` and returns the
// content between the matching braces (exclusive).
func extractBraceBlock(text, keyword string) string {
	idx := strings.Index(text, keyword+" {")
	if idx == -1 {
		idx = strings.Index(text, keyword+"{")
	}
	if idx == -1 {
		return ""
	}
	braceStart := strings.Index(text[idx:], "{")
	if braceStart == -1 {
		return ""
	}
	return extractBraceContent(text[idx+braceStart:])
}

// extractBraceContent returns the content inside the outermost braces of s,
// which must start with '{'. It respects single-quoted, double-quoted,
// triple-single-quoted, and triple-double-quoted strings.
func extractBraceContent(s string) string {
	if len(s) == 0 || s[0] != '{' {
		return ""
	}
	depth := 0
	i := 0
	for i < len(s) {
		// Triple-quoted strings first
		if i+2 < len(s) {
			triple := s[i : i+3]
			if triple == `"""` || triple == "'''" {
				end := strings.Index(s[i+3:], triple)
				if end != -1 {
					i = i + 3 + end + 3
					continue
				}
			}
		}
		ch := s[i]
		switch ch {
		case '{':
			depth++
			i++
		case '}':
			depth--
			if depth == 0 {
				return s[1:i]
			}
			i++
		case '"':
			// Skip double-quoted string
			i++
			for i < len(s) && s[i] != '"' {
				if s[i] == '\\' {
					i++
				}
				i++
			}
			i++ // closing quote
		case '\'':
			// Skip single-quoted string
			i++
			for i < len(s) && s[i] != '\'' {
				if s[i] == '\\' {
					i++
				}
				i++
			}
			i++ // closing quote
		default:
			i++
		}
	}
	return ""
}

// extractQuotedString extracts the string value starting at position pos in text.
// Returns the string content and number of bytes consumed. Returns ("", 0) if not a
// recognized quote pattern.
func extractQuotedString(text string, pos int) (string, int) {
	if pos >= len(text) {
		return "", 0
	}

	// Triple-double-quote
	if pos+2 < len(text) && text[pos:pos+3] == `"""` {
		end := strings.Index(text[pos+3:], `"""`)
		if end != -1 {
			content := text[pos+3 : pos+3+end]
			return strings.TrimSpace(content), 3 + end + 3
		}
	}
	// Triple-single-quote
	if pos+2 < len(text) && text[pos:pos+3] == "'''" {
		end := strings.Index(text[pos+3:], "'''")
		if end != -1 {
			content := text[pos+3 : pos+3+end]
			return strings.TrimSpace(content), 3 + end + 3
		}
	}
	// Double-quote
	if text[pos] == '"' {
		i := pos + 1
		for i < len(text) && text[i] != '"' && text[i] != '\n' {
			if text[i] == '\\' {
				i++
			}
			i++
		}
		if i < len(text) && text[i] == '"' {
			return text[pos+1 : i], i - pos + 1
		}
	}
	// Single-quote
	if text[pos] == '\'' {
		i := pos + 1
		for i < len(text) && text[i] != '\'' && text[i] != '\n' {
			if text[i] == '\\' {
				i++
			}
			i++
		}
		if i < len(text) && text[i] == '\'' {
			return text[pos+1 : i], i - pos + 1
		}
	}
	return "", 0
}

// init registers the Jenkins parser
func init() {
	RegisterParser(NewJenkinsParser())
}
