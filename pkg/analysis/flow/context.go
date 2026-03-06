package flow

// FlowContext tracks variable state at a point in execution
type FlowContext struct {
	// InputLookup maps input names to their resolved values
	// e.g., "title" -> "${{ github.event.issue.title }}"
	InputLookup map[string]string

	// EnvLookup maps env var names to github context references
	// e.g., "MY_BODY" -> "github.event.comment.body"
	EnvLookup map[string]string

	// StepOutputs maps step.id.output to values
	// e.g., "get-pr.result" -> "${{ github.event.pull_request.body }}"
	StepOutputs map[string]string

	// ApprovalGate indicates if an approval gate was encountered
	ApprovalGate bool

	// GateDetails provides information about detected gates
	GateDetails []GateInfo

	// TaintMap tracks tainted values (NEW)
	TaintMap map[string]*TaintedValue

	// TaintedExpressions tracks expressions containing tainted refs (NEW)
	TaintedExpressions []string
}

// GateInfo describes a detected soft gate
type GateInfo struct {
	Type        GateType
	Location    string // job/step ID
	Confidence  Confidence
	Description string
}

// GateType represents types of approval gates
type GateType string

const (
	GateDeploymentApproval GateType = "deployment_approval"
	GatePermissionCheck    GateType = "permission_check"
	GateLabelRequired      GateType = "label_required"
	GateAuthorAssociation  GateType = "author_association"
)

// Confidence represents confidence level in analysis
type Confidence int

const (
	ConfidenceLow Confidence = iota
	ConfidenceMedium
	ConfidenceHigh
)

// NewFlowContext creates a new FlowContext with initialized maps
func NewFlowContext() *FlowContext {
	return &FlowContext{
		InputLookup:        make(map[string]string),
		EnvLookup:          make(map[string]string),
		StepOutputs:        make(map[string]string),
		ApprovalGate:       false,
		GateDetails:        []GateInfo{},
		TaintMap:           make(map[string]*TaintedValue),
		TaintedExpressions: []string{},
	}
}

// MergeEnv merges environment variables into the context
// Later values override earlier ones (job env overrides workflow env)
func (fc *FlowContext) MergeEnv(env map[string]string) {
	for key, value := range env {
		fc.EnvLookup[key] = value
	}
}

// AddGate adds a gate to the context and sets ApprovalGate flag
func (fc *FlowContext) AddGate(gate GateInfo) {
	fc.GateDetails = append(fc.GateDetails, gate)
	fc.ApprovalGate = true
}

// AddTaint adds a tainted value to the context
func (fc *FlowContext) AddTaint(variable string, tv *TaintedValue) {
	fc.TaintMap[variable] = tv
}

// GetTaint retrieves a tainted value by variable name
func (fc *FlowContext) GetTaint(variable string) *TaintedValue {
	return fc.TaintMap[variable]
}

// IsTainted checks if a variable is tainted
func (fc *FlowContext) IsTainted(variable string) bool {
	tv, exists := fc.TaintMap[variable]
	return exists && tv != nil && tv.IsTainted()
}

// PropagateTaint propagates taint from source to destination variable
func (fc *FlowContext) PropagateTaint(source, dest string) {
	if tv := fc.GetTaint(source); tv != nil {
		fc.TaintMap[dest] = tv.PropagateThrough(dest)
	}
}

// AddTaintedExpression records an expression containing tainted references
func (fc *FlowContext) AddTaintedExpression(expr string) {
	fc.TaintedExpressions = append(fc.TaintedExpressions, expr)
}

// GetAllTaints returns all tainted values in the context
func (fc *FlowContext) GetAllTaints() map[string]*TaintedValue {
	return fc.TaintMap
}
