package attacks

// ContextKey identifies typed values in ChainContext
type ContextKey string

const (
	// C2RepoKey is the full name of the C2 repository (e.g., "owner/trajan-c2-xxx")
	C2RepoKey ContextKey = "c2_repo"

	// C2URLKey is the URL of the C2 repository
	C2URLKey ContextKey = "c2_url"

	// RunnersKey contains the list of connected runners
	RunnersKey ContextKey = "runners"

	// GistIDKey contains the ID of the implant gist
	GistIDKey ContextKey = "gist_id"

	// ForkRepoKey contains the forked repository name
	ForkRepoKey ContextKey = "fork_repo"

	// PRNumberKey contains the pull request number
	PRNumberKey ContextKey = "pr_number"
)

// ChainableAttackPlugin extends AttackPlugin with dependency metadata
// for attack chaining support.
type ChainableAttackPlugin interface {
	AttackPlugin

	// Dependencies returns plugin names this plugin requires to run first.
	// Empty slice means no hard dependencies.
	Dependencies() []string

	// OptionalDependencies returns plugins that enhance this one but aren't required.
	// The chain executor will include these if available.
	// For example, runner-on-runner can create its own C2 or reuse c2-setup's C2.
	OptionalDependencies() []string

	// Provides returns the context keys this plugin populates after execution.
	// Used for documentation and validation.
	Provides() []ContextKey

	// Requires returns the context keys this plugin needs to execute.
	// The chain executor validates these are available before execution.
	Requires() []ContextKey
}
