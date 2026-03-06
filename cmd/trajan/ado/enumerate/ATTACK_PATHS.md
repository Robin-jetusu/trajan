# Attack Paths Command

## Overview

The `attack-paths` command performs comprehensive security analysis to identify potential attack paths in Azure DevOps organizations by examining permissions, pipeline triggers, and policies.

## Usage

```bash
# Basic usage
trajan enumerate attack-paths --platform azuredevops --org myorg --project myproject --token xxx

# JSON output
trajan enumerate attack-paths --platform azuredevops --org myorg --project myproject -o json

# CSV output (paths only)
trajan enumerate attack-paths --platform azuredevops --org myorg --project myproject -o csv
```

## Analysis Phases

### Phase 1: Permission Analysis
Analyzes user permissions across two security namespaces:

**Build Namespace:**
- Queue builds permission
- View builds permission
- View definitions permission

**Git Namespace:**
- Contribute code permission (implies PR creation)
- Force push permission
- Policy bypass permissions (push and PR)

### Phase 2: Trigger Analysis
Analyzes all pipeline triggers in the project:

**Trigger Types:**
- CI triggers (continuousIntegration)
- PR triggers (pullRequest)
- Scheduled triggers (schedule)
- Manual-only pipelines

**Exploitability Analysis:**
- Wildcard patterns allowing arbitrary branches
- User-controllable branch patterns (features/*, users/*)
- Lack of branch filters (all branches)
- Only protected branches (safe)

### Phase 3: Policy Analysis
Analyzes branch policies:
- Build validation policies
- Repository scope
- Branch scope
- Enabled/disabled status

### Phase 4: Attack Path Identification

The command identifies 6 types of attack paths:

| Attack Path | Risk | Conditions | Description |
|------------|------|-----------|-------------|
| **Direct Pipeline Execution** | High | Can queue builds | User can directly execute any pipeline without code changes |
| **CI Trigger Hijack** | Critical | Can contribute + exploitable CI triggers | User can create branches matching wildcard patterns to trigger pipelines |
| **CI Trigger via Code Push** | High | Can contribute + CI triggers | User can push code to trigger pipelines |
| **PR Trigger Attack** | Critical/Medium | Can create PRs + (PR triggers or build policies) | User can create PRs to trigger pipelines (Critical if exploitable patterns) |
| **Policy Bypass** | High | Can bypass policies | User can bypass branch policies on push or PR |
| **Scheduled Trigger Poisoning** | Medium | Can contribute + scheduled triggers | User can modify pipeline definitions to be executed on schedule |

## Output Formats

### Console (default)
```
=== Permission Analysis ===
Queue builds:      Yes
Contribute code:   Yes
Create PRs:        Yes
Force push:        No
Bypass policies:   No

=== Trigger Analysis ===
CI Triggers:        5 (3 exploitable)
PR Triggers:        2 (1 exploitable)
Scheduled:          1
Manual only:        3
Total pipelines:    11

=== Policy Analysis ===
Build Validation:   2 policies

=== Attack Paths ===
RISK       ATTACK PATH                    DETAILS
--------------------------------------------------------------------------------
Critical   CI Trigger Hijack              3 exploitable CI triggers + contribute access
High       Direct Pipeline Execution      Queue builds permission granted
Medium     Scheduled Trigger Poisoning    1 scheduled trigger + contribute access

Found 3 attack paths (1 critical, 1 high, 1 medium)
```

### JSON
Complete structured output including:
- Full permission analysis
- Complete trigger lists (by type and exploitability)
- Policy details
- Attack paths array
- Summary statistics (total paths, by risk level)

### CSV
Attack paths only in CSV format for easy import into spreadsheets.

## Implementation Details

### File Structure
- **attack_paths.go** (~400 lines): Main implementation
  - Command registration (`newAttackPathsCmd`)
  - Platform dispatch (`runAttackPaths`, `runAttackPathsAzDO`)
  - Analysis phases (permissions, triggers, policies)
  - Attack path identification logic
  - Output formatters (console, JSON, CSV)

- **attack_paths_test.go**: Comprehensive test suite
  - Command registration test
  - Attack path identification tests for all 6 path types
  - Multi-risk scenario tests
  - Edge case tests

### Dependencies
Reuses existing code from:
- `analysis.go`: `analyzeBranchFilters`, permission constants, formatting utilities
- `root.go`: `GetTokenForPlatform` for token retrieval
- Azure DevOps client methods: `QueryAccessControlLists`, `ListBuildDefinitions`, `GetBuildDefinition`, `ListPolicyConfigurations`

### Permission Detection Approach
The permission analysis is **best-effort**:
- Uses simplified token paths (may not match all ADO configurations)
- Checks all ACEs in returned ACLs (doesn't require knowing current user descriptor)
- Defaults to `false` for permissions if ACL queries fail (safe default)
- Provides actionable findings even with partial permission visibility

## Testing

Run tests:
```bash
# All attack path tests
GOWORK=off go test ./cmd/trajan/enumerate -run TestAttackPaths -v
GOWORK=off go test ./cmd/trajan/enumerate -run TestIdentifyAttackPaths -v

# Full package test suite
GOWORK=off go test ./cmd/trajan/enumerate
```

## Security Considerations

The command helps identify:
1. **Privilege escalation paths**: How low-privilege users can execute code via pipelines
2. **Supply chain risks**: Exploitable trigger patterns allowing malicious code execution
3. **Policy gaps**: Missing or bypassable protections on critical branches
4. **Combined risk**: Multiple low/medium risks that together create critical exposure

Use output to prioritize security hardening:
- Tighten branch filters on CI/PR triggers
- Remove unnecessary queue builds permissions
- Enable required build validation policies
- Remove wildcard patterns from triggers
