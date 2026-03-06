package enumerate

import "testing"

// === analyzeBranchFilters tests ===

func TestAnalyzeBranchFilters_EmptyFilters(t *testing.T) {
	// Empty filters = all branches trigger = exploitable
	exploitable, reason := analyzeBranchFilters([]string{})
	if !exploitable {
		t.Error("empty filters should be exploitable")
	}
	if reason == "" {
		t.Error("should have a reason")
	}
}

func TestAnalyzeBranchFilters_BroadWildcard(t *testing.T) {
	// Test *, +*, +refs/heads/* patterns
	cases := [][]string{
		{"*"},
		{"+*"},
		{"+refs/heads/*"},
	}
	for _, filters := range cases {
		exploitable, _ := analyzeBranchFilters(filters)
		if !exploitable {
			t.Errorf("filter %v should be exploitable", filters)
		}
	}
}

func TestAnalyzeBranchFilters_ProtectedOnly(t *testing.T) {
	// Only protected branches = NOT exploitable
	cases := [][]string{
		{"+refs/heads/main"},
		{"+refs/heads/master"},
		{"+refs/heads/main", "+refs/heads/develop"},
		{"+main", "+master"},
	}
	for _, filters := range cases {
		exploitable, _ := analyzeBranchFilters(filters)
		if exploitable {
			t.Errorf("filter %v should NOT be exploitable", filters)
		}
	}
}

func TestAnalyzeBranchFilters_UserBranches(t *testing.T) {
	// User-controllable patterns = exploitable
	cases := [][]string{
		{"+refs/heads/feature/*"},
		{"+refs/heads/users/*"},
		{"+refs/heads/bugfix/*"},
		{"+refs/heads/fix/*"},
	}
	for _, filters := range cases {
		exploitable, _ := analyzeBranchFilters(filters)
		if !exploitable {
			t.Errorf("filter %v should be exploitable", filters)
		}
	}
}

func TestAnalyzeBranchFilters_ProtectedWildcard(t *testing.T) {
	// Protected wildcards (release/*, releases/*) are recognized by isProtectedWildcard()
	// and should NOT be exploitable even though they contain wildcards
	cases := [][]string{
		{"+refs/heads/release/*"},
		{"+refs/heads/releases/*"},
	}
	for _, filters := range cases {
		exploitable, _ := analyzeBranchFilters(filters)
		if exploitable {
			t.Errorf("filter %v should NOT be exploitable (protected wildcard)", filters)
		}
	}
}

func TestAnalyzeBranchFilters_ExcludeFiltersIgnored(t *testing.T) {
	// Exclude filters (starting with -) should be skipped
	exploitable, _ := analyzeBranchFilters([]string{"+refs/heads/main", "-refs/heads/develop"})
	if exploitable {
		t.Error("should not be exploitable with only protected include")
	}
}

func TestAnalyzeBranchFilters_MixedProtectedAndWildcard(t *testing.T) {
	// Protected + wildcard = exploitable (wildcard wins)
	exploitable, _ := analyzeBranchFilters([]string{"+refs/heads/main", "+refs/heads/feature/*"})
	if !exploitable {
		t.Error("mixed protected + user wildcard should be exploitable")
	}
}

// === containsWildcard tests ===

func TestContainsWildcard(t *testing.T) {
	cases := map[string]bool{
		"refs/heads/main":    false,
		"refs/heads/*":       true,
		"feature/?":          true,
		"*":                  true,
		"+refs/heads/main":   false,
		"+refs/heads/feat/*": true,
	}
	for pattern, expected := range cases {
		if containsWildcard(pattern) != expected {
			t.Errorf("containsWildcard(%q) = %v, want %v", pattern, !expected, expected)
		}
	}
}

// === containsUserBranchPattern tests ===

func TestContainsUserBranchPattern(t *testing.T) {
	cases := map[string]bool{
		"+refs/heads/feature/*": true,
		"+refs/heads/users/*":   true,
		"+refs/heads/bugfix/*":  true,
		"+refs/heads/hotfix/*":  true,
		"+refs/heads/main":      false,
		"+refs/heads/release/*": false,
		"feature/my-thing":      true,
		"refs/heads/dev/branch": true,
	}
	for pattern, expected := range cases {
		if containsUserBranchPattern(pattern) != expected {
			t.Errorf("containsUserBranchPattern(%q) = %v, want %v", pattern, !expected, expected)
		}
	}
}

// === isProtectedWildcard tests ===

func TestIsProtectedWildcard(t *testing.T) {
	cases := map[string]bool{
		"+refs/heads/release/*":  true,
		"+refs/heads/releases/*": true,
		"+release/*":             true,
		"+releases/*":            true,
		"+refs/heads/feature/*":  false,
		"+refs/heads/*":          false,
		"*":                      false,
	}
	for pattern, expected := range cases {
		if isProtectedWildcard(pattern) != expected {
			t.Errorf("isProtectedWildcard(%q) = %v, want %v", pattern, !expected, expected)
		}
	}
}

// === formatBranchFilters tests ===

func TestFormatBranchFilters_Empty(t *testing.T) {
	if formatBranchFilters([]string{}, 3) != "*" {
		t.Error("empty should return *")
	}
}

func TestFormatBranchFilters_WithinLimit(t *testing.T) {
	result := formatBranchFilters([]string{"a", "b"}, 3)
	if result != "a, b" {
		t.Errorf("got %q", result)
	}
}

func TestFormatBranchFilters_ExceedsLimit(t *testing.T) {
	result := formatBranchFilters([]string{"a", "b", "c", "d", "e"}, 3)
	// Should show first 3 + "+2 more"
	if result == "" {
		t.Error("should not be empty")
	}
}

// === utility tests ===

func TestFormatBool(t *testing.T) {
	if formatBool(true) != "Yes" {
		t.Error("true should be Yes")
	}
	if formatBool(false) != "No" {
		t.Error("false should be No")
	}
}

func TestTruncateString(t *testing.T) {
	if truncateString("short", 10) != "short" {
		t.Error("short string shouldn't be truncated")
	}
	if truncateString("this is very long", 10) != "this is..." {
		t.Error("long string should be truncated")
	}
}

func TestPolicyTypeNameMap(t *testing.T) {
	m := policyTypeNameMap()
	if m["0609b952-1397-4640-95ec-e00a01b2c241"] != "Build" {
		t.Error("Build policy type missing")
	}
	if m["fa4e907d-c16b-4a4c-9dfa-4906e5d171dd"] != "Min Reviewers" {
		t.Error("Min Reviewers missing")
	}
	if len(m) != 4 {
		t.Errorf("expected 4 policy types, got %d", len(m))
	}
}
