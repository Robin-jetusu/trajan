package platforms

import "testing"

func TestRepositoryFullName(t *testing.T) {
	tests := []struct {
		name     string
		repo     Repository
		expected string
	}{
		{
			name: "basic repository",
			repo: Repository{
				Owner: "praetorian-inc",
				Name:  "trajan",
			},
			expected: "praetorian-inc/trajan",
		},
		{
			name: "single character owner and repo",
			repo: Repository{
				Owner: "a",
				Name:  "b",
			},
			expected: "a/b",
		},
		{
			name: "owner with hyphen",
			repo: Repository{
				Owner: "my-org",
				Name:  "my-repo",
			},
			expected: "my-org/my-repo",
		},
		{
			name: "repo with underscores",
			repo: Repository{
				Owner: "example_org",
				Name:  "test_project",
			},
			expected: "example_org/test_project",
		},
		{
			name: "empty owner and name",
			repo: Repository{
				Owner: "",
				Name:  "",
			},
			expected: "/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.repo.FullName()
			if got != tt.expected {
				t.Errorf("FullName() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestRepositoryFullNameWithCompleteStruct(t *testing.T) {
	// Test that FullName works with a complete Repository struct
	repo := Repository{
		Owner:         "testorg",
		Name:          "testrepo",
		DefaultBranch: "main",
		Private:       true,
		Archived:      false,
		URL:           "https://github.com/testorg/testrepo",
	}

	expected := "testorg/testrepo"
	got := repo.FullName()

	if got != expected {
		t.Errorf("FullName() = %q, want %q", got, expected)
	}
}

func TestRepositoryFullNameConsistency(t *testing.T) {
	// Verify that FullName returns consistent results
	repo := Repository{
		Owner: "owner",
		Name:  "repo",
	}

	first := repo.FullName()
	second := repo.FullName()

	if first != second {
		t.Errorf("FullName() inconsistent: first=%q, second=%q", first, second)
	}
}
