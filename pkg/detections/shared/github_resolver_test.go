// modules/trajan/pkg/detections/shared/github_resolver_test.go
package shared

import "testing"

func TestGitHubUsesResolver(t *testing.T) {
	resolver := NewGitHubUsesResolver()

	tests := []struct {
		name     string
		uses     string
		wantErr  bool
		wantType UsesType
		wantPin  bool
	}{
		{
			name:     "standard action with tag",
			uses:     "actions/checkout@v3",
			wantErr:  false,
			wantType: UsesTypeAction,
			wantPin:  false,
		},
		{
			name:     "action pinned to SHA",
			uses:     "actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29",
			wantErr:  false,
			wantType: UsesTypeAction,
			wantPin:  true,
		},
		{
			name:     "docker image",
			uses:     "docker://alpine:3.18",
			wantErr:  false,
			wantType: UsesTypeDocker,
			wantPin:  false,
		},
		{
			name:     "local action",
			uses:     "./actions/my-action",
			wantErr:  false,
			wantType: UsesTypeLocal,
			wantPin:  true, // Local actions are inherently pinned
		},
		{
			name:     "action with path",
			uses:     "actions/aws-actions/configure-aws-credentials@v2",
			wantErr:  false,
			wantType: UsesTypeAction,
			wantPin:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref, err := resolver.Parse(tt.uses)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			if ref.Type != tt.wantType {
				t.Errorf("Type = %v, want %v", ref.Type, tt.wantType)
			}
			if ref.IsPinned != tt.wantPin {
				t.Errorf("IsPinned = %v, want %v", ref.IsPinned, tt.wantPin)
			}
		})
	}
}
