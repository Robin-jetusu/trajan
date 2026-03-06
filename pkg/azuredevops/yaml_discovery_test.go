package azuredevops

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractServiceConnectionsFromYAML(t *testing.T) {
	tests := []struct {
		name          string
		content       string
		repoName      string
		filePath      string
		expectedCount int
		expectedNames []string
		expectedTypes []string
	}{
		{
			name: "direct azureSubscription field",
			content: `
steps:
  - task: AzureCLI@2
    inputs:
      azureSubscription: 'my-azure-sub'
`,
			repoName:      "test-repo",
			filePath:      "/azure-pipelines.yml",
			expectedCount: 1,
			expectedNames: []string{"my-azure-sub"},
			expectedTypes: []string{"azureSubscription"},
		},
		{
			name: "multiple connection types",
			content: `
steps:
  - task: Docker@2
    inputs:
      containerRegistry: 'docker-registry'
  - task: Kubernetes@1
    inputs:
      kubernetesServiceConnection: 'k8s-conn'
`,
			repoName:      "test-repo",
			filePath:      "/azure-pipelines.yml",
			expectedCount: 2,
			expectedNames: []string{"docker-registry", "k8s-conn"},
			expectedTypes: []string{"containerRegistry", "kubernetesServiceConnection"},
		},
		{
			name: "parameter default with SERVICE_CONNECTION",
			content: `
parameters:
  - name: SERVICE_CONNECTION
    type: string
    default: 'prod-service'
`,
			repoName:      "test-repo",
			filePath:      "/azure-pipelines.yml",
			expectedCount: 1,
			expectedNames: []string{"prod-service"},
			expectedTypes: []string{"parameter-default"},
		},
		{
			name: "azure subscription parameter",
			content: `
parameters:
  - name: AZURE_SUBSCRIPTION
    type: string
    default: 'my-sub'
`,
			repoName:      "test-repo",
			filePath:      "/azure-pipelines.yml",
			expectedCount: 1,
			expectedNames: []string{"my-sub"},
			expectedTypes: []string{"parameter-default"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := extractServiceConnectionsFromYAML(tt.content, tt.repoName, tt.filePath)
			assert.Len(t, actual, tt.expectedCount, "should extract expected number of connections")

			for i, expectedName := range tt.expectedNames {
				found := false
				for _, conn := range actual {
					if conn.Name == expectedName {
						found = true
						assert.Equal(t, tt.repoName, conn.Repository, "repository should match")
						assert.Equal(t, tt.filePath, conn.FilePath, "file path should match")
						if i < len(tt.expectedTypes) {
							assert.Equal(t, tt.expectedTypes[i], conn.UsageType, "usage type should match for %s", expectedName)
						}
						break
					}
				}
				assert.True(t, found, "should find connection named %s", expectedName)
			}
		})
	}
}
