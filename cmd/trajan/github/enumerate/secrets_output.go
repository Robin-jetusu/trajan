package enumerate

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/praetorian-inc/trajan/pkg/github"
)

// outputSecretsJSON outputs secrets enumeration in JSON format
func outputSecretsJSON(result *github.SecretsResult, outputFile string) error {
	enc := json.NewEncoder(os.Stdout)
	if outputFile != "" {
		f, err := os.Create(outputFile)
		if err != nil {
			return fmt.Errorf("creating output file: %w", err)
		}
		defer f.Close()
		enc = json.NewEncoder(f)
	}

	enc.SetIndent("", "  ")
	return enc.Encode(result)
}
