package enumerate

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/praetorian-inc/trajan/pkg/github"
)

// outputReposJSON outputs repository enumeration in JSON format
func outputReposJSON(result *github.ReposEnumerateResult, outputFile string) error {
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
