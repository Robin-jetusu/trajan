package enumerate

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	gitlabplatform "github.com/praetorian-inc/trajan/pkg/gitlab"
)

func outputRunnersConsole(results []*gitlabplatform.RunnersEnumerateResult, showGapsOnly bool) error {
	fmt.Printf("=== Runner Enumeration ===\n\n")

	// Collect unique runners by ID to avoid counting duplicates
	uniqueRunners := make(map[int]gitlabplatform.RunnerInfo)
	instanceRunners := make(map[int]gitlabplatform.RunnerInfo)
	groupRunners := make(map[int]gitlabplatform.RunnerInfo)
	projectRunners := make(map[int]gitlabplatform.RunnerInfo)
	historicalRunners := make(map[string]gitlabplatform.RunnerInfo) // Deduplicate by Description
	totalMissingTags := 0

	for _, result := range results {
		// Collect instance runners
		for _, runner := range result.InstanceRunners {
			uniqueRunners[runner.ID] = runner
			instanceRunners[runner.ID] = runner
		}

		// Collect group runners
		for _, runner := range result.GroupRunners {
			uniqueRunners[runner.ID] = runner
			groupRunners[runner.ID] = runner
		}

		// Collect project runners
		for _, runner := range result.ProjectRunners {
			uniqueRunners[runner.ID] = runner
			projectRunners[runner.ID] = runner
		}

		// Collect historical runners (deduplicate by description since they lack IDs)
		for _, runner := range result.HistoricalRunners {
			historicalRunners[runner.Description] = runner
		}
		// Count missing tags if workflow analysis was performed
		if len(result.WorkflowTags.RequiredTags) > 0 {
			totalMissingTags += len(result.WorkflowTags.MissingTags)
		}
	}

	// Calculate totals from unique runners
	totalRunners := len(uniqueRunners)
	totalOnline := 0
	totalOffline := 0
	for _, runner := range uniqueRunners {
		if runner.Online {
			totalOnline++
		} else {
			totalOffline++
		}
	}
	totalInstance := len(instanceRunners)
	totalGroup := len(groupRunners)
	totalProject := len(projectRunners)

	if totalRunners == 0 && len(results) > 0 && len(results[0].Errors) == 0 {
		fmt.Println("No runners found")
		return nil
	}

	// Print summary
	fmt.Printf("Total: %d runners (%d online, %d offline)\n", totalRunners, totalOnline, totalOffline)
	if totalInstance > 0 || totalGroup > 0 || totalProject > 0 {
		fmt.Printf("  * Instance: %d\n", totalInstance)
		fmt.Printf("  * Group: %d\n", totalGroup)
		fmt.Printf("  * Project: %d\n", totalProject)
	}

	// If --show-gaps, filter to only show results with missing tags
	if showGapsOnly {
		filtered := make([]*gitlabplatform.RunnersEnumerateResult, 0)
		for _, result := range results {
			if len(result.WorkflowTags.MissingTags) > 0 {
				filtered = append(filtered, result)
			}
		}
		results = filtered

		if len(results) == 0 {
			fmt.Println("\nNo missing workflow tags found!")
			return nil
		}
	}

	// Print unique runners by type
	fmt.Println()
	printUniqueRunnersByType(instanceRunners, groupRunners, projectRunners)

	// Print historical runners from log analysis (deduplicated across all projects)
	if len(historicalRunners) > 0 {
		// Convert map to slice for printing
		runners := make([]gitlabplatform.RunnerInfo, 0, len(historicalRunners))
		for _, runner := range historicalRunners {
			runners = append(runners, runner)
		}
		printHistoricalRunners(runners)
	}

	// Print workflow tag analysis from results
	for _, result := range results {
		if len(result.WorkflowTags.RequiredTags) > 0 {
			fmt.Println()
			printWorkflowTagAnalysis(result.WorkflowTags, showGapsOnly)
		}
	}

	// Print errors from results
	for _, result := range results {
		if len(result.Errors) > 0 {
			fmt.Println()
			fmt.Printf("Errors:\n")
			for _, err := range result.Errors {
				fmt.Printf("  * %s\n", err)
			}
		}
	}

	// Print warnings section
	if totalMissingTags > 0 && !showGapsOnly {
		fmt.Printf("\nWarnings:\n")
		fmt.Printf("  * %d workflow tags are missing from available runners\n", totalMissingTags)
		fmt.Printf("  * Use --show-gaps to filter to only missing tags\n")
		fmt.Printf("  * Workflows requiring these tags will fail or queue indefinitely\n")
	}

	return nil
}

func printUniqueRunnersByType(instanceRunners, groupRunners, projectRunners map[int]gitlabplatform.RunnerInfo) {
	// Instance runners
	if len(instanceRunners) > 0 {
		fmt.Printf("Instance Runners (%d):\n", len(instanceRunners))
		// Sort runner IDs for deterministic output
		ids := make([]int, 0, len(instanceRunners))
		for id := range instanceRunners {
			ids = append(ids, id)
		}
		sort.Ints(ids)
		for _, id := range ids {
			runner := instanceRunners[id]
			printRunnerInfo(runner, "  ")
		}
	}

	// Group runners
	if len(groupRunners) > 0 {
		fmt.Printf("Group Runners (%d):\n", len(groupRunners))
		// Sort runner IDs for deterministic output
		ids := make([]int, 0, len(groupRunners))
		for id := range groupRunners {
			ids = append(ids, id)
		}
		sort.Ints(ids)
		for _, id := range ids {
			runner := groupRunners[id]
			printRunnerInfo(runner, "  ")
		}
	}

	// Project runners
	if len(projectRunners) > 0 {
		fmt.Printf("Project Runners (%d):\n", len(projectRunners))
		// Sort runner IDs for deterministic output
		ids := make([]int, 0, len(projectRunners))
		for id := range projectRunners {
			ids = append(ids, id)
		}
		sort.Ints(ids)
		for _, id := range ids {
			runner := projectRunners[id]
			printRunnerInfo(runner, "  ")
		}
	}
}

func printHistoricalRunners(historical []gitlabplatform.RunnerInfo) {
	if len(historical) == 0 {
		return
	}

	fmt.Printf("\nHistorical Runners (from logs) (%d):\n", len(historical))
	fmt.Printf("  These runners were discovered by analyzing recent pipeline execution logs.\n")
	fmt.Printf("  They may be offline or decommissioned but were recently active.\n\n")

	for _, runner := range historical {
		// For historical runners, use description as name since they don't have IDs
		fmt.Printf("  * %s\n", runner.Description)

		if len(runner.Tags) > 0 {
			fmt.Printf("    - Tags: %s\n", strings.Join(runner.Tags, ", "))
		}

		if runner.Version != "" {
			fmt.Printf("    - Version: %s\n", runner.Version)
		}

		if runner.Executor != "" {
			fmt.Printf("    - Executor: %s\n", runner.Executor)
		}

		if runner.Platform != "" {
			fmt.Printf("    - Platform: %s", runner.Platform)
			if runner.Architecture != "" {
				fmt.Printf(" (%s)", runner.Architecture)
			}
			fmt.Println()
		}

		if runner.LastSeenAt != "" {
			fmt.Printf("    - Last seen: %s\n", runner.LastSeenAt)
		}

		if runner.IsShared {
			fmt.Printf("    - Type: shared\n")
		}
	}
}

func printRunnerInfo(runner gitlabplatform.RunnerInfo, indent string) {
	status := "offline"
	if runner.Online {
		status = "online"
	}

	fmt.Printf("%s* #%d: %s [%s]\n", indent, runner.ID, runner.Description, status)

	if len(runner.Tags) > 0 {
		fmt.Printf("%s  - Tags: %s\n", indent, strings.Join(runner.Tags, ", "))
	} else {
		fmt.Printf("%s  - Tags: none\n", indent)
	}

	if runner.Platform != "" {
		fmt.Printf("%s  - Platform: %s", indent, runner.Platform)
		if runner.Architecture != "" {
			fmt.Printf(" (%s)", runner.Architecture)
		}
		fmt.Println()
	}

	if runner.Version != "" {
		fmt.Printf("%s  - Version: %s\n", indent, runner.Version)
	}

	if runner.Executor != "" {
		fmt.Printf("%s  - Executor: %s\n", indent, runner.Executor)
	}

	if runner.IPAddress != "" {
		fmt.Printf("%s  - IP: %s\n", indent, runner.IPAddress)
	}

	// Show runner type and shared status
	if runner.RunnerType != "" {
		sharedStatus := ""
		if runner.IsShared {
			sharedStatus = " (shared)"
		}
		fmt.Printf("%s  - Type: %s%s\n", indent, runner.RunnerType, sharedStatus)
	}

	if runner.Paused {
		fmt.Printf("%s  - WARNING: Runner is paused\n", indent)
	}

	if !runner.Active {
		fmt.Printf("%s  - WARNING: Runner is inactive\n", indent)
	}
}

func printWorkflowTagAnalysis(analysis gitlabplatform.WorkflowTagAnalysis, showGapsOnly bool) {
	if showGapsOnly {
		// Only show missing tags section
		if len(analysis.MissingTags) > 0 {
			fmt.Printf("Missing Workflow Tags:\n")
			for _, tag := range analysis.MissingTags {
				fmt.Printf("  * %s (MISSING - workflows will fail)\n", tag)
			}
		}
		return
	}

	// Full analysis
	fmt.Printf("Workflow Tag Analysis:\n")
	fmt.Printf("  Projects analyzed: %d\n", analysis.ProjectsAnalyzed)

	if len(analysis.RequiredTags) > 0 {
		fmt.Printf("  Required tags: %s\n", strings.Join(analysis.RequiredTags, ", "))
	} else {
		fmt.Printf("  Required tags: none (workflows use default runners)\n")
	}

	if len(analysis.AvailableTags) > 0 {
		fmt.Printf("  Available tags: %s\n", strings.Join(analysis.AvailableTags, ", "))
	} else {
		fmt.Printf("  Available tags: none\n")
	}

	if len(analysis.MissingTags) > 0 {
		fmt.Printf("  Missing tags:\n")
		for _, tag := range analysis.MissingTags {
			fmt.Printf("    * %s (MISSING - workflows will fail)\n", tag)
		}
	} else {
		fmt.Printf("  Missing tags: none (all workflow requirements satisfied)\n")
	}
}

// outputRunnersJSON outputs runner enumeration results in JSON format.
// Note: JSON output preserves raw data without deduplication, unlike console output
// which deduplicates runners by ID. This allows consumers to see the full context
// of where each runner was discovered (instance/group/project level).
func outputRunnersJSON(results []*gitlabplatform.RunnersEnumerateResult, outputFile string) error {
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

	// For single project, output the single result directly
	// For multiple projects, output as array
	if len(results) == 1 {
		return enc.Encode(results[0])
	}
	return enc.Encode(results)
}
