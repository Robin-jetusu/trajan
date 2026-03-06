//go:build integration

package jenkins

import (
	"bytes"
	"os"
	"testing"

	"github.com/spf13/cobra"
)

// newTestRootCmd creates a minimal root command that mirrors the real root's
// persistent flags (token, output, verbose, username). This is necessary because
// JenkinsCmd is normally a child of the real rootCmd and cmdutil helpers like
// GetTokenForPlatform look up flags via cmd.Root().PersistentFlags().
func newTestRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use: "trajan",
	}
	root.PersistentFlags().String("token", "", "")
	root.PersistentFlags().String("output", "console", "")
	root.PersistentFlags().Bool("verbose", false, "")
	root.PersistentFlags().String("proxy", "", "")
	root.PersistentFlags().String("socks-proxy", "", "")

	// Re-create JenkinsCmd to avoid state leakage between tests.
	jenkinsCmd := &cobra.Command{
		Use:   "jenkins",
		Short: "Jenkins pipeline security operations",
	}
	jenkinsCmd.PersistentFlags().String("username", "", "")
	jenkinsCmd.AddCommand(enumerateCmd)

	root.AddCommand(jenkinsCmd)
	return root
}

func TestIntegration_EnumerateAccessCmd(t *testing.T) {
	url := os.Getenv("JENKINS_TEST_URL")
	if url == "" {
		t.Skip("JENKINS_TEST_URL not set")
	}
	user := os.Getenv("JENKINS_TEST_USER")
	token := os.Getenv("JENKINS_TEST_TOKEN")

	// Set env vars so cmdutil.GetTokenForPlatform / GetUsernameForPlatform
	// can resolve credentials even without --token flag on the root.
	t.Setenv("JENKINS_TOKEN", token)
	t.Setenv("JENKINS_USERNAME", user)

	root := newTestRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"jenkins", "enumerate", "access", "--url", url})
	if err := root.Execute(); err != nil {
		t.Fatalf("enumerate access failed: %v\nOutput: %s", err, buf.String())
	}
	t.Logf("Output:\n%s", buf.String())
}

func TestIntegration_EnumerateJobsCmd(t *testing.T) {
	url := os.Getenv("JENKINS_TEST_URL")
	if url == "" {
		t.Skip("JENKINS_TEST_URL not set")
	}
	user := os.Getenv("JENKINS_TEST_USER")
	token := os.Getenv("JENKINS_TEST_TOKEN")

	t.Setenv("JENKINS_TOKEN", token)
	t.Setenv("JENKINS_USERNAME", user)

	root := newTestRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"jenkins", "enumerate", "jobs", "--url", url})
	if err := root.Execute(); err != nil {
		t.Fatalf("enumerate jobs failed: %v\nOutput: %s", err, buf.String())
	}
	t.Logf("Output:\n%s", buf.String())
}
