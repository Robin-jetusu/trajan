package jenkins

import (
	"io"
	"os"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/trajan/pkg/attacks"
	"github.com/praetorian-inc/trajan/pkg/platforms"

	// Register all platforms so registry.GetPlatform("jenkins") works in cleanup path
	_ "github.com/praetorian-inc/trajan/pkg/platforms/all"
)

// captureStdout redirects os.Stdout to a pipe, invokes fn, then returns
// everything written to stdout as a string.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	origStdout := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)

	os.Stdout = w

	fn()

	w.Close()
	os.Stdout = origStdout

	out, err := io.ReadAll(r)
	require.NoError(t, err)
	return string(out)
}

// captureAllOutput redirects both os.Stdout and os.Stderr to pipes, invokes
// fn, then returns everything written to each as strings.
func captureAllOutput(t *testing.T, fn func()) (stdout, stderr string) {
	t.Helper()

	origStdout := os.Stdout
	origStderr := os.Stderr
	rOut, wOut, err := os.Pipe()
	require.NoError(t, err)
	rErr, wErr, err := os.Pipe()
	require.NoError(t, err)

	os.Stdout = wOut
	os.Stderr = wErr

	fn()

	wOut.Close()
	wErr.Close()
	os.Stdout = origStdout
	os.Stderr = origStderr

	outBytes, err := io.ReadAll(rOut)
	require.NoError(t, err)
	errBytes, err := io.ReadAll(rErr)
	require.NoError(t, err)
	return string(outBytes), string(errBytes)
}

// newCleanupTestRoot builds a fresh command tree rooted at "trajan" with the
// jenkins -> attack -> cleanup chain, wiring the RunE to the real
// runAttackCleanup function. Each invocation gets its own flag storage so
// tests do not leak state through package-level variables.
func newCleanupTestRoot() *cobra.Command {
	root := &cobra.Command{Use: "trajan"}
	root.PersistentFlags().String("token", "", "")
	root.PersistentFlags().String("output", "console", "")
	root.PersistentFlags().Bool("verbose", false, "")
	root.PersistentFlags().String("proxy", "", "")
	root.PersistentFlags().String("socks-proxy", "", "")

	jenkinsCmd := &cobra.Command{
		Use:   "jenkins",
		Short: "Jenkins pipeline security operations",
	}
	jenkinsCmd.PersistentFlags().String("username", "", "")
	jenkinsCmd.PersistentFlags().String("password", "", "")

	atkCmd := &cobra.Command{
		Use:   "attack",
		Short: "Execute attacks against Jenkins vulnerabilities",
	}

	cleanupCmd := &cobra.Command{
		Use:   "cleanup",
		Short: "Clean up resources created by attacks",
		RunE:  runAttackCleanup,
	}
	cleanupCmd.Flags().Bool("list", false, "list available sessions")
	cleanupCmd.Flags().StringVar(&attackSessionID, "session", "", "session ID to cleanup")
	cleanupCmd.Flags().StringVar(&attackURL, "url", "", "Jenkins instance URL")

	atkCmd.AddCommand(cleanupCmd)
	jenkinsCmd.AddCommand(atkCmd)
	root.AddCommand(jenkinsCmd)
	return root
}

func TestRunAttackCleanup_NoSessionOrListReturnsError(t *testing.T) {
	// Reset package-level vars to ensure clean state
	attackSessionID = ""
	attackURL = ""

	root := newCleanupTestRoot()
	root.SetArgs([]string{"jenkins", "attack", "cleanup"})

	err := root.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must specify --session")
}

func TestRunAttackCleanup_SessionWithoutURLReturnsError(t *testing.T) {
	// Use a temp HOME so sessions are isolated and cleaned up
	origHome := os.Getenv("HOME")
	tmpDir := t.TempDir()
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", origHome)

	// Reset package-level vars
	attackSessionID = ""
	attackURL = ""

	// Create and save a session file so LoadSession succeeds
	sessionID := "test-cleanup-sess"
	target := platforms.Target{Type: platforms.TargetOrg, Value: "http://jenkins.example.com"}
	session := attacks.NewSession(sessionID, target, "jenkins", "")
	session.AddResult(&attacks.AttackResult{
		Plugin:  "test-plugin",
		Success: true,
		Message: "test result",
	})
	err := session.Save()
	require.NoError(t, err)

	root := newCleanupTestRoot()
	root.SetArgs([]string{"jenkins", "attack", "cleanup", "--session", sessionID})

	err = root.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must specify --url")
}

func TestRunAttackCleanup_ListSessions(t *testing.T) {
	origHome := os.Getenv("HOME")
	tmpDir := t.TempDir()
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", origHome)

	attackSessionID = ""
	attackURL = ""

	target := platforms.Target{Type: platforms.TargetOrg, Value: "http://jenkins.example.com"}

	// Session 1: with an artifact
	sess1 := attacks.NewSession("sess-with-artifacts", target, "jenkins", "")
	sess1.AddResult(&attacks.AttackResult{
		Plugin:  "job-injection",
		Success: true,
		Message: "injected job",
		Artifacts: []attacks.Artifact{
			{Type: attacks.ArtifactWorkflow, Identifier: "test-job", Description: "injected job"},
		},
	})
	require.NoError(t, sess1.Save())

	// Session 2: without artifacts
	sess2 := attacks.NewSession("sess-no-artifacts", target, "jenkins", "")
	sess2.AddResult(&attacks.AttackResult{
		Plugin:  "credential-dump",
		Success: true,
		Message: "dumped creds",
	})
	require.NoError(t, sess2.Save())

	root := newCleanupTestRoot()
	root.SetArgs([]string{"jenkins", "attack", "cleanup", "--list"})

	var execErr error
	output := captureStdout(t, func() {
		execErr = root.Execute()
	})

	require.NoError(t, execErr)
	assert.Contains(t, output, "Available Sessions")
	assert.Contains(t, output, "sess-with-artifacts")
	assert.Contains(t, output, "sess-no-artifacts")
}

func TestRunAttackCleanup_SessionAll_NoSessions(t *testing.T) {
	origHome := os.Getenv("HOME")
	tmpDir := t.TempDir()
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", origHome)

	attackSessionID = ""
	attackURL = ""

	root := newCleanupTestRoot()
	root.SetArgs([]string{"jenkins", "attack", "cleanup", "--session", "all"})

	var execErr error
	output := captureStdout(t, func() {
		execErr = root.Execute()
	})

	require.NoError(t, execErr)
	assert.Contains(t, output, "No sessions to clean up.")
}

func TestRunAttackCleanup_SessionAll_SkipsArtifactsWithoutURL(t *testing.T) {
	origHome := os.Getenv("HOME")
	tmpDir := t.TempDir()
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", origHome)

	attackSessionID = ""
	attackURL = ""

	target := platforms.Target{Type: platforms.TargetOrg, Value: "http://jenkins.example.com"}

	// Create a session WITH artifacts and cleanup actions
	sess := attacks.NewSession("sess-needs-cleanup", target, "jenkins", "")
	sess.AddResult(&attacks.AttackResult{
		Plugin:  "job-injection",
		Success: true,
		Message: "injected job",
		Artifacts: []attacks.Artifact{
			{Type: attacks.ArtifactWorkflow, Identifier: "test-job"},
		},
		CleanupActions: []attacks.CleanupAction{
			{Type: attacks.ArtifactWorkflow, Identifier: "test-job", Action: "delete"},
		},
	})
	require.NoError(t, sess.Save())

	root := newCleanupTestRoot()
	root.SetArgs([]string{"jenkins", "attack", "cleanup", "--session", "all"})

	var execErr error
	stdoutStr, stderrStr := captureAllOutput(t, func() {
		execErr = root.Execute()
	})

	// No error is returned even though the session was skipped
	require.NoError(t, execErr)
	// The stderr output should indicate the session was skipped because no --url was provided
	assert.Contains(t, stderrStr, "skipping")
	// The stdout summary should report 1 failed
	assert.Contains(t, stdoutStr, "1 failed")
}

func TestRunAttackCleanup_SessionAll_CleansZeroArtifactSessions(t *testing.T) {
	origHome := os.Getenv("HOME")
	tmpDir := t.TempDir()
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", origHome)

	attackSessionID = ""
	attackURL = ""

	target := platforms.Target{Type: platforms.TargetOrg, Value: "http://jenkins.example.com"}

	// Create 2 sessions with NO artifacts
	sess1 := attacks.NewSession("clean-sess-1", target, "jenkins", "")
	require.NoError(t, sess1.Save())

	sess2 := attacks.NewSession("clean-sess-2", target, "jenkins", "")
	require.NoError(t, sess2.Save())

	root := newCleanupTestRoot()
	root.SetArgs([]string{"jenkins", "attack", "cleanup", "--session", "all"})

	var execErr error
	output := captureStdout(t, func() {
		execErr = root.Execute()
	})

	require.NoError(t, execErr)
	assert.Contains(t, output, "Cleaned up 2 sessions")

	// Verify sessions are actually deleted
	remaining, err := attacks.ListSessions()
	require.NoError(t, err)
	assert.Empty(t, remaining)
}
