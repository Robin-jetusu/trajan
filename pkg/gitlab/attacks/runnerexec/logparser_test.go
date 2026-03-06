// pkg/gitlab/attacks/runnerexec/logparser_test.go
package runnerexec

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractBase64Output_ValidOutput(t *testing.T) {
	logs := `Running job...
$ echo "test"
test
$ (whoami) 2>&1 | base64 -w0 || (whoami) 2>&1 | base64 || true
cm9vdApteWhvc3Q=
$ echo "done"
Job succeeded`

	output, err := ExtractBase64Output(logs, "whoami")

	assert.NoError(t, err)
	assert.Contains(t, output, "root")
}

func TestExtractBase64Output_CommandNotFound(t *testing.T) {
	logs := `Running job...
$ echo "test"
Job succeeded`

	_, err := ExtractBase64Output(logs, "whoami")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "command not found in logs")
}

func TestExtractBase64Output_EmptyOutput(t *testing.T) {
	logs := `Running job...
$ (which curl) 2>&1 | base64 -w0 || (which curl) 2>&1 | base64 || true
$ echo "done"
Job succeeded`

	output, err := ExtractBase64Output(logs, "which curl")

	assert.NoError(t, err)
	assert.Equal(t, "", output)
}

func TestExtractBase64Output_WithTimestamps(t *testing.T) {
	logs := `2026-02-26T02:59:30.359671Z 01O $ (echo test) 2>&1 | base64 -w0 || (echo test) 2>&1 | base64 || true
2026-02-26T02:59:30.359691Z 01O dGVzdAo=
2026-02-26T02:59:30.359692Z 01O $ echo "done"
Job succeeded`

	output, err := ExtractBase64Output(logs, "echo test")

	assert.NoError(t, err)
	assert.Equal(t, "test\n", output)
}

func TestExtractBase64Output_WithANSICodes(t *testing.T) {
	logs := `Running job...
$ (hostname) 2>&1 | base64 -w0 || (hostname) 2>&1 | base64 || true
bXlob3N0Cg==` + "\x1b[32;1m$ echo done\x1b[0;m" + `
Job succeeded`

	output, err := ExtractBase64Output(logs, "hostname")

	assert.NoError(t, err)
	assert.Equal(t, "myhost\n", output)
}

func TestExtractBase64Output_MultilineBase64(t *testing.T) {
	// macOS base64 wraps at 76 chars by default
	logs := `$ (cat file) 2>&1 | base64 -w0 || (cat file) 2>&1 | base64 || true
TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdC
4gU2VkIGRvIGVpdXNtb2QgdGVtcG9yIGluY2lkaWR1bnQgdXQgbGFib3Jl
$ echo done`

	output, err := ExtractBase64Output(logs, "cat file")

	assert.NoError(t, err)
	assert.Contains(t, output, "Lorem ipsum")
}
