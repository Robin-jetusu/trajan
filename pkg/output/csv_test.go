package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRenderCSV(t *testing.T) {
	tests := []struct {
		name     string
		headers  []string
		rows     [][]string
		expected string
	}{
		{
			name:    "simple table",
			headers: []string{"Name", "Value"},
			rows: [][]string{
				{"foo", "bar"},
				{"baz", "qux"},
			},
			expected: "Name,Value\nfoo,bar\nbaz,qux\n",
		},
		{
			name:    "with commas",
			headers: []string{"Name", "Description"},
			rows: [][]string{
				{"Project A", "A simple, small project"},
				{"Project B", "Another project, with commas"},
			},
			expected: "Name,Description\nProject A,\"A simple, small project\"\nProject B,\"Another project, with commas\"\n",
		},
		{
			name:     "empty rows",
			headers:  []string{"Column1", "Column2"},
			rows:     [][]string{},
			expected: "Column1,Column2\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := RenderCSV(&buf, tt.headers, tt.rows)
			require.NoError(t, err)

			actual := buf.String()
			assert.Equal(t, tt.expected, actual)
		})
	}
}

func TestRenderCSVMultilineValues(t *testing.T) {
	headers := []string{"ID", "Description"}
	rows := [][]string{
		{"1", "Line 1\nLine 2"},
		{"2", "Simple"},
	}

	var buf bytes.Buffer
	err := RenderCSV(&buf, headers, rows)
	require.NoError(t, err)

	output := buf.String()
	// CSV should quote multiline values
	assert.True(t, strings.Contains(output, "\"Line 1\nLine 2\""))
}
