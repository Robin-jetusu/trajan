package common

import (
	"archive/zip"
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDownloadFromSignedURL_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test-content"))
	}))
	defer server.Close()

	data, err := DownloadFromSignedURL(server.URL)
	require.NoError(t, err)
	assert.Equal(t, []byte("test-content"), data)
}

func TestDownloadFromSignedURL_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("access denied"))
	}))
	defer server.Close()

	_, err := DownloadFromSignedURL(server.URL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "403")
}

func TestDownloadFromSignedURL_InvalidURL(t *testing.T) {
	_, err := DownloadFromSignedURL("http://localhost:99999/nonexistent")
	require.Error(t, err)
}

func TestExtractFilesFromZip_Valid(t *testing.T) {
	// Create a valid zip in memory
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	f1, err := w.Create("encrypted/output_updated.json")
	require.NoError(t, err)
	f1.Write([]byte("encrypted-content"))

	f2, err := w.Create("encrypted/lookup.txt")
	require.NoError(t, err)
	f2.Write([]byte("encrypted-key"))

	w.Close()

	files, err := ExtractFilesFromZip(buf.Bytes())
	require.NoError(t, err)
	assert.Len(t, files, 2)
	assert.Equal(t, []byte("encrypted-content"), files["output_updated.json"])
	assert.Equal(t, []byte("encrypted-key"), files["lookup.txt"])
}

func TestExtractFilesFromZip_Empty(t *testing.T) {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	w.Close()

	_, err := ExtractFilesFromZip(buf.Bytes())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no files found")
}

func TestExtractFilesFromZip_InvalidData(t *testing.T) {
	_, err := ExtractFilesFromZip([]byte("not a zip"))
	require.Error(t, err)
}

func TestExtractFilesFromZip_SkipsDirectories(t *testing.T) {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	// Add a directory entry
	_, err := w.Create("encrypted/")
	require.NoError(t, err)

	// Add a file
	f, err := w.Create("encrypted/data.bin")
	require.NoError(t, err)
	f.Write([]byte("some data"))

	w.Close()

	files, err := ExtractFilesFromZip(buf.Bytes())
	require.NoError(t, err)
	assert.Len(t, files, 1)
	assert.Equal(t, []byte("some data"), files["data.bin"])
}
