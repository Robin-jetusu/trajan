//go:build ignore

// server.go is a local development server for the Trajan browser UI.
// It serves static files and proxies Azure DevOps API requests to bypass
// browser CORS restrictions (Azure DevOps does not send Access-Control-Allow-Origin).
//
// Usage: go run server.go
// Then open http://localhost:8080 in your browser.
package main

import (
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func main() {
	mux := http.NewServeMux()

	// Proxy Azure DevOps API calls through localhost to bypass CORS.
	// Path format: /azdo-proxy/{host}/{rest-of-path}
	mux.HandleFunc("/azdo-proxy/", handleADOProxy)

	// Serve browser UI static files
	mux.Handle("/", http.FileServer(http.Dir(".")))

	log.Println("Trajan dev server running at http://localhost:8080")
	log.Println("Azure DevOps API calls are proxied via /azdo-proxy/ to bypass CORS")
	log.Fatal(http.ListenAndServe(":8080", mux))
}

// isAllowedADOHost returns true only for Azure DevOps hostnames that the proxy
// is permitted to forward to. This prevents SSRF: without this check a malicious
// page open in the same browser could call localhost:8080/azdo-proxy/<any-host>/...
// and reach internal services using the developer's network context.
//
// Allowed: dev.azure.com and *.visualstudio.com (legacy ADO hostname).
func isAllowedADOHost(host string) bool {
	if host == "dev.azure.com" {
		return true
	}
	// Allow *.visualstudio.com (e.g. myorg.visualstudio.com)
	parts := strings.Split(host, ".")
	if len(parts) >= 3 && parts[len(parts)-2] == "visualstudio" && parts[len(parts)-1] == "com" {
		return true
	}
	return false
}

// handleADOProxy forwards browser requests to Azure DevOps API endpoints.
// The browser calls localhost:8080/azdo-proxy/dev.azure.com/myorg/_apis/...
// and this handler forwards them to https://dev.azure.com/myorg/_apis/...
// Since the proxy makes server-side requests, no CORS restrictions apply.
func handleADOProxy(w http.ResponseWriter, r *http.Request) {
	// Restrict CORS to same origin only — this server only serves the local UI.
	w.Header().Set("Access-Control-Allow-Origin", "http://localhost:8080")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Accept")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Extract target host and path: /azdo-proxy/{host}/{path}
	trimmed := strings.TrimPrefix(r.URL.Path, "/azdo-proxy/")
	idx := strings.Index(trimmed, "/")
	var host, restPath string
	if idx == -1 {
		host, restPath = trimmed, "/"
	} else {
		host, restPath = trimmed[:idx], trimmed[idx:]
	}

	if host == "" {
		http.Error(w, "missing target host in proxy path", http.StatusBadRequest)
		return
	}

	// Allowlist check — only forward to Azure DevOps hostnames.
	if !isAllowedADOHost(host) {
		http.Error(w, "host not allowed", http.StatusForbidden)
		return
	}

	target := &url.URL{
		Scheme:   "https",
		Host:     host,
		Path:     restPath,
		RawQuery: r.URL.RawQuery,
	}

	proxyReq, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), r.Body)
	if err != nil {
		http.Error(w, "failed to build proxy request: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Forward request headers (Authorization, Content-Type, etc.), skip hop-by-hop
	hopByHop := map[string]bool{
		"Connection": true, "Keep-Alive": true, "Proxy-Connection": true,
		"Transfer-Encoding": true, "Upgrade": true,
	}
	for k, vs := range r.Header {
		if hopByHop[k] {
			continue
		}
		for _, v := range vs {
			proxyReq.Header.Add(k, v)
		}
	}

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(proxyReq)
	if err != nil {
		http.Error(w, "proxy request failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Forward response headers, skip hop-by-hop and strip Www-Authenticate
	// to prevent the browser from showing its native Basic Auth dialog when
	// ADO returns 401 (e.g., insufficient permissions on CheckPermission calls).
	for k, vs := range resp.Header {
		if hopByHop[k] || k == "Www-Authenticate" {
			continue
		}
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}
