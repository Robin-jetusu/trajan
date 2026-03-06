// Package proxy provides shared HTTP/SOCKS5 proxy transport configuration.
package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/net/proxy"
)

// Config configures proxy settings for HTTP transports.
type Config struct {
	// HTTPProxy is the HTTP proxy URL (e.g., "http://proxy:8080").
	// When set, TLS verification is automatically disabled for interception.
	HTTPProxy string

	// SOCKSProxy is the SOCKS5 proxy URL (e.g., "socks5://proxy:1080").
	// Supports authentication: "socks5://user:pass@proxy:1080".
	SOCKSProxy string

	// SkipTLSVerify disables TLS certificate verification.
	// Automatically enabled when HTTPProxy is set.
	SkipTLSVerify bool
}

// HasProxy reports whether any proxy is configured.
func (c Config) HasProxy() bool { return c.HTTPProxy != "" || c.SOCKSProxy != "" }

// NewTransport creates an http.RoundTripper configured with the given proxy settings.
// Returns (nil, nil) when no proxy is configured. Returns an error if both
// HTTPProxy and SOCKSProxy are specified or if a proxy URL is invalid.
func NewTransport(config Config) (http.RoundTripper, error) {
	if !config.HasProxy() && !config.SkipTLSVerify {
		return nil, nil
	}

	// Validate mutual exclusion.
	if config.HTTPProxy != "" && config.SOCKSProxy != "" {
		return nil, fmt.Errorf("cannot use both HTTP and SOCKS proxy simultaneously")
	}

	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	// Configure TLS (skip verification for HTTP proxy interception or if explicitly requested).
	if config.SkipTLSVerify || config.HTTPProxy != "" {
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // Intentional for proxy testing/Burp interception
		}
	}

	// Configure HTTP proxy.
	if config.HTTPProxy != "" {
		proxyURL, err := url.Parse(config.HTTPProxy)
		if err != nil {
			return nil, fmt.Errorf("parsing HTTP proxy URL: %w", err)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	// Configure SOCKS5 proxy.
	if config.SOCKSProxy != "" {
		proxyURL, err := url.Parse(config.SOCKSProxy)
		if err != nil {
			return nil, fmt.Errorf("parsing SOCKS proxy URL: %w", err)
		}

		auth := &proxy.Auth{}
		if proxyURL.User != nil {
			auth.User = proxyURL.User.Username()
			auth.Password, _ = proxyURL.User.Password()
		}

		dialer, err := proxy.SOCKS5("tcp", proxyURL.Host, auth, proxy.Direct)
		if err != nil {
			return nil, fmt.Errorf("creating SOCKS5 dialer: %w", err)
		}

		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.Dial(network, addr)
		}
	}

	return transport, nil
}
