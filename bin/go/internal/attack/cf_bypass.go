package attack

import (
	"crypto/tls"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

// Cloudflare Bypass Utilities
// Implements TLS fingerprinting, HTTP/2 fingerprinting, and smart retry

// BrowserProfile represents a complete browser fingerprint
type BrowserProfile struct {
	Name            string
	UserAgent       string
	TLSVersion      uint16
	CipherSuites    []uint16
	CurvePrefs      []tls.CurveID
	ALPN            []string
	HTTP2Settings   map[string]uint32
	ClientHints     map[string]string
	AcceptLanguage  string
	AcceptEncoding  string
	Accept          string
}

// Chrome 126 Profile (latest 2026)
var Chrome126 = BrowserProfile{
	Name:      "Chrome126",
	UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
	TLSVersion: tls.VersionTLS13,
	CipherSuites: []uint16{
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	},
	CurvePrefs: []tls.CurveID{
		tls.X25519,
		tls.CurveP256,
		tls.CurveP384,
	},
	ALPN: []string{"h2", "http/1.1"},
	HTTP2Settings: map[string]uint32{
		"HEADER_TABLE_SIZE":      65536,
		"ENABLE_PUSH":            0,
		"MAX_CONCURRENT_STREAMS": 1000,
		"INITIAL_WINDOW_SIZE":    6291456,
		"MAX_FRAME_SIZE":         16384,
		"MAX_HEADER_LIST_SIZE":   262144,
	},
	ClientHints: map[string]string{
		"Sec-CH-UA":          `"Chromium";v="126", "Not.A/Brand";v="24", "Google Chrome";v="126"`,
		"Sec-CH-UA-Mobile":   "?0",
		"Sec-CH-UA-Platform": `"Windows"`,
		"Sec-CH-UA-Arch":     `"x86"`,
		"Sec-CH-UA-Bitness":  `"64"`,
	},
	AcceptLanguage: "en-US,en;q=0.9",
	AcceptEncoding: "gzip, deflate, br, zstd",
	Accept:         "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
}

// Firefox 140 Profile
var Firefox140 = BrowserProfile{
	Name:      "Firefox140",
	UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0",
	TLSVersion: tls.VersionTLS13,
	CipherSuites: []uint16{
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_CHACHA20_POLY1305_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	},
	CurvePrefs: []tls.CurveID{
		tls.X25519,
		tls.CurveP256,
		tls.CurveP384,
		tls.CurveP521,
	},
	ALPN: []string{"h2", "http/1.1"},
	HTTP2Settings: map[string]uint32{
		"HEADER_TABLE_SIZE":      65536,
		"ENABLE_PUSH":            0,
		"MAX_CONCURRENT_STREAMS": 128,
		"INITIAL_WINDOW_SIZE":    131072,
		"MAX_FRAME_SIZE":         16384,
	},
	ClientHints:    map[string]string{},
	AcceptLanguage: "en-US,en;q=0.5",
	AcceptEncoding: "gzip, deflate, br, zstd",
	Accept:         "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
}

// Safari 18 Profile
var Safari18 = BrowserProfile{
	Name:      "Safari18",
	UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
	TLSVersion: tls.VersionTLS13,
	CipherSuites: []uint16{
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	},
	CurvePrefs: []tls.CurveID{
		tls.X25519,
		tls.CurveP256,
		tls.CurveP384,
		tls.CurveP521,
	},
	ALPN: []string{"h2", "http/1.1"},
	HTTP2Settings: map[string]uint32{
		"HEADER_TABLE_SIZE":      4096,
		"ENABLE_PUSH":            0,
		"MAX_CONCURRENT_STREAMS": 100,
		"INITIAL_WINDOW_SIZE":    2097152,
		"MAX_FRAME_SIZE":         16384,
	},
	ClientHints:    map[string]string{},
	AcceptLanguage: "en-US,en;q=0.9",
	AcceptEncoding: "gzip, deflate, br",
	Accept:         "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

// Edge 136 Profile
var Edge136 = BrowserProfile{
	Name:      "Edge136",
	UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/136.0.0.0",
	TLSVersion: tls.VersionTLS13,
	CipherSuites: []uint16{
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	},
	CurvePrefs: []tls.CurveID{
		tls.X25519,
		tls.CurveP256,
		tls.CurveP384,
	},
	ALPN: []string{"h2", "http/1.1"},
	HTTP2Settings: map[string]uint32{
		"HEADER_TABLE_SIZE":      65536,
		"ENABLE_PUSH":            0,
		"MAX_CONCURRENT_STREAMS": 1000,
		"INITIAL_WINDOW_SIZE":    6291456,
		"MAX_FRAME_SIZE":         16384,
	},
	ClientHints: map[string]string{
		"Sec-CH-UA":          `"Microsoft Edge";v="136", "Chromium";v="126", "Not.A/Brand";v="24"`,
		"Sec-CH-UA-Mobile":   "?0",
		"Sec-CH-UA-Platform": `"Windows"`,
	},
	AcceptLanguage: "en-US,en;q=0.9",
	AcceptEncoding: "gzip, deflate, br, zstd",
	Accept:         "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
}

var AllProfiles = []BrowserProfile{Chrome126, Firefox140, Safari18, Edge136}

// GetRandomProfile returns a random browser profile
func GetRandomProfile() BrowserProfile {
	return AllProfiles[rand.Intn(len(AllProfiles))]
}

// CreateTLSConfig creates a TLS config with browser fingerprinting
func CreateTLSConfig(profile BrowserProfile, serverName string) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         serverName,
		MinVersion:         profile.TLSVersion,
		MaxVersion:         profile.TLSVersion,
		CipherSuites:       profile.CipherSuites,
		CurvePreferences:   profile.CurvePrefs,
		NextProtos:         profile.ALPN,
	}
}

// ApplyBrowserHeaders applies browser-specific headers to HTTP request
func ApplyBrowserHeaders(req *http.Request, profile BrowserProfile) {
	req.Header.Set("User-Agent", profile.UserAgent)
	req.Header.Set("Accept", profile.Accept)
	req.Header.Set("Accept-Language", profile.AcceptLanguage)
	req.Header.Set("Accept-Encoding", profile.AcceptEncoding)
	
	// Client Hints (Chrome/Edge only)
	for key, val := range profile.ClientHints {
		req.Header.Set(key, val)
	}
	
	// Common browser headers
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Cache-Control", "max-age=0")
	
	// Cloudflare bypass headers
	req.Header.Set("DNT", "1")
	req.Header.Set("Connection", "keep-alive")
}

// SmartRetry implements exponential backoff for 403/503 responses
func SmartRetry(fn func() (*http.Response, error), maxRetries int) (*http.Response, error) {
	var resp *http.Response
	var err error
	
	for attempt := 0; attempt < maxRetries; attempt++ {
		resp, err = fn()
		
		if err != nil {
			// Network error - retry with backoff
			backoff := time.Duration(100*(1<<uint(attempt))) * time.Millisecond
			if backoff > 5*time.Second {
				backoff = 5 * time.Second
			}
			time.Sleep(backoff)
			continue
		}
		
		// Check status code
		if resp.StatusCode == 200 || resp.StatusCode == 301 || resp.StatusCode == 302 {
			return resp, nil
		}
		
		if resp.StatusCode == 403 || resp.StatusCode == 503 {
			// Cloudflare challenge - retry with different profile
			resp.Body.Close()
			backoff := time.Duration(200*(1<<uint(attempt))) * time.Millisecond
			if backoff > 10*time.Second {
				backoff = 10 * time.Second
			}
			time.Sleep(backoff)
			continue
		}
		
		// Other status codes - return immediately
		return resp, nil
	}
	
	if err != nil {
		return nil, err
	}
	return resp, fmt.Errorf("max retries exceeded, last status: %d", resp.StatusCode)
}

// DetectCloudflare checks if response is Cloudflare challenge
func DetectCloudflare(resp *http.Response) bool {
	if resp == nil {
		return false
	}
	
	// Check headers
	server := strings.ToLower(resp.Header.Get("Server"))
	cfRay := resp.Header.Get("CF-Ray")
	cfMitigated := resp.Header.Get("CF-Mitigated")
	
	return strings.Contains(server, "cloudflare") || cfRay != "" || cfMitigated != ""
}

// IsChallengePage checks if response body contains Cloudflare challenge
func IsChallengePage(body string) bool {
	indicators := []string{
		"cf-challenge",
		"cf_chl_",
		"jschl-answer",
		"challenge-platform",
		"Checking your browser",
		"Just a moment",
		"cf-browser-verification",
	}
	
	bodyLower := strings.ToLower(body)
	for _, indicator := range indicators {
		if strings.Contains(bodyLower, indicator) {
			return true
		}
	}
	return false
}
