package proxy

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type PoolProxy struct {
	Addr     string
	Alive    bool
	Latency  time.Duration
	LastUsed time.Time
	FailCnt  int
}

type ProxyPool struct {
	proxies []*PoolProxy
	mu      sync.RWMutex
	idx     int
	client  *http.Client
	sources []string
}

func NewProxyPool() *ProxyPool {
	pp := &ProxyPool{
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: nil,
				DialContext: (&net.Dialer{
					Timeout:   8 * time.Second,
					KeepAlive: 0,
				}).DialContext,
			},
		},
		sources: []string{
			"https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
			"https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
			"https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=10000&country=all",
		},
	}
	// Blocking initial validation of first 200 proxies
	pp.fetchAll()
	fmt.Printf("[pool] Initial fetch: %d proxies (first 200 validated)\n", pp.Count())
	// Background refresh + validate rest
	go func() {
		time.Sleep(2 * time.Second)
		go pp.validateRest()
		ticker := time.NewTicker(5 * time.Minute)
		for range ticker.C {
			pp.fetchAll()
			fmt.Printf("[pool] Refresh: %d proxies\n", pp.Count())
		}
	}()
	return pp
}

func (pp *ProxyPool) refreshLoop() {
	pp.fetchAll()
	fmt.Printf("[pool] Initial fetch complete: %d proxies\n", len(pp.proxies))
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		pp.fetchAll()
		fmt.Printf("[pool] Refresh complete: %d proxies\n", len(pp.proxies))
	}
}

func (pp *ProxyPool) fetchAll() {
	var all []string
	for _, src := range pp.sources {
		addrs := pp.fetchSource(src)
		all = append(all, addrs...)
	}
	pp.validateAndStore(all, 200)
}

func (pp *ProxyPool) validateRest() {
	pp.mu.RLock()
	var addrs []string
	for _, p := range pp.proxies {
		if !p.Alive {
			addrs = append(addrs, p.Addr)
		}
	}
	pp.mu.RUnlock()
	if len(addrs) == 0 {
		return
	}
	more := pp.validateBatch(addrs, 50)
	pp.mu.Lock()
	for _, p := range more {
		pp.proxies = append(pp.proxies, p)
	}
	pp.mu.Unlock()
	fmt.Printf("[pool] Validation complete: %d total proxies\n", pp.Count())
}

func (pp *ProxyPool) fetchSource(url string) []string {
	resp, err := pp.client.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	lines := strings.Split(string(body), "\n")
	var addrs []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, ":") {
			addrs = append(addrs, line)
		}
	}
	return addrs
}

func (pp *ProxyPool) validateAndStore(addrs []string, limit int) {
	if len(addrs) == 0 {
		return
	}
	if limit > 0 && len(addrs) > limit {
		addrs = addrs[:limit]
	}
	alive := pp.validateBatch(addrs, 50)
	pp.mu.Lock()
	pp.proxies = alive
	pp.idx = 0
	pp.mu.Unlock()
}

func (pp *ProxyPool) validateBatch(addrs []string, concurrency int) []*PoolProxy {
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)
	var mu sync.Mutex
	var alive []*PoolProxy

	for _, addr := range addrs {
		wg.Add(1)
		sem <- struct{}{}
		go func(a string) {
			defer wg.Done()
			defer func() { <-sem }()
			start := time.Now()
			conn, err := net.DialTimeout("tcp", a, 5*time.Second)
			if err != nil {
				return
			}
			conn.Close()
			latency := time.Since(start)
			mu.Lock()
			alive = append(alive, &PoolProxy{
				Addr:    a,
				Alive:   true,
				Latency: latency,
			})
			mu.Unlock()
		}(addr)
	}
	wg.Wait()
	return alive
}

func (pp *ProxyPool) Next() *PoolProxy {
	pp.mu.Lock()
	defer pp.mu.Unlock()
	if len(pp.proxies) == 0 {
		return nil
	}
	for i := 0; i < len(pp.proxies); i++ {
		pp.idx = (pp.idx + 1) % len(pp.proxies)
		p := pp.proxies[pp.idx]
		if p.Alive && p.FailCnt < 3 {
			p.LastUsed = time.Now()
			return p
		}
	}
	// If all dead, reset and return first
	for _, p := range pp.proxies {
		p.Alive = true
		p.FailCnt = 0
	}
	pp.idx = 0
	return pp.proxies[0]
}

func (pp *ProxyPool) ReportFail(addr string) {
	pp.mu.Lock()
	defer pp.mu.Unlock()
	for _, p := range pp.proxies {
		if p.Addr == addr {
			p.FailCnt++
			if p.FailCnt >= 3 {
				p.Alive = false
			}
			return
		}
	}
}

func (pp *ProxyPool) Count() int {
	pp.mu.RLock()
	defer pp.mu.RUnlock()
	return len(pp.proxies)
}

func (pp *ProxyPool) AddProxy(addr string) {
	pp.mu.Lock()
	defer pp.mu.Unlock()
	pp.proxies = append(pp.proxies, &PoolProxy{
		Addr:  addr,
		Alive: true,
	})
}
