package attack

import (
	"fmt"
	"net"
	"net/http"
	"runtime"
	"sync/atomic"
	"time"
)

var (
	uaList = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
	}
	uaCounter int64
)

func randomUA() string {
	idx := atomic.AddInt64(&uaCounter, 1)
	return uaList[idx%int64(len(uaList))]
}

func randomIP() string {
	v := atomic.AddInt64(&uaCounter, 1)
	return fmt.Sprintf("%d.%d.%d.%d", (v>>24)&0xFF|1, (v>>16)&0xFF, (v>>8)&0xFF, v&0xFF|1)
}

func rand63() int64 {
	return time.Now().UnixNano() ^ atomic.AddInt64(&uaCounter, 1)
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func max64(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func getMemoryMB() uint64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.Alloc / 1024 / 1024
}

func getTransport(timeout, keepAlive, maxConns int) *http.Transport {
	return &http.Transport{
		MaxIdleConns:        maxConns,
		MaxIdleConnsPerHost: maxConns,
		MaxConnsPerHost:     maxConns,
		IdleConnTimeout:     time.Duration(keepAlive) * time.Second,
		TLSHandshakeTimeout: time.Duration(timeout) * time.Second,
		DisableKeepAlives:   false,
		DisableCompression:  false,
		ForceAttemptHTTP2:   http2Enabled,
		ResponseHeaderTimeout: time.Duration(timeout) * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DialContext: (&net.Dialer{
			Timeout:   time.Duration(timeout) * time.Second,
			KeepAlive: time.Duration(keepAlive) * time.Second,
			DualStack: true,
		}).DialContext,
	}
}


