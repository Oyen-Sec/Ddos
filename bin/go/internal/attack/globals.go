package attack

import (
	"sync"
	"ddos-go-engine/internal/proxy"
)

type AttackConfig struct {
	Target       string `json:"target"`
	Method       string `json:"method"`
	Duration     int    `json:"duration"`
	RPS          int    `json:"rps"`
	Threads      int    `json:"threads"`
	ProxyFile    string `json:"proxy_file"`
	ProxyChain   string `json:"proxy_chain"`
	HTTP2        bool   `json:"http2"`
	RapidReset   bool   `json:"rapid_reset"`
	OriginIP     string `json:"origin_ip"`
	Timeout      int    `json:"timeout"`
	KeepAlive    int    `json:"keep_alive"`
	MethodType   string `json:"method_type"`
	MaxConns     int    `json:"max_conns"`
}

type AttackMetrics struct {
	TotalRequests   int64   `json:"total_requests"`
	Completed       int64   `json:"completed"`
	Failed          int64   `json:"failed"`
	Timeout         int64   `json:"timeout"`
	CurrentRPS      float64 `json:"current_rps"`
	PeakRPS         float64 `json:"peak_rps"`
	AvgResponseTime float64 `json:"avg_response_time_ms"`
	Elapsed         float64 `json:"elapsed_seconds"`
	Status          string  `json:"status"`
	InFlight        int64   `json:"in_flight"`
	GCRuns          int64   `json:"gc_runs"`
}

const Version = "5.0"

var (
	metrics          AttackMetrics
	metricsMu        sync.RWMutex
	stopFlag         int32
	http2Enabled     bool
	globalProxyChain string
	globalProxyPool  *proxy.ProxyPool
)
