package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type ProxyInfo struct {
	URL          string  `json:"url"`
	Protocol     string  `json:"protocol"`
	Host         string  `json:"host"`
	Port         int     `json:"port"`
	Alive        bool    `json:"alive"`
	ConnectTime  float64 `json:"connect_time_ms"`
	LastChecked  int64   `json:"last_checked"`
	FailCount    int     `json:"fail_count"`
	SuccessCount int     `json:"success_count"`
	RTTEMA       float64 `json:"rtt_ema"`
}

type ProxyManager struct {
	proxies    []*ProxyInfo
	alive      []*ProxyInfo
	dead       []string
	mu         sync.RWMutex
	checkURL   string
	timeout    time.Duration
	maxFail    int
	running    bool
}

func NewProxyManager(checkURL string, timeout int, maxFail int) *ProxyManager {
	return &ProxyManager{
		checkURL: checkURL,
		timeout:  time.Duration(timeout) * time.Second,
		maxFail:  maxFail,
	}
}

func (pm *ProxyManager) LoadFile(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	count := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		pi := parseProxyURL(line)
		if pi != nil {
			pm.mu.Lock()
			pm.proxies = append(pm.proxies, pi)
			pm.mu.Unlock()
			count++
		}
	}
	return count, scanner.Err()
}

func parseProxyURL(rawURL string) *ProxyInfo {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if u.Scheme == "http" || u.Scheme == "https" {
			port = "80"
		} else {
			port = "1080"
		}
	}
	p := 80
	fmt.Sscanf(port, "%d", &p)
	return &ProxyInfo{
		URL:      rawURL,
		Protocol: u.Scheme,
		Host:     host,
		Port:     p,
	}
}

func (pm *ProxyManager) ValidateAll(concurrency int) int {
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)

	pm.mu.RLock()
	proxyList := make([]*ProxyInfo, len(pm.proxies))
	copy(proxyList, pm.proxies)
	pm.mu.RUnlock()

	aliveCount := 0
	var aliveMu sync.Mutex

	for _, pi := range proxyList {
		wg.Add(1)
		sem <- struct{}{}
		go func(p *ProxyInfo) {
			defer wg.Done()
			defer func() { <-sem }()

			if pm.validateProxy(p) {
				aliveMu.Lock()
				pm.mu.Lock()
				pm.alive = append(pm.alive, p)
				pm.mu.Unlock()
				aliveCount++
				aliveMu.Unlock()
			} else {
				pm.mu.Lock()
				pm.dead = append(pm.dead, p.URL)
				pm.mu.Unlock()
			}
		}(pi)
	}

	wg.Wait()
	return aliveCount
}

func (pm *ProxyManager) validateProxy(pi *ProxyInfo) bool {
	start := time.Now()

	switch pi.Protocol {
	case "http", "https":
		proxyURL, _ := url.Parse(pi.URL)
		transport := &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			DialContext: (&net.Dialer{
				Timeout: pm.timeout,
			}).DialContext,
		}
		client := &http.Client{
			Transport: transport,
			Timeout:   pm.timeout,
		}
		resp, err := client.Get(pm.checkURL)
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return false
		}
		pi.ConnectTime = float64(time.Since(start).Milliseconds())
		pi.Alive = true
		pi.LastChecked = time.Now().Unix()
		return true

	case "socks5", "socks4":
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", pi.Host, pi.Port), pm.timeout)
		if err != nil {
			return false
		}
		defer conn.Close()
		pi.ConnectTime = float64(time.Since(start).Milliseconds())
		pi.Alive = true
		pi.LastChecked = time.Now().Unix()
		return true

	default:
		return false
	}
}

func (pm *ProxyManager) GetAliveURLs() []string {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	urls := make([]string, len(pm.alive))
	for i, p := range pm.alive {
		urls[i] = p.URL
	}
	return urls
}

func (pm *ProxyManager) SaveAlive(path string) int {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	content := strings.Join(pm.GetAliveURLs(), "\n")
	os.WriteFile(path, []byte(content+"\n"), 0644)
	return len(pm.alive)
}

func (pm *ProxyManager) Stats() map[string]int {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return map[string]int{
		"total":  len(pm.proxies),
		"alive":  len(pm.alive),
		"dead":   len(pm.dead),
	}
}

func (pm *ProxyManager) HealthLoop(interval int) {
	pm.running = true
	for pm.running {
		time.Sleep(time.Duration(interval) * time.Second)
		if !pm.running {
			break
		}
		pm.mu.Lock()
		alive := make([]*ProxyInfo, 0)
		for _, p := range pm.alive {
			if pm.validateProxy(p) {
				alive = append(alive, p)
			} else {
				p.FailCount++
				if p.FailCount >= pm.maxFail {
					pm.dead = append(pm.dead, p.URL)
				} else {
					alive = append(alive, p)
				}
			}
		}
		pm.alive = alive
		pm.mu.Unlock()
	}
}

func (pm *ProxyManager) Stop() {
	pm.running = false
}

func (pm *ProxyManager) GetProxy() *ProxyInfo {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	if len(pm.alive) == 0 {
		return nil
	}
	p := pm.alive[0]
	pm.alive = append(pm.alive[1:], p)
	return p
}

func (pm *ProxyManager) ReportSuccess(pi *ProxyInfo, rttMs float64) {
	pi.SuccessCount++
	if rttMs > 0 {
		if pi.RTTEMA > 0 {
			pi.RTTEMA = pi.RTTEMA*0.7 + rttMs*0.3
		} else {
			pi.RTTEMA = rttMs
		}
	}
}

func (pm *ProxyManager) ReportFailure(pi *ProxyInfo) {
	pi.FailCount++
	if pi.FailCount >= pm.maxFail {
		pm.mu.Lock()
		for i, p := range pm.alive {
			if p.URL == pi.URL {
				pm.alive = append(pm.alive[:i], pm.alive[i+1:]...)
				pm.dead = append(pm.dead, pi.URL)
				break
			}
		}
		pm.mu.Unlock()
	}
}

func init() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
}
