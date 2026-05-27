package proxy

import (
	"bufio"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type ProxyRotator struct {
	proxies   []*url.URL
	mu        sync.RWMutex
	idx       uint64
	transport map[string]*http.Transport
	tmu       sync.RWMutex
	timeout   int
	http2     bool
}

func NewProxyRotator(filePath string, timeout int, http2Enabled bool) *ProxyRotator {
	pr := &ProxyRotator{
		transport: make(map[string]*http.Transport),
		timeout:   timeout,
		http2:     http2Enabled,
	}
	if filePath != "" {
		pr.LoadFile(filePath)
	}
	return pr
}

func parseProxyLine(line string) *url.URL {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return nil
	}

	hasScheme := false
	for _, prefix := range []string{"http://", "https://", "socks5://", "socks5h://", "socks4://"} {
		if strings.HasPrefix(strings.ToLower(line), prefix) {
			hasScheme = true
			break
		}
	}

	if !hasScheme {
		var user, pass, hostPort string

		if strings.Contains(line, "@") {
			parts := strings.SplitN(line, "@", 2)
			authParts := strings.SplitN(parts[0], ":", 2)
			user = authParts[0]
			if len(authParts) == 2 {
				pass = authParts[1]
			}
			hostPort = parts[1]
		} else {
			parts := strings.Split(line, ":")
			if len(parts) == 2 {
				hostPort = line
			} else if len(parts) == 4 {
				hostPort = parts[0] + ":" + parts[1]
				user = parts[2]
				pass = parts[3]
			} else {
				return nil
			}
		}

		var raw string
		if user != "" {
			raw = "http://" + user + ":" + pass + "@" + hostPort
		} else {
			raw = "http://" + hostPort
		}
		u, err := url.Parse(raw)
		if err != nil {
			return nil
		}
		return u
	}

	u, err := url.Parse(line)
	if err != nil {
		return nil
	}
	return u
}

func (pr *ProxyRotator) LoadFile(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()

	count := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		u := parseProxyLine(scanner.Text())
		if u != nil {
			pr.mu.Lock()
			pr.proxies = append(pr.proxies, u)
			pr.mu.Unlock()
			count++
		}
	}
	return count
}

func (pr *ProxyRotator) Count() int {
	pr.mu.RLock()
	defer pr.mu.RUnlock()
	return len(pr.proxies)
}

func (pr *ProxyRotator) Next() *url.URL {
	pr.mu.RLock()
	defer pr.mu.RUnlock()
	if len(pr.proxies) == 0 {
		return nil
	}
	idx := atomic.AddUint64(&pr.idx, 1)
	return pr.proxies[idx%uint64(len(pr.proxies))]
}

func (pr *ProxyRotator) GetTransport(proxyURL *url.URL) *http.Transport {
	if proxyURL == nil {
		return nil
	}
	key := proxyURL.String()

	pr.tmu.RLock()
	if t, ok := pr.transport[key]; ok {
		pr.tmu.RUnlock()
		return t
	}
	pr.tmu.RUnlock()

	pr.tmu.Lock()
	defer pr.tmu.Unlock()
	if t, ok := pr.transport[key]; ok {
		return t
	}

	dialer := &net.Dialer{
		Timeout:   time.Duration(pr.timeout) * time.Second,
		KeepAlive: 30 * time.Second,
	}

	t := &http.Transport{
		Proxy:               http.ProxyURL(proxyURL),
		DialContext:         dialer.DialContext,
		MaxIdleConns:        500,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		TLSHandshakeTimeout: time.Duration(pr.timeout) * time.Second,
		ForceAttemptHTTP2:   pr.http2,
	}

	pr.transport[key] = t
	return t
}

func (pr *ProxyRotator) CloseAll() {
	pr.tmu.Lock()
	defer pr.tmu.Unlock()
	for _, t := range pr.transport {
		t.CloseIdleConnections()
	}
}
