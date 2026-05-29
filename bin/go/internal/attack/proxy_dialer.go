package attack

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/txthinking/socks5"
)

var poolClients sync.Map

func parseProxyAddr(proxyChain string) (string, string, string) {
	proxyChain = strings.TrimSpace(proxyChain)
	proxyType := "socks5"

	for _, prefix := range []string{"socks5://", "socks5h://", "socks4://", "socks4a://", "http://", "https://"} {
		if strings.HasPrefix(strings.ToLower(proxyChain), prefix) {
			proxyType = strings.TrimSuffix(strings.ToLower(prefix), "://")
			proxyChain = proxyChain[len(prefix):]
			break
		}
	}

	var username, password string
	if idx := strings.Index(proxyChain, "@"); idx != -1 {
		auth := proxyChain[:idx]
		proxyChain = proxyChain[idx+1:]
		if colonIdx := strings.Index(auth, ":"); colonIdx != -1 {
			username = auth[:colonIdx]
			password = auth[colonIdx+1:]
		}
	}

	return proxyType, proxyChain, username + ":" + password
}

func createSOCKSDialer(proxyAddr string, timeout time.Duration) (*socks5.Client, error) {
	proxyType, addr, auth := parseProxyAddr(proxyAddr)

	if !strings.HasPrefix(proxyType, "socks5") && !strings.HasPrefix(proxyType, "socks4") {
		return nil, fmt.Errorf("unsupported proxy type: %s", proxyType)
	}

	var username, password string
	if auth != ":" {
		parts := strings.SplitN(auth, ":", 2)
		if len(parts) == 2 {
			username = parts[0]
			password = parts[1]
		}
	}

	client := &socks5.Client{
		Server:     addr,
		UserName:   username,
		Password:   password,
		TCPTimeout: int(timeout.Seconds()),
		UDPTimeout: int(timeout.Seconds()),
	}

	return client, nil
}

func getPooledDialer(addr string, timeout time.Duration) (*socks5.Client, error) {
	if cached, ok := poolClients.Load(addr); ok {
		return cached.(*socks5.Client), nil
	}

	client := &socks5.Client{
		Server:     addr,
		TCPTimeout: int(timeout.Seconds()),
		UDPTimeout: int(timeout.Seconds()),
	}

	poolClients.Store(addr, client)
	return client, nil
}

func createDialer(proxyChain string, timeout time.Duration) func(string, string) (net.Conn, error) {
	chain := proxyChain
	if chain == "" {
		chain = globalProxyChain
	}
	if chain != "" {
		socksClient, err := createSOCKSDialer(chain, timeout)
		if err != nil {
			dialer := &net.Dialer{Timeout: timeout}
			return dialer.Dial
		}
		return func(network, addr string) (net.Conn, error) {
			return socksClient.Dial(network, addr)
		}
	}

	if globalProxyPool != nil {
		return func(network, addr string) (net.Conn, error) {
			p := globalProxyPool.Next()
			if p == nil {
				dialer := &net.Dialer{Timeout: timeout}
				return dialer.Dial(network, addr)
			}
			client, err := getPooledDialer(p.Addr, timeout)
			if err != nil {
				globalProxyPool.ReportFail(p.Addr)
				dialer := &net.Dialer{Timeout: timeout}
				return dialer.Dial(network, addr)
			}
			conn, err := client.Dial(network, addr)
			if err != nil {
				globalProxyPool.ReportFail(p.Addr)
				dialer := &net.Dialer{Timeout: timeout}
				return dialer.Dial(network, addr)
			}
			return conn, nil
		}
	}

	dialer := &net.Dialer{Timeout: timeout}
	return dialer.Dial
}

func createDialerWithKeepAlive(proxyChain string, timeout, keepAlive time.Duration) func(context.Context, string, string) (net.Conn, error) {
	chain := proxyChain
	if chain == "" {
		chain = globalProxyChain
	}
	if chain != "" {
		socksClient, err := createSOCKSDialer(chain, timeout)
		if err != nil {
			dialer := &net.Dialer{
				Timeout:   timeout,
				KeepAlive: keepAlive,
			}
			return dialer.DialContext
		}
		return func(_ context.Context, network, addr string) (net.Conn, error) {
			return socksClient.Dial(network, addr)
		}
	}

	if globalProxyPool != nil {
		return func(_ context.Context, network, addr string) (net.Conn, error) {
			p := globalProxyPool.Next()
			if p == nil {
				dialer := &net.Dialer{Timeout: timeout, KeepAlive: keepAlive}
				return dialer.DialContext(context.Background(), network, addr)
			}
			client, err := getPooledDialer(p.Addr, timeout)
			if err != nil {
				globalProxyPool.ReportFail(p.Addr)
				dialer := &net.Dialer{Timeout: timeout, KeepAlive: keepAlive}
				return dialer.DialContext(context.Background(), network, addr)
			}
			conn, err := client.Dial(network, addr)
			if err != nil {
				globalProxyPool.ReportFail(p.Addr)
				dialer := &net.Dialer{Timeout: timeout, KeepAlive: keepAlive}
				return dialer.DialContext(context.Background(), network, addr)
			}
			return conn, nil
		}
	}

	dialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: keepAlive,
	}
	return dialer.DialContext
}
