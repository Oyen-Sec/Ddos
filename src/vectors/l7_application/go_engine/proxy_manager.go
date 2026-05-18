package main

import (
	"bufio"
	"encoding/json"
	"math/rand"
	"os"
	"strings"
	"sync"
)

type ProxyManager struct {
	Proxies []string
	mu      sync.Mutex
}

func NewProxyManager(filePath string) *ProxyManager {
	pm := &ProxyManager{}
	pm.LoadProxies(filePath)
	return pm
}

func (pm *ProxyManager) LoadProxies(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		// If it's a JSON file from Python
		if strings.HasSuffix(filePath, ".json") {
			type ProxyData struct {
				Proxies []string `json:"proxies"`
			}
			var data ProxyData
			bytes, _ := os.ReadFile(filePath)
			json.Unmarshal(bytes, &data)
			pm.Proxies = data.Proxies
			return nil
		}
		return err
	}
	defer file.Close()

	var proxies []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			proxies = append(proxies, line)
		}
	}
	pm.Proxies = proxies
	return scanner.Err()
}

func (pm *ProxyManager) GetRandomProxy() string {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	if len(pm.Proxies) == 0 {
		return ""
	}
	return pm.Proxies[rand.Intn(len(pm.Proxies))]
}
