package attack

import (
	"fmt"
	"net"
	"runtime"
	"time"
)

// ProbePorts quickly checks which TCP ports are open on a target
func ProbePorts(ip string, ports []int, timeout time.Duration) []int {
	var open []int
	results := make(chan int, len(ports))

	for _, p := range ports {
		go func(port int) {
			dial := createDialer("", timeout)
			conn, err := dial("tcp", fmt.Sprintf("%s:%d", ip, port))
			if err != nil {
				results <- 0
				return
			}
			conn.Close()
			results <- port
		}(p)
	}

	timeoutCh := time.After(timeout + 500*time.Millisecond)
	for i := 0; i < len(ports); i++ {
		select {
		case port := <-results:
			if port > 0 {
				open = append(open, port)
			}
		case <-timeoutCh:
			return open
		}
	}
	return open
}

// CommonWebPorts returns common web server ports
func CommonWebPorts() []int {
	return []int{80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000, 9443,
		2082, 2083, 2086, 2087, 2095, 2096, 2078, 2079,
		81, 591, 8008, 8081, 8082, 8083, 9090, 10000}
}

// ipToBytes converts net.IP string to [4]byte
func ipToBytes(ip net.IP) [4]byte {
	var b [4]byte
	copy(b[:], ip.To4())
	return b
}

// randIPAsBytes returns a random IP as [4]byte for packet spoofing
func randIPAsBytes() [4]byte {
	return ipToBytes(net.ParseIP(randomIP()))
}

// IsWindows returns true if running on Windows
func IsWindows() bool {
	return runtime.GOOS == "windows"
}
