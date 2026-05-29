package attack

import (
	"crypto/tls"
	"fmt"
	"math/rand"
	"net"
	"sync/atomic"
	"time"

	utls "github.com/refraction-networking/utls"
)

type TLSProfile struct {
	Name      string
	JA3       string
	JA4       string
	ClientID  utls.ClientHelloID
}

type FingerprintDialer struct {
	profile     string
	serverName  string
}

var tlsDialCount int64
var TLSProfiles = map[string]utls.ClientHelloID{
	"chrome136": utls.HelloChrome_133,
	"chrome120": utls.HelloChrome_120,
	"firefox140": utls.HelloFirefox_120,
	"safari18": utls.HelloSafari_16_0,
	"edge136": utls.HelloEdge_106,
}

var JA3Strings = map[string]string{
	"chrome136": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-65037-27-51-13-43-5-18-17513-65281-23-10-45-35-11-16,29-23-24-25-256-257,0",
	"chrome120": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24-25-257,0",
	"firefox140": "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-65037,29-23-24,0",
	"safari18": "771,4865-4866-4867-49196-49195-52393-49200-49199-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27-17513-21,29-23-24-25,0",
}

var JA4Strings = map[string]string{
	"chrome136": "t13d1516h2_8daaf6152771_9f8d1e4799f1",
	"chrome120": "t13d1516h2_8daaf6152771_9f8d1e4799f1",
	"firefox140": "t13d1516h2_8e260b28723c_b0b74e65e4c6",
	"safari18": "t13d1516h2_e2d1f5e7c0b0_2b3c4d5e6f7a",
}

func GetTLSConfig(browser string) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
		},
		CurvePreferences: []tls.CurveID{
			tls.X25519, tls.CurveP256, tls.CurveP384,
		},
		NextProtos: []string{"h2", "http/1.1"},
	}
}

func GetJA3String(browser string) string {
	if s, ok := JA3Strings[browser]; ok {
		return s
	}
	return JA3Strings["chrome136"]
}

func GetJA4String(browser string) string {
	if s, ok := JA4Strings[browser]; ok {
		return s
	}
	return JA4Strings["chrome136"]
}

func GetRandomBrowser() string {
	browsers := make([]string, 0, len(TLSProfiles))
	for name := range TLSProfiles {
		browsers = append(browsers, name)
	}
	return browsers[rand.Intn(len(browsers))]
}

func DialWithFingerprint(addr, serverName, browser string) (net.Conn, error) {
	helloID, ok := TLSProfiles[browser]
	if !ok {
		helloID = TLSProfiles["chrome136"]
	}

	dial := createDialer("", 10*time.Second)
	tcpConn, err := dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tcp dial: %w", err)
	}

	config := &utls.Config{
		InsecureSkipVerify: true,
		ServerName:         serverName,
	}

	tlsConn := utls.UClient(tcpConn, config, helloID)
	if err := tlsConn.Handshake(); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("tls handshake: %w", err)
	}

	atomic.AddInt64(&tlsDialCount, 1)
	return tlsConn, nil
}

func DialWithRandomFingerprint(addr, serverName string) (net.Conn, string, error) {
	browser := GetRandomBrowser()
	conn, err := DialWithFingerprint(addr, serverName, browser)
	if err != nil {
		return nil, browser, err
	}
	return conn, browser, nil
}

func DialWithRotatingFingerprint(addr, serverName string) (net.Conn, string, error) {
	idx := atomic.AddInt64(&tlsDialCount, 1)
	browsers := []string{"chrome136", "chrome120", "firefox140", "safari18", "edge136"}
	browser := browsers[idx%int64(len(browsers))]
	conn, err := DialWithFingerprint(addr, serverName, browser)
	if err != nil {
		return nil, browser, err
	}
	return conn, browser, nil
}

func FingerprintStats() string {
	return fmt.Sprintf("ja3_rotations=%d", atomic.LoadInt64(&tlsDialCount))
}

func GetJA3ForConn(c net.Conn) string {
	if utlsConn, ok := c.(*utls.UConn); ok {
		state := utlsConn.ConnectionState()
		if state.HandshakeComplete {
			return computeJA3(state)
		}
	}
	return ""
}

func computeJA3(state utls.ConnectionState) string {
	return fmt.Sprintf("771,%d,0",
		state.CipherSuite)
}

