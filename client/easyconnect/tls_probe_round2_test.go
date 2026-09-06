package easyconnect

import (
	"context"
	"encoding/hex"
	"net"
	"testing"
	"time"

	"github.com/refraction-networking/utls"
)

// Round 2: does the IPv6 front dispatch the Sangfor tunnel by SessionId
// magic regardless of TLS version? If ServerHello echoes "L3IP", yes.
func TestYibinuTunnelHelloRound2(t *testing.T) {
	server := net.JoinHostPort("2001:250:2010:2:1::5", "443")

	type variant struct {
		name    string
		mkHello func(c *tls.UConn)
	}
	variants := []variant{
		// Modern TLS1.2 default cipher list, only SessionId + heartbeat patched in
		{"tls12-modern-ciphers+L3IP+beat", func(c *tls.UConn) {
			random := make([]byte, 32)
			_ = c.SetClientRandom(random)
			c.HandshakeState.Hello.SessionId = []byte{'L', '3', 'I', 'P', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
			c.Extensions = append(c.Extensions, &fakeHeartBeatExtension{})
		}},
		// TLS1.2 ECDHE-only ciphers + L3IP + heartbeat
		{"tls12-ecdhe+L3IP+beat", func(c *tls.UConn) {
			random := make([]byte, 32)
			_ = c.SetClientRandom(random)
			_ = c.SetTLSVers(tls.VersionTLS12, tls.VersionTLS12, []tls.TLSExtension{})
			c.HandshakeState.Hello.Vers = tls.VersionTLS12
			c.HandshakeState.Hello.CipherSuites = []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			}
			c.HandshakeState.Hello.CompressionMethods = []uint8{0}
			c.HandshakeState.Hello.SessionId = []byte{'L', '3', 'I', 'P', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
			c.Extensions = []tls.TLSExtension{&fakeHeartBeatExtension{}}
		}},
		// Control: modern TLS1.2 with NORMAL sessionId — does plain HTTPS work?
		{"tls12-modern-normal-sessionid", func(c *tls.UConn) {
			random := make([]byte, 32)
			_ = c.SetClientRandom(random)
		}},
	}

	for _, v := range variants {
		v := v
		t.Run(v.name, func(t *testing.T) {
			d := net.Dialer{Timeout: 8 * time.Second}
			conn, err := d.DialContext(context.Background(), "tcp", server)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer conn.Close()

			u := tls.UClient(conn, &tls.Config{InsecureSkipVerify: true}, tls.HelloGolang)
			v.mkHello(u)

			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			if err := u.HandshakeContext(ctx); err != nil {
				t.Logf("[%s] handshake: %v", v.name, err)
				return
			}
			sid := u.HandshakeState.ServerHello.SessionId
			beat := len(sid) >= 4 && string(sid[:4]) == "L3IP"
			t.Logf("[%s] OK negotiated=0x%04x sessionId[:8]=%s L3IP-echo=%v cipher=0x%04x",
				v.name, u.ConnectionState().Version,
				hex.EncodeToString(sid[:min(8, len(sid))]), beat,
				u.ConnectionState().CipherSuite)
		})
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
