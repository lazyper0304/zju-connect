package easyconnect

import (
	"context"
	"encoding/hex"
	"net"
	"testing"
	"time"

	"github.com/refraction-networking/utls"
)

// Replicates tlsConn's exact hello shape but with tunable TLS version,
// probing directly against the IPv6 entry. Run manually:
//
//	go test ./client/easyconnect/ -run TestYibinuTunnelHelloVariants -v -count=1
func TestYibinuTunnelHelloVariants(t *testing.T) {
	server := net.JoinHostPort("2001:250:2010:2:1::5", "443")

	type variant struct {
		name    string
		mkHello func(c *tls.UConn)
	}
	variants := []variant{
		{"tls11-rc4-L3IP-heartbeat(EXACT)", func(c *tls.UConn) {
			random := make([]byte, 32)
			_ = c.SetClientRandom(random)
			_ = c.SetTLSVers(tls.VersionTLS11, tls.VersionTLS11, []tls.TLSExtension{})
			c.HandshakeState.Hello.Vers = tls.VersionTLS11
			c.HandshakeState.Hello.CipherSuites = []uint16{tls.TLS_RSA_WITH_RC4_128_SHA, tls.FAKE_TLS_EMPTY_RENEGOTIATION_INFO_SCSV}
			c.HandshakeState.Hello.CompressionMethods = []uint8{0}
			c.HandshakeState.Hello.SessionId = []byte{'L', '3', 'I', 'P', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
			c.Extensions = []tls.TLSExtension{&fakeHeartBeatExtension{}}
		}},
		{"tls12-rc4-L3IP-heartbeat", func(c *tls.UConn) {
			random := make([]byte, 32)
			_ = c.SetClientRandom(random)
			_ = c.SetTLSVers(tls.VersionTLS12, tls.VersionTLS12, []tls.TLSExtension{})
			c.HandshakeState.Hello.Vers = tls.VersionTLS12
			c.HandshakeState.Hello.CipherSuites = []uint16{tls.TLS_RSA_WITH_RC4_128_SHA, tls.FAKE_TLS_EMPTY_RENEGOTIATION_INFO_SCSV}
			c.HandshakeState.Hello.CompressionMethods = []uint8{0}
			c.HandshakeState.Hello.SessionId = []byte{'L', '3', 'I', 'P', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
			c.Extensions = []tls.TLSExtension{&fakeHeartBeatExtension{}}
		}},
		{"tls11-rc4-L3IP-nobeat", func(c *tls.UConn) {
			random := make([]byte, 32)
			_ = c.SetClientRandom(random)
			_ = c.SetTLSVers(tls.VersionTLS11, tls.VersionTLS11, []tls.TLSExtension{})
			c.HandshakeState.Hello.Vers = tls.VersionTLS11
			c.HandshakeState.Hello.CipherSuites = []uint16{tls.TLS_RSA_WITH_RC4_128_SHA, tls.FAKE_TLS_EMPTY_RENEGOTIATION_INFO_SCSV}
			c.HandshakeState.Hello.CompressionMethods = []uint8{0}
			c.HandshakeState.Hello.SessionId = []byte{'L', '3', 'I', 'P', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
			c.Extensions = []tls.TLSExtension{}
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

			u := tls.UClient(conn, &tls.Config{InsecureSkipVerify: true}, tls.HelloCustom)
			v.mkHello(u)

			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			if err := u.HandshakeContext(ctx); err != nil {
				t.Logf("[%s] handshake: %v", v.name, err)
			} else {
				t.Logf("[%s] OK sessionId[:8]=%s", v.name, hex.EncodeToString(u.HandshakeState.ServerHello.SessionId[:8]))
			}
		})
	}
}
