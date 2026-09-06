package easyconnect

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"testing"
	"time"

	tls "github.com/refraction-networking/utls"
)

// Round 3: bind to the WLAN interface IPv4 to bypass the TUN proxy, then
// fire the exact Sangfor legacy hello at the IPv4 entry.
// Run: go test ./client/easyconnect/ -run TestYibinuTunnelHelloIPv4Bind -v -count=1
func TestYibinuTunnelHelloIPv4Bind(t *testing.T) {
	const wlanIPv4 = "192.168.1.29"
	// Note: net.Dialer.LocalAddr on Windows binds the source; packets to
	// 125.64.220.23 should then egress via WLAN if the routing table allows.
	// If the TUN route is a /32 catch-all this may still fail - that result
	// is informative too.
	localAddr := &net.TCPAddr{IP: net.ParseIP(wlanIPv4)}

	cases := []struct {
		name    string
		network string
	}{
		{"tcp4-bound-to-WLAN", "tcp4"},
		{"tcp-bound-to-WLAN", "tcp"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			d := net.Dialer{
				Timeout:   8 * time.Second,
				LocalAddr: localAddr,
			}
			conn, err := d.DialContext(context.Background(), tc.network,
				net.JoinHostPort("125.64.220.23", "443"))
			if err != nil {
				t.Logf("[%s] dial: %v", tc.name, err)
				return
			}
			defer conn.Close()
			t.Logf("[%s] connected, remote=%s local=%s", tc.name, conn.RemoteAddr(), conn.LocalAddr())

			u := tls.UClient(conn, &tls.Config{InsecureSkipVerify: true}, tls.HelloCustom)
			random := make([]byte, 32)
			_ = u.SetClientRandom(random)
			_ = u.SetTLSVers(tls.VersionTLS11, tls.VersionTLS11, []tls.TLSExtension{})
			u.HandshakeState.Hello.Vers = tls.VersionTLS11
			u.HandshakeState.Hello.CipherSuites = []uint16{tls.TLS_RSA_WITH_RC4_128_SHA, tls.FAKE_TLS_EMPTY_RENEGOTIATION_INFO_SCSV}
			u.HandshakeState.Hello.CompressionMethods = []uint8{0}
			u.HandshakeState.Hello.SessionId = []byte{'L', '3', 'I', 'P', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
			u.Extensions = []tls.TLSExtension{&fakeHeartBeatExtension{}}

			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			if err := u.HandshakeContext(ctx); err != nil {
				t.Logf("[%s] handshake: %v", tc.name, err)
				return
			}
			sid := u.HandshakeState.ServerHello.SessionId
			beat := len(sid) >= 4 && string(sid[:4]) == "L3IP"
			fmt.Printf("[%s] TLS OK negotiated=0x%04x L3IP-echo=%v sessionId[:8]=%s\n",
				tc.name, u.ConnectionState().Version, beat, hex.EncodeToString(sid[:min(8, len(sid))]))
		})
	}
}
