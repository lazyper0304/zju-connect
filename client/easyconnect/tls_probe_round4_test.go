package easyconnect

import (
	"context"
	"encoding/hex"
	"net"
	"testing"
	"time"

	tls "github.com/refraction-networking/utls"
)

// Round 4: IPv4 entry accepts the L3IP dispatch (we got past version check),
// but RC4 gets "handshake failure". Matrix-probe legacy ciphersuits to find
// which one the Sangfor front still accepts.
// Run: go -C <fork> test ./client/easyconnect/ -run TestYibinuTunnelCipherMatrix -v -count=1
func TestYibinuTunnelCipherMatrix(t *testing.T) {
	server := net.JoinHostPort("125.64.220.23", "443")

	ciphers := map[string]uint16{
		"rc4-sha(tls11-only)":      tls.TLS_RSA_WITH_RC4_128_SHA,
		"3des-ede-cbc-sha":         tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		"aes128-cbc-sha":           tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		"aes256-cbc-sha":           tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		"aes128-cbc-sha256(tls12)": tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
		"aes128-gcm(tls12)":        tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	}
	versions := map[string]uint16{
		"tls11": tls.VersionTLS11,
		"tls12": tls.VersionTLS12,
	}

	for vname, ver := range versions {
		for cname, cip := range ciphers {
			// RSA key exchange works with any version; CBC-SHA256 and GCM are TLS12-only
			if vname == "tls11" && (cname == "aes128-cbc-sha256(tls12)" || cname == "aes128-gcm(tls12)") {
				continue
			}
			name := vname + "+" + cname
			t.Run(name, func(t *testing.T) {
				d := net.Dialer{Timeout: 8 * time.Second}
				conn, err := d.DialContext(context.Background(), "tcp4", server)
				if err != nil {
					t.Fatalf("dial: %v", err)
				}
				defer conn.Close()

				u := tls.UClient(conn, &tls.Config{InsecureSkipVerify: true}, tls.HelloCustom)
				random := make([]byte, 32)
				_ = u.SetClientRandom(random)
				_ = u.SetTLSVers(ver, ver, []tls.TLSExtension{})
				u.HandshakeState.Hello.Vers = ver
				u.HandshakeState.Hello.CipherSuites = []uint16{cip, tls.FAKE_TLS_EMPTY_RENEGOTIATION_INFO_SCSV}
				u.HandshakeState.Hello.CompressionMethods = []uint8{0}
				u.HandshakeState.Hello.SessionId = []byte{'L', '3', 'I', 'P', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
				u.Extensions = []tls.TLSExtension{&fakeHeartBeatExtension{}}

				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				if err := u.HandshakeContext(ctx); err != nil {
					t.Logf("[%s] %v", name, err)
					return
				}
				sid := u.HandshakeState.ServerHello.SessionId
				t.Logf("[%s] OK negotiated=0x%04x L3IP-echo=%v sid[:8]=%s",
					name, u.ConnectionState().Version,
					len(sid) >= 4 && string(sid[:4]) == "L3IP",
					hex.EncodeToString(sid[:min(8, len(sid))]))
			})
		}
	}
}
