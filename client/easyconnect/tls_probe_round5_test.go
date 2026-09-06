package easyconnect

import (
	"context"
	"net"
	"testing"
	"time"

	tls "github.com/refraction-networking/utls"
)

// Round 5: full tlsConn replica + immediate Sangfor send-stream probe with a
// FAKE token. Success criterion: TLS handshake completes AND we get a real
// HandCmdMsg reply byte (any 0x0x code proves the Sangfor tunnel processor
// accepted the connection; a fake token yields an error code, not TLS death).
func TestYibinuTunnelSendStreamFake(t *testing.T) {
	server := net.JoinHostPort("125.64.220.23", "443")

	d := net.Dialer{Timeout: 8 * time.Second}
	conn, err := d.DialContext(context.Background(), "tcp4", server)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	u := tls.UClient(conn, &tls.Config{InsecureSkipVerify: true}, tls.HelloCustom)
	random := make([]byte, 32)
	_ = u.SetClientRandom(random)
	_ = u.SetTLSVers(tls.VersionTLS11, tls.VersionTLS11, []tls.TLSExtension{})
	u.HandshakeState.Hello.Vers = tls.VersionTLS11
	// Patched cipher list (AES-CBC first, RC4 fallback)
	u.HandshakeState.Hello.CipherSuites = []uint16{
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_RC4_128_SHA,
		tls.FAKE_TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
	}
	u.HandshakeState.Hello.CompressionMethods = []uint8{0}
	u.HandshakeState.Hello.SessionId = []byte{'L', '3', 'I', 'P', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	u.Extensions = []tls.TLSExtension{&fakeHeartBeatExtension{}}

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	if err := u.HandshakeContext(ctx); err != nil {
		t.Fatalf("tls handshake: %v", err)
	}
	t.Logf("TLS handshake OK negotiated=0x%04x cipher=0x%04x", u.ConnectionState().Version, u.ConnectionState().CipherSuite)

	// Send-stream probe with fake token (48 zero bytes) - mirrors SendConn layout
	message := []byte{0x05, 0x00, 0x00, 0x00}
	message = append(message, make([]byte, 48)...)
	message = append(message, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}...)
	message = append(message, make([]byte, 4)...)

	_ = u.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err := u.Write(message); err != nil {
		t.Fatalf("write send-stream: %v", err)
	}
	t.Logf("send-stream written (%d bytes), waiting reply...", len(message))

	reply := make([]byte, 64)
	n, err := u.Read(reply)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	t.Logf("reply %d bytes: first=0x%02x hex[:16]=% x", n, reply[0], reply[:min(16, n)])
}
