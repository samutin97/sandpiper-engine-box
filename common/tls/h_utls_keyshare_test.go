package tls

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

// clientHelloSize is the size of the first TLS record a client with these options sends.
func clientHelloSize(t *testing.T, keyShare string) int {
	t.Helper()
	config, err := NewClient(context.Background(), log.NewNOPFactory().NewLogger("t"), "example.com", option.OutboundTLSOptions{
		Enabled: true, ServerName: "example.com",
		UTLS: &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "firefox", KeyShare: keyShare},
	})
	if err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	defer server.Close()
	errs := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, err := ClientHandshake(ctx, client, config)
		errs <- err
		client.Close()
	}()
	header := make([]byte, 5)
	if _, err := io.ReadFull(server, header); err != nil {
		t.Fatal(err, <-errs)
	}
	return int(header[3])<<8 | int(header[4])
}

func TestH_UTLSClassicalKeyShare(t *testing.T) {
	hybrid, classical := clientHelloSize(t, ""), clientHelloSize(t, "classical")
	if classical >= hybrid || hybrid-classical < 1000 {
		t.Fatalf("hybrid %d bytes, classical %d: the 1184-byte ML-KEM share should be gone", hybrid, classical)
	}
	if _, err := NewClient(context.Background(), log.NewNOPFactory().NewLogger("t"), "example.com", option.OutboundTLSOptions{
		Enabled: true, ServerName: "example.com", UTLS: &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "firefox", KeyShare: "bogus"},
	}); err == nil {
		t.Fatal("bogus key_share accepted")
	}
}
