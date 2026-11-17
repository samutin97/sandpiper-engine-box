package mixed

import (
	"context"
	"net"
	"testing"
)

func TestH_DisableUDPRefusesTheAssociate(t *testing.T) {
	h := &Inbound{disableUDP: true}
	if _, ok := h.packetListener().(noUDPListener); !ok {
		t.Fatal("disable_udp: the SOCKS5 UDP relay still listens")
	}
	if _, err := (noUDPListener{}).ListenPacket(net.ListenConfig{}, context.Background(), "udp", "127.0.0.1:0"); err == nil {
		t.Fatal("no error")
	}
}
