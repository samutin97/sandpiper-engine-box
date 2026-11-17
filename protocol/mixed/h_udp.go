package mixed

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/protocol/socks"
)

// errUDPDisabled refuses a SOCKS5 UDP ASSOCIATE on an inbound with disable_udp. //H
var errUDPDisabled = E.New("socks5: UDP associate is disabled on this inbound")

// noUDPListener is the packet listener of an inbound with disable_udp: the UDP relay a SOCKS5
// UDP ASSOCIATE opens is not covered by the SOCKS5 password (any process on the client's address
// can send to it), so on a loopback proxy any app on the device could use it. //H
type noUDPListener struct{}

func (noUDPListener) ListenPacket(net.ListenConfig, context.Context, string, string) (net.PacketConn, error) {
	return nil, errUDPDisabled
}

// packetListener is what SOCKS5 UDP ASSOCIATE listens with: none with disable_udp. //H
func (h *Inbound) packetListener() socks.PacketListener {
	if h.disableUDP {
		return noUDPListener{}
	}
	return h.listener
}

var _ adapter.Inbound = (*Inbound)(nil)
