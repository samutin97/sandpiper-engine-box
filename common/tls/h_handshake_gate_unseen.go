package tls

import (
	"context"
	"net"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// The naive outbound's TLS handshakes went past the gate: cronet makes them, on the TCP sockets it
// takes from the outbound's dialer, and their ClientHellos fell between the gate's, with no gap.
// GateDialer is the dialer to give such a handshaker. A TCP dial takes the server's turn before
// the connect, as DialForHandshake does, and returns once the gap since the previous ClientHello
// to the address has passed (the handshaker sends its ClientHello at once). The end of a handshake
// it makes is not seen (cronet takes over the socket, often as a duplicate of its descriptor), so
// the turn ends unseen_hold after the connect, instead of when the ticket of an unused dial ends
// (dialTicketHold). The connection is the dialer's own, unwrapped.

// GateDialer paces the TCP dials of dialer in the handshake gate, for a TLS handshake the gate does
// not see. Datagrams (QUIC) go as they are. //H
func GateDialer(dialer N.Dialer) N.Dialer {
	return &unseenGateDialer{dialer: dialer}
}

type unseenGateDialer struct {
	dialer N.Dialer
}

func (d *unseenGateDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	gate := activeGate.Load()
	if gate == nil || N.NetworkName(network) != N.NetworkTCP {
		return d.dialer.DialContext(ctx, network, destination)
	}
	conn, err := DialForHandshake(ctx, d.dialer, destination)
	if err != nil {
		return nil, err
	}
	// the turn taken at the dial, and the gap to the previous ClientHello
	release, err := enterHandshake(ctx, conn, "")
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	time.AfterFunc(gate.unseenHold, release)
	return conn, nil
}

// ListenPacket goes as it is. No Upstream: common.Cast must not reach the inner dialer and dial
// past the gate.
func (d *unseenGateDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return d.dialer.ListenPacket(ctx, destination)
}
