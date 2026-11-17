package tun

import (
	"net/netip"
	"testing"

	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/sing-box/adapter"
	tun "github.com/sagernet/sing-tun"
)

type preMatchRouter struct {
	adapter.Router
	calls int
}

func (r *preMatchRouter) PreMatch(metadata adapter.InboundContext, firstPacket []byte) adapter.PreMatchResult {
	r.calls++
	return adapter.PreMatchResult{Action: adapter.PreMatchReject}
}

// A datagram to another port of the TUN's DNS address was taken for a DNS query: it was never
// routed, and the router logged an error for it. Only port 53 is DNS now.
func TestH_DNSAddressOnlyPort53IsDNS(t *testing.T) {
	dnsAddress := netip.MustParseAddr("10.64.0.2")
	router := &preMatchRouter{}
	inbound := &Inbound{router: router, dnsHijackAddress: []netip.Addr{dnsAddress}}
	source := netip.MustParseAddrPort("10.64.0.1:40000")
	udp := uint8(header.UDPProtocolNumber)
	if verdict := inbound.JudgeFlow(udp, source, netip.AddrPortFrom(dnsAddress, 53), nil); verdict.Action != tun.ActionHijackDNS {
		t.Fatalf("port 53: %v", verdict.Action)
	}
	if router.calls != 0 {
		t.Fatal("port 53 went to the router")
	}
	if verdict := inbound.JudgeFlow(udp, source, netip.AddrPortFrom(dnsAddress, 9), nil); verdict.Action != tun.ActionReject {
		t.Fatalf("port 9: %v (routed: %d)", verdict.Action, router.calls)
	}
	if router.calls != 1 {
		t.Fatalf("port 9 routed %d times", router.calls)
	}
	// TCP to the address stays as upstream has it (accepted, then routed as a connection)
	if verdict := inbound.JudgeFlow(uint8(header.TCPProtocolNumber), source, netip.AddrPortFrom(dnsAddress, 853), nil); verdict.Action != tun.ActionAccept {
		t.Fatalf("tcp: %v", verdict.Action)
	}
}
