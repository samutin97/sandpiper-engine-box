package dialer

import (
	"context"
	"net"
	"os"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/hiddify/finalmask"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

type hPlainDialer struct{}

func (hPlainDialer) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, os.ErrInvalid
}

func (hPlainDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

type hUpstreamDialer struct {
	hPlainDialer
	upstream any
}

func (d hUpstreamDialer) Upstream() any { return d.upstream }

// The handshake gate keys a dial by the address its connection reached, unless the connection
// went through a detour: its remote address is then the detour's server.
func TestH_ThroughDetour(t *testing.T) {
	manager := &hFakeOutboundManager{byTag: map[string]adapter.Outbound{"proxy": &hFakeOutbound{tag: "proxy"}}}
	detour := NewDetour(manager, "proxy", true)
	masks := &finalmask.Masks{}
	for name, dialer := range map[string]N.Dialer{
		"detour":                    detour,
		"default outbound":          NewDefaultOutboundDetour(manager),
		"default outbound dialer":   &DefaultOutboundDialer{outbound: manager},
		"masked detour":             newFinalMaskDialer(detour, masks),
		"resolved masked detour":    &resolveDialer{dialer: newFinalMaskDialer(detour, masks)},
		"parallel resolved detour":  &resolveParallelNetworkDialer{resolveDialer: resolveDialer{dialer: detour}},
		"masked parallel detour":    &finalMaskParallelDialer{finalMaskDialer: finalMaskDialer{dialer: detour, masks: masks}},
		"other wrapper of a detour": hUpstreamDialer{upstream: detour},
	} {
		require.True(t, ThroughDetour(dialer), name)
	}
	for name, dialer := range map[string]N.Dialer{
		"nil":                     nil,
		"plain":                   hPlainDialer{},
		"masked":                  newFinalMaskDialer(hPlainDialer{}, masks),
		"resolved masked":         &resolveDialer{dialer: newFinalMaskDialer(hPlainDialer{}, masks)},
		"wrapper of a non-dialer": hUpstreamDialer{upstream: "x"},
		"wrapper of a plain one":  hUpstreamDialer{upstream: hPlainDialer{}},
	} {
		require.False(t, ThroughDetour(dialer), name)
	}
}
