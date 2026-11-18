package dialer

import (
	"github.com/sagernet/sing/common"
	N "github.com/sagernet/sing/common/network"
)

// ThroughDetour reports whether the connections of d go through another outbound (a detour, or
// the default outbound) rather than straight to their destination: such a connection reaches the
// detour's server, and its remote address is that server's. It sees through the dialers this
// package wraps around a detour (the final mask and the resolver), and through any other wrapper
// that gives its upstream dialer.
func ThroughDetour(d N.Dialer) bool {
	for range 16 {
		switch current := d.(type) {
		case nil:
			return false
		case *DetourDialer, *DefaultOutboundDialer:
			return true
		case *finalMaskDialer:
			d = current.dialer
		case *finalMaskParallelDialer:
			d = current.finalMaskDialer.dialer
		case *resolveDialer:
			d = current.dialer
		case *resolveParallelNetworkDialer:
			d = current.resolveDialer.dialer
		default:
			wrapper, isWrapper := d.(common.WithUpstream)
			if !isWrapper {
				return false
			}
			upstream, isDialer := wrapper.Upstream().(N.Dialer)
			if !isDialer {
				return false
			}
			d = upstream
		}
	}
	return false
}
