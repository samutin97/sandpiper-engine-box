package route

import (
	"context"
	"sync/atomic"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

// malformedDNSPacketReport is how often a DNS query that does not parse is logged as a warning;
// the others go to the debug level. Any app can send garbage to the DNS address of the TUN: that
// is not an error of the router, and one line per datagram filled the log and the problem reports.
const malformedDNSPacketReport = time.Minute

var lastMalformedDNSPacket atomic.Int64

func (r *Router) logMalformedDNSPacket(ctx context.Context, err error) {
	err = E.Cause(err, "process DNS packet: unpack request")
	now := time.Now().UnixNano()
	last := lastMalformedDNSPacket.Load()
	if now-last >= int64(malformedDNSPacketReport) && lastMalformedDNSPacket.CompareAndSwap(last, now) {
		r.logger.WarnContext(ctx, err, " (more within a minute go to the debug level)")
		return
	}
	r.logger.DebugContext(ctx, err)
}
