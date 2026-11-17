package v2raygrpc

import "context"

// dialScope is the context of the client's dials until the next Close.
//
// Close ends a dial under way, but must not end the client. VLESS, VMess and Trojan call their
// transport's Close on a network reset (InterfaceUpdated: a network change, ReleaseMemory, the
// Clash API closing all connections) and go on dialing through the same client, since upstream's
// Close only closed the connection. Close cancelled the client's own context instead, so every dial
// after the first reset failed with "context canceled" until the profile restarted. Close now ends
// the dials of its scope, and the next dial opens a new one. //H
type dialScope struct {
	ctx    context.Context
	cancel context.CancelFunc
}

func (c *Client) dialScope() *dialScope {
	for {
		if scope := c.dials.Load(); scope != nil {
			return scope
		}
		ctx, cancel := context.WithCancel(c.ctx)
		scope := &dialScope{ctx: ctx, cancel: cancel}
		if c.dials.CompareAndSwap(nil, scope) {
			return scope
		}
		cancel()
	}
}

func (c *Client) endDialScope() {
	if scope := c.dials.Swap(nil); scope != nil {
		scope.cancel()
	}
}
