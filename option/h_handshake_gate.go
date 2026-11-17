package option

import "github.com/sagernet/sing/common/json/badoption"

// HandshakeGateOptions pace the TLS handshakes of the outbounds to one server (address or subnet,
// and server name): at most max_inflight at a time (3 when 0), min_gap between the starts of two
// (450ms when 0). ipv4_prefix / ipv6_prefix group the addresses of a subnet as one server (32 and
// 128, one address, when 0). Off unless enabled. See common/tls/h_handshake_gate.go. //H
type HandshakeGateOptions struct {
	Enabled     bool               `json:"enabled,omitempty"`
	MaxInflight int                `json:"max_inflight,omitempty"`
	MinGap      badoption.Duration `json:"min_gap,omitempty"`
	IPv4Prefix  int                `json:"ipv4_prefix,omitempty"`
	IPv6Prefix  int                `json:"ipv6_prefix,omitempty"`
}
