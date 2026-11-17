package option

import "github.com/sagernet/sing/common/json/badoption"

// HandshakeGateOptions pace the TLS handshakes of the outbounds to one server (an address or a
// subnet, whatever the server name; from the TCP connect for the outbounds' TLS dials): at most
// max_inflight at a time (3 when 0), min_gap between the starts of two and between two ClientHellos
// (450ms when 0). With max_gap above min_gap, each of these gaps is drawn anew, uniformly between
// min_gap and max_gap, so the series has no fixed rhythm. With window and window_max, at most
// window_max handshakes start to one server within any window (a sliding window; off when either
// is 0). ipv4_prefix / ipv6_prefix group the addresses of a subnet as one server (32 and 128, one
// address, when 0). Off unless enabled. See common/tls/h_handshake_gate.go. //H
type HandshakeGateOptions struct {
	Enabled     bool               `json:"enabled,omitempty"`
	MaxInflight int                `json:"max_inflight,omitempty"`
	MinGap      badoption.Duration `json:"min_gap,omitempty"`
	MaxGap      badoption.Duration `json:"max_gap,omitempty"`
	Window      badoption.Duration `json:"window,omitempty"`
	WindowMax   int                `json:"window_max,omitempty"`
	IPv4Prefix  int                `json:"ipv4_prefix,omitempty"`
	IPv6Prefix  int                `json:"ipv6_prefix,omitempty"`
}
