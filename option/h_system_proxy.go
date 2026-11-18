package option

import "github.com/sagernet/sing/common/json/badoption"

// SystemProxyOptions tune the system proxy an inbound sets (set_system_proxy). On Windows, turning
// it on over the proxy settings of another program (a proxy client the user runs) remembers them,
// and turning it off puts them back if that proxy still answers a TCP connect within
// restore_check_timeout (1s when 0); otherwise the system proxy is turned off. See
// common/settings/h_proxy_previous_windows.go. //H
type SystemProxyOptions struct {
	RestoreCheckTimeout badoption.Duration `json:"restore_check_timeout,omitempty"`
}
