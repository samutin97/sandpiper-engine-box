package settings

import (
	"errors"
	"net"
	"strings"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/wininet"

	"golang.org/x/sys/windows/registry"
)

// The system proxy was turned off whatever had been there before it was turned on: a proxy client
// the user runs (another program's 127.0.0.1 proxy, with its own exceptions) lost its system proxy
// when ours was turned off, and the server kept pointing at our closed port. Enable now remembers
// the settings it replaces, unless they are off or ours, and Disable puts them back if their proxy
// still answers a TCP connect (experimental.system_proxy.restore_check_timeout); otherwise it turns
// the system proxy off as before.

// windowsProxySettings are the user's WinINet proxy settings (of the LAN, as the Windows settings
// show them).
type windowsProxySettings struct {
	Enabled bool
	Server  string // ProxyServer: "host:port", "scheme://host:port" or "http=host:port;https=…"
	Bypass  string // ProxyOverride
}

// windowsProxyStore reads and writes them; the tests replace it, so no test touches the settings
// of the machine it runs on.
type windowsProxyStore interface {
	Read() (windowsProxySettings, error)
	Set(server string, bypass string) error
	Clear() error
	Answers(address string, timeout time.Duration) bool
}

var windowsProxy windowsProxyStore = wininetProxyStore{}

type wininetProxyStore struct{}

const internetSettingsKey = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

func (wininetProxyStore) Read() (windowsProxySettings, error) {
	key, err := registry.OpenKey(registry.CURRENT_USER, internetSettingsKey, registry.QUERY_VALUE)
	if err != nil {
		return windowsProxySettings{}, err
	}
	defer key.Close()
	var settings windowsProxySettings
	enabled, _, err := key.GetIntegerValue("ProxyEnable")
	if err != nil && !errors.Is(err, registry.ErrNotExist) {
		return windowsProxySettings{}, err
	}
	settings.Enabled = enabled != 0
	settings.Server, _, err = key.GetStringValue("ProxyServer")
	if err != nil && !errors.Is(err, registry.ErrNotExist) {
		return windowsProxySettings{}, err
	}
	settings.Bypass, _, err = key.GetStringValue("ProxyOverride")
	if err != nil && !errors.Is(err, registry.ErrNotExist) {
		return windowsProxySettings{}, err
	}
	return settings, nil
}

func (wininetProxyStore) Set(server string, bypass string) error {
	return wininet.SetSystemProxy(server, bypass)
}

func (wininetProxyStore) Clear() error {
	return wininet.ClearSystemProxy()
}

func (wininetProxyStore) Answers(address string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// rememberPrevious returns the settings Enable is about to replace, or nil when there is nothing to
// put back: the system proxy is off, unreadable, or already ours (one we left on before).
func rememberPrevious(ours M.Socksaddr) *windowsProxySettings {
	previous, err := windowsProxy.Read()
	if err != nil || !previous.Enabled || strings.TrimSpace(previous.Server) == "" || pointsAt(previous.Server, ours) {
		return nil
	}
	return &previous
}

// pointsAt reports whether a ProxyServer value names address.
func pointsAt(server string, address M.Socksaddr) bool {
	for _, entry := range proxyServerAddresses(server) {
		if strings.EqualFold(entry, address.String()) {
			return true
		}
	}
	return false
}

// restorePrevious turns our system proxy off: back to the previous settings if their proxy
// answers, else off.
//
// A Disable without an Enable of the same proxy is the cleanup after a core that was killed with
// its system proxy on (hiddify-core, from its marker). The system proxy may have been taken by
// another program since (the user started their other proxy client again): it is turned off only
// while it is on and still points at this address; otherwise, or when it cannot be read, nothing
// changes.
func (p *WindowsSystemProxy) restorePrevious() error {
	if !p.isEnabled {
		current, err := windowsProxy.Read()
		if err != nil || !current.Enabled || !pointsAt(current.Server, p.serverAddr) {
			return nil
		}
		return windowsProxy.Clear()
	}
	previous := p.previous
	p.previous = nil
	if previous != nil {
		if addresses := proxyServerAddresses(previous.Server); len(addresses) > 0 && windowsProxy.Answers(addresses[0], restoreCheckTimeout()) {
			return windowsProxy.Set(previous.Server, previous.Bypass)
		}
	}
	return windowsProxy.Clear()
}

// defaultProxyPort is the port WinINet takes for a proxy server given without one.
const defaultProxyPort = "80"

// proxyServerAddresses are the host:port of a ProxyServer value, the one for HTTP first.
func proxyServerAddresses(server string) []string {
	var first, rest []string
	for _, entry := range strings.Split(server, ";") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		scheme, value, keyed := strings.Cut(entry, "=")
		if !keyed {
			value, scheme = entry, ""
		}
		if before, after, found := strings.Cut(value, "://"); found {
			if scheme == "" {
				scheme = before
			}
			value = after
		}
		value = strings.TrimSuffix(value, "/")
		host, port, err := net.SplitHostPort(value)
		if err != nil {
			host, port = strings.Trim(value, "[]"), defaultProxyPort
		}
		if host == "" {
			continue
		}
		address := net.JoinHostPort(host, port)
		if scheme == "" || strings.EqualFold(scheme, "http") {
			first = append(first, address)
		} else {
			rest = append(rest, address)
		}
	}
	return append(first, rest...)
}
