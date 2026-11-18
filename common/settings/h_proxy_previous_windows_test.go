package settings

import (
	"context"
	"errors"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
)

// fakeProxyStore stands for the user's proxy settings: no test reads or writes those of the
// machine it runs on.
type fakeProxyStore struct {
	settings  windowsProxySettings
	readErr   error
	answering map[string]bool
	asked     []string
	timeouts  []time.Duration
	calls     []string
}

func (s *fakeProxyStore) Read() (windowsProxySettings, error) {
	return s.settings, s.readErr
}

func (s *fakeProxyStore) Set(server string, bypass string) error {
	s.calls = append(s.calls, "set "+server)
	s.settings.Enabled = true
	s.settings.Server = server
	if bypass != "" {
		s.settings.Bypass = bypass
	}
	return nil
}

func (s *fakeProxyStore) Clear() error {
	s.calls = append(s.calls, "clear")
	s.settings.Enabled = false
	return nil
}

func (s *fakeProxyStore) Answers(address string, timeout time.Duration) bool {
	s.asked = append(s.asked, address)
	s.timeouts = append(s.timeouts, timeout)
	return s.answering[address]
}

func useFakeProxyStore(t *testing.T, store *fakeProxyStore) {
	t.Helper()
	real := windowsProxy
	windowsProxy = store
	t.Cleanup(func() { windowsProxy = real })
}

func enableAndDisable(t *testing.T) {
	t.Helper()
	proxy, err := NewSystemProxy(context.Background(), M.ParseSocksaddr("127.0.0.1:2081"), true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := proxy.Enable(); err != nil {
		t.Fatal(err)
	}
	if err := proxy.Disable(); err != nil {
		t.Fatal(err)
	}
}

// Another program's system proxy was on before ours: turning ours off turned it off too, and left
// the server at our closed port. Now it is put back, server and exceptions, while it answers.
func TestH_SystemProxyPutsBackAnotherProgramsProxy(t *testing.T) {
	previous := windowsProxySettings{Enabled: true, Server: "127.0.0.1:2080", Bypass: "localhost;127.*;<local>"}
	store := &fakeProxyStore{settings: previous, answering: map[string]bool{"127.0.0.1:2080": true}}
	useFakeProxyStore(t, store)
	enableAndDisable(t)
	if store.settings != previous {
		t.Fatalf("after ours: %+v, want %+v", store.settings, previous)
	}
	if want := []string{"set http://127.0.0.1:2081", "set 127.0.0.1:2080"}; !reflect.DeepEqual(store.calls, want) {
		t.Fatalf("calls %v, want %v", store.calls, want)
	}
}

// A previous proxy that no longer answers is not put back: off, as before.
func TestH_SystemProxyTurnsOffWhenThePreviousIsGone(t *testing.T) {
	store := &fakeProxyStore{settings: windowsProxySettings{Enabled: true, Server: "http=127.0.0.1:8080;https=127.0.0.1:8443"}}
	useFakeProxyStore(t, store)
	enableAndDisable(t)
	if store.settings.Enabled {
		t.Fatalf("the system proxy is on: %+v", store.settings)
	}
	if !reflect.DeepEqual(store.asked, []string{"127.0.0.1:8080"}) {
		t.Fatalf("asked %v, want the HTTP one", store.asked)
	}
}

// Off before, unreadable, or ours already (left on by an earlier run): off, as before, and nothing
// is asked.
func TestH_SystemProxyOffAsBefore(t *testing.T) {
	for name, store := range map[string]*fakeProxyStore{
		"off before":       {settings: windowsProxySettings{Server: "127.0.0.1:2080"}, answering: map[string]bool{"127.0.0.1:2080": true}},
		"unreadable":       {readErr: errors.New("denied")},
		"ours left on":     {settings: windowsProxySettings{Enabled: true, Server: "http://127.0.0.1:2081"}, answering: map[string]bool{"127.0.0.1:2081": true}},
		"enabled no value": {settings: windowsProxySettings{Enabled: true}},
	} {
		useFakeProxyStore(t, store)
		enableAndDisable(t)
		if store.settings.Enabled || len(store.asked) != 0 || store.calls[len(store.calls)-1] != "clear" {
			t.Fatalf("%s: %+v, asked %v, calls %v", name, store.settings, store.asked, store.calls)
		}
	}
}

// Another program took the system proxy while ours was on (the user started their other proxy
// client): turning ours off turned theirs off, or put back the settings from before ours. Now
// their settings stay; settings that cannot be read do not stop the restore.
func TestH_SystemProxyLeavesAProxyTakenMeanwhile(t *testing.T) {
	previous := windowsProxySettings{Enabled: true, Server: "127.0.0.1:2080", Bypass: "localhost;<local>"}
	for name, taken := range map[string]windowsProxySettings{
		"another program":  {Enabled: true, Server: "127.0.0.1:2090", Bypass: "<local>"},
		"the previous one": previous,
		"per protocol":     {Enabled: true, Server: "http=127.0.0.1:2090;https=127.0.0.1:2090"},
	} {
		store := &fakeProxyStore{settings: previous, answering: map[string]bool{"127.0.0.1:2080": true, "127.0.0.1:2090": true}}
		useFakeProxyStore(t, store)
		proxy, _ := NewSystemProxy(context.Background(), M.ParseSocksaddr("127.0.0.1:2081"), true, nil)
		if err := proxy.Enable(); err != nil {
			t.Fatal(err)
		}
		store.settings = taken
		if err := proxy.Disable(); err != nil {
			t.Fatal(err)
		}
		if store.settings != taken || len(store.calls) != 1 || len(store.asked) != 0 {
			t.Fatalf("%s: %+v, calls %v, asked %v", name, store.settings, store.calls, store.asked)
		}
	}
	// unreadable at the end: as before, the previous settings come back
	store := &fakeProxyStore{settings: previous, answering: map[string]bool{"127.0.0.1:2080": true}}
	useFakeProxyStore(t, store)
	proxy, _ := NewSystemProxy(context.Background(), M.ParseSocksaddr("127.0.0.1:2081"), true, nil)
	if err := proxy.Enable(); err != nil {
		t.Fatal(err)
	}
	store.readErr = errors.New("denied")
	if err := proxy.Disable(); err != nil || store.settings != previous {
		t.Fatalf("unreadable: %v, %+v", err, store.settings)
	}
}

// The cleanup after a core that was killed with its system proxy on (a Disable without an Enable)
// turned the system proxy off whatever it was: another program that took it since (the user
// started their other proxy client again) lost it at our start. Now only a system proxy that is
// on and still ours is turned off.
func TestH_SystemProxyCleanupTurnsOffOnlyOurs(t *testing.T) {
	cleanup := func(store *fakeProxyStore) {
		t.Helper()
		useFakeProxyStore(t, store)
		proxy, err := NewSystemProxy(context.Background(), M.ParseSocksaddr("127.0.0.1:2081"), true, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := proxy.Disable(); err != nil {
			t.Fatal(err)
		}
	}
	ours := &fakeProxyStore{settings: windowsProxySettings{Enabled: true, Server: "http://127.0.0.1:2081", Bypass: "<local>"}}
	cleanup(ours)
	if ours.settings.Enabled || !reflect.DeepEqual(ours.calls, []string{"clear"}) {
		t.Fatalf("ours left on: %+v, calls %v", ours.settings, ours.calls)
	}
	for name, store := range map[string]*fakeProxyStore{
		"another program's": {settings: windowsProxySettings{Enabled: true, Server: "127.0.0.1:2080", Bypass: "localhost;<local>"}},
		"per protocol":      {settings: windowsProxySettings{Enabled: true, Server: "http=127.0.0.1:2080;https=127.0.0.1:2080"}},
		"off, ours":         {settings: windowsProxySettings{Server: "http://127.0.0.1:2081"}},
		"unreadable":        {readErr: errors.New("denied")},
	} {
		before := store.settings
		cleanup(store)
		if store.settings != before || len(store.calls) != 0 || len(store.asked) != 0 {
			t.Fatalf("%s: %+v, calls %v, asked %v", name, store.settings, store.calls, store.asked)
		}
	}
}

func TestH_SystemProxyRestoreCheckTimeout(t *testing.T) {
	store := &fakeProxyStore{settings: windowsProxySettings{Enabled: true, Server: "127.0.0.1:2080"}}
	useFakeProxyStore(t, store)
	defer SetSystemProxyOptions(nil)
	SetSystemProxyOptions(&option.SystemProxyOptions{RestoreCheckTimeout: badoption.Duration(250 * time.Millisecond)})
	enableAndDisable(t)
	SetSystemProxyOptions(nil)
	store.settings = windowsProxySettings{Enabled: true, Server: "127.0.0.1:2080"}
	enableAndDisable(t)
	if want := []time.Duration{250 * time.Millisecond, DefaultSystemProxyRestoreCheckTimeout}; !reflect.DeepEqual(store.timeouts, want) {
		t.Fatalf("timeouts %v, want %v", store.timeouts, want)
	}
}

func TestH_ProxyServerAddresses(t *testing.T) {
	for server, want := range map[string][]string{
		"127.0.0.1:2080":                           {"127.0.0.1:2080"},
		"http://127.0.0.1:2080/":                   {"127.0.0.1:2080"},
		"proxy.example.com":                        {"proxy.example.com:80"},
		"socks=127.0.0.1:1080;http=127.0.0.1:8080": {"127.0.0.1:8080", "127.0.0.1:1080"},
		"[::1]:8080":                               {"[::1]:8080"},
		" ; ":                                      nil,
	} {
		if got := proxyServerAddresses(server); !reflect.DeepEqual(got, want) {
			t.Fatalf("%q: %v, want %v", server, got, want)
		}
	}
}

// The check of the previous proxy is a TCP connect (to a listener of the test, on the loopback).
func TestH_SystemProxyAnswers(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if !(wininetProxyStore{}).Answers(address, time.Second) {
		t.Fatal("a listening proxy does not answer")
	}
	_ = listener.Close()
	if (wininetProxyStore{}).Answers(address, time.Second) {
		t.Fatal("a closed port answers")
	}
}
