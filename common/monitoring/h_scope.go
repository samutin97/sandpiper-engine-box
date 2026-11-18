package monitoring

import (
	"slices"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"
)

// Which outbounds the monitoring tests, and when (see option.MonitoringOptions):
//   - exclude_types are never tested: a direct outbound "always answers" and its test goes from
//     the device's own address to the test URL, the IP lookup to geolocation services: the
//     provider sees a VPN client's checks (HC-09).
//   - on_demand_types are tested only when asked for (a tap, a selection) or while a group has
//     them selected: an AmneziaWG or WireGuard endpoint tested with the TCP proxies is a UDP
//     handshake to the server beside them every cycle. on_demand_tags does the same by tag,
//     whatever the type: a proxy that no automatic group uses, a VLESS over HTTP/3.
//   - retest_on_network_change: "all" (the default), "selected" (only what the groups have
//     selected: a burst of handshakes of every protocol to the same server at each Wi-Fi/LTE
//     switch is easy to see, HC-10) or "none".
//   - disable_ipinfo: no IP lookup after a test.
//
//   - held back (SetUntestable, not an option: its owner sets it while the box runs): never
//     tested, whatever asks for it (a cycle, a selection, keep top, a group's test, the outbound's
//     own test when it comes up, the app). For an outbound a test of which is itself what must not
//     happen: a last resort that waits for the user's agreement, whose test is a handshake with
//     its server.
//
// Keep top manages only the lazy outbounds the cycles test: never one tested on demand or held
// back. It took every lazy outbound for its own, and an AmneziaWG last resort (lazy to stay quiet,
// tested on demand only) was tested by its picks, and even kept, as soon as the ones it kept
// stopped answering.
//
// A hot reload can change on_demand_tags (SetOnDemandTags): the set of proxies of a subscription
// that no automatic group uses changes with the subscription, and a restart for it dropped every
// connection. The other fields stay as the box started.

const (
	RetestAll      = "all"
	RetestSelected = "selected"
	RetestNone     = "none"
)

type testScope struct {
	excludeTypes  []string
	onDemandTypes []string
	onDemandTags  *atomic.Pointer[[]string]        // replaced by a hot reload (SetOnDemandTags)
	untestable    *atomic.Pointer[map[string]bool] // held back (SetUntestable)
	retest        string
	noIPInfo      bool
}

func newTestScope(options option.MonitoringOptions) testScope {
	onDemandTags := &atomic.Pointer[[]string]{}
	tags := []string(options.OnDemandTags)
	onDemandTags.Store(&tags)
	retest := options.RetestOnNetworkChange
	switch retest {
	case RetestSelected, RetestNone:
	default:
		retest = RetestAll
	}
	return testScope{
		excludeTypes:  options.ExcludeTypes,
		onDemandTypes: options.OnDemandTypes,
		onDemandTags:  onDemandTags,
		untestable:    &atomic.Pointer[map[string]bool]{},
		retest:        retest,
		noIPInfo:      options.DisableIPInfo,
	}
}

// tags are the outbounds tested on demand only by their tag, now.
func (s testScope) tags() []string {
	if s.onDemandTags == nil {
		return nil
	}
	if tags := s.onDemandTags.Load(); tags != nil {
		return *tags
	}
	return nil
}

// hasOnDemand: some outbound may be tested on demand only, by its type or its tag.
func (s testScope) hasOnDemand() bool {
	return len(s.onDemandTypes) > 0 || len(s.tags()) > 0
}

// excluded: never tested, not in the registry.
func (s testScope) excluded(outbound adapter.Outbound) bool {
	return slices.Contains(s.excludeTypes, outbound.Type())
}

// onDemand: tested only when asked for or selected, by its type (on_demand_types) or its tag
// (on_demand_tags).
func (s testScope) onDemand(outbound adapter.Outbound) bool {
	return slices.Contains(s.onDemandTypes, outbound.Type()) || slices.Contains(s.tags(), outbound.Tag())
}

// held: the outbound is held back from every test (SetUntestable).
func (s testScope) held(tag string) bool {
	if s.untestable == nil {
		return false
	}
	held := s.untestable.Load()
	return held != nil && (*held)[tag]
}

// outsideKeepTop: an outbound keep top neither keeps nor rests, tests nor names: one tested on
// demand only, or held back.
func (s testScope) outsideKeepTop(outbound adapter.Outbound) bool {
	return s.onDemand(outbound) || s.held(outbound.Tag())
}

// SetUntestable holds the outbounds of tags back from every test from now on, and lets the others
// be tested again; nil holds none. The check is where every test is queued (enqueueTask), so no
// path of the monitoring tests a held one; keep top leaves them out as well. A test of one already
// running when it is held goes on to its end.
func (m *OutboundMonitoring) SetUntestable(tags []string) {
	if m.scope.untestable == nil {
		return
	}
	held := make(map[string]bool, len(tags))
	for _, tag := range tags {
		held[tag] = true
	}
	m.scope.untestable.Store(&held)
	m.keepTopRescope()
}

// keepTopRescope follows a change of what keep top may manage (on demand, held back) in a running
// keep top.
func (m *OutboundMonitoring) keepTopRescope() {
	k := &m.keepTop
	k.access.Lock()
	defer k.access.Unlock()
	registry := m.reg()
	if !k.on || k.options == nil || registry == nil {
		return // keepTopStart reads them when it starts
	}
	changed := m.keepTopRefreshLocked(registry)
	m.keepTopStepLocked(topOrder{restart: changed})
}

// SetOnDemandTags replaces the outbounds tested on demand only by their tag (on_demand_tags) of a
// running monitoring (hot reload). A tag that leaves the list is tested from the next cycle on; one
// that joins it is no longer tested in cycles unless a group selects it. Called before Reload of
// the same hot reload, so that the outbounds kept keep or drop their results by the new list.
func (m *OutboundMonitoring) SetOnDemandTags(tags []string) {
	if m.scope.onDemandTags == nil {
		return
	}
	tags = slices.Clone(tags)
	m.scope.onDemandTags.Store(&tags)
	m.keepTopRescope()
}

// selectedTags are the outbounds the groups have selected now.
func (m *OutboundMonitoring) selectedTags() map[string]bool {
	selected := map[string]bool{}
	for _, outbound := range m.outboundManager.Outbounds() {
		// a balancer's Now, a selector's stored choice: no Selected of a balancer, which may pick
		// (and so create a lazy outbound)
		if group, ok := outbound.(interface{ Now() string }); ok {
			if now := group.Now(); now != "" {
				selected[now] = true
			}
		} else if group, ok := outbound.(adapter.OutboundGroup); ok && outbound.Type() == C.TypeSelector {
			if now := group.Selected(N.NetworkTCP); now != nil {
				selected[now.Tag()] = true
			}
		}
	}
	return selected
}

// skipInCycle says whether a cycle (periodic, at the start, after a network change) leaves the
// outbound out: an on-demand one that no group has selected.
func (m *OutboundMonitoring) skipInCycle(tag string, state *outboundState, selected map[string]bool) bool {
	return selected != nil && m.scope.onDemand(state.outbound) && !selected[tag]
}
