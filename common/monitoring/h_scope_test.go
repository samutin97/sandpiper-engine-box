package monitoring

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/htest"
	"github.com/sagernet/sing-box/option"
	"github.com/stretchr/testify/require"
)

func TestH_TestScope(t *testing.T) {
	s := newTestScope(option.MonitoringOptions{})
	if s.retest != RetestAll || s.noIPInfo || len(s.excludeTypes) != 0 {
		t.Fatalf("defaults changed: %+v", s)
	}
	s = newTestScope(option.MonitoringOptions{
		ExcludeTypes: []string{"direct"}, OnDemandTypes: []string{"awg"},
		RetestOnNetworkChange: "selected", DisableIPInfo: true,
	})
	if s.retest != RetestSelected || !s.noIPInfo {
		t.Fatalf("%+v", s)
	}
	m := &OutboundMonitoring{scope: s}
	awg := &outboundState{outbound: testOutbound{tag: "AWG", typ: "awg"}}
	vless := &outboundState{outbound: testOutbound{tag: "v", typ: "vless"}}
	if !m.skipInCycle("AWG", awg, map[string]bool{}) || m.skipInCycle("AWG", awg, map[string]bool{"AWG": true}) || m.skipInCycle("v", vless, map[string]bool{}) {
		t.Fatal("on-demand: an unselected awg is skipped, a selected one and a vless are not")
	}
	if !s.excluded(testOutbound{typ: "direct"}) || s.excluded(testOutbound{typ: "vless"}) {
		t.Fatal("exclude_types")
	}
	if newTestScope(option.MonitoringOptions{RetestOnNetworkChange: "bogus"}).retest != RetestAll {
		t.Fatal("unknown retest value")
	}
}

// on_demand_tags keeps proxies out of the cycles by tag, whatever their type (a VLESS over HTTP/3,
// a proxy no automatic group uses): skipped unless a group has them selected; the others are not.
func TestH_OnDemandTags(t *testing.T) {
	s := newTestScope(option.MonitoringOptions{OnDemandTags: []string{"h3"}})
	if !s.hasOnDemand() || newTestScope(option.MonitoringOptions{}).hasOnDemand() {
		t.Fatal("hasOnDemand")
	}
	m := &OutboundMonitoring{scope: s}
	h3 := &outboundState{outbound: testOutbound{tag: "h3", typ: "vless"}}
	grpc := &outboundState{outbound: testOutbound{tag: "grpc", typ: "vless"}}
	if !m.skipInCycle("h3", h3, map[string]bool{}) {
		t.Fatal("an unselected on-demand tag is left out of the cycle")
	}
	if m.skipInCycle("h3", h3, map[string]bool{"h3": true}) {
		t.Fatal("a selected one is tested")
	}
	if m.skipInCycle("grpc", grpc, map[string]bool{}) {
		t.Fatal("another vless is tested")
	}

	// in the cycle's targets
	a := &fakeOutbound{tag: "h3"}
	b := &fakeOutbound{tag: "grpc"}
	mon := newTestMonitor(t, nil, option.MonitoringOptions{OnDemandTags: []string{"h3"}}, a, b)
	require.NoError(t, htest.Start(mon, adapter.StartStateInitialize))
	require.Equal(t, []string{"grpc"}, mon.collectCycleTargets())
}

// testOutbound is an outbound of a type and a tag, that only the scope looks at.
type testOutbound struct {
	adapter.Outbound
	tag, typ string
}

func (o testOutbound) Type() string { return o.typ }
func (o testOutbound) Tag() string  { return o.tag }

// A hot reload replaces on_demand_tags of the running monitoring (SetOnDemandTags): a tag that
// leaves the list is tested in the next cycle, one that joins it is not; the caller's slice is not
// kept.
func TestH_OnDemandTagsHotReload(t *testing.T) {
	h3, grpc, wg := &fakeOutbound{tag: "h3"}, &fakeOutbound{tag: "grpc"}, &fakeOutbound{tag: "wg"}
	mon := newTestMonitor(t, nil, option.MonitoringOptions{OnDemandTags: []string{"h3"}}, h3, grpc, wg)
	require.NoError(t, htest.Start(mon, adapter.StartStateInitialize))
	require.ElementsMatch(t, []string{"grpc", "wg"}, mon.collectCycleTargets())

	tags := []string{"wg"}
	mon.SetOnDemandTags(tags)
	tags[0] = "grpc"
	require.ElementsMatch(t, []string{"h3", "grpc"}, mon.collectCycleTargets())

	mon.SetOnDemandTags(nil)
	require.False(t, mon.scope.hasOnDemand())
	require.ElementsMatch(t, []string{"h3", "grpc", "wg"}, mon.collectCycleTargets())
}
