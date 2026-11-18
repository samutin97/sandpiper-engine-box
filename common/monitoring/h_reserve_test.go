package monitoring

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/htest"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/stretchr/testify/require"
)

// The rule of the last resort, as hiddify-core builds it: a subscription of two servers, A (2, 3,
// and its last resort 10, an AmneziaWG endpoint) and B (12, 13, and its last resort 20). The
// automatic groups have 12, 13, 2 and 3, keep top keeps two of them; the last resorts are lazy
// endpoints (quiet until used) and tested on demand only, and the core holds them back from every
// test (SetUntestable) until the user agrees. The group is on 12; B stops answering, the group
// moves to 2 (the second tier). Not one test may go to 10 or 20: a test of an AmneziaWG endpoint is
// a handshake with its server. Keep top took every lazy outbound for its own, the last resorts too,
// and its pick after 12 and 13 died tested them (sp.12 on an emulator: AmneziaWG handshakes to both
// servers every 10 s, without the user's agreement).
func TestH_LastResortsGetNoTest(t *testing.T) {
	link, addr := slowServer(t)
	delays := map[string]int64{"12": 10, "13": 20, "2": 30, "3": 40, "20": 5, "10": 5}
	lazies := map[string]*topLazy{}
	var outbounds []adapter.Outbound
	for _, tag := range []string{"12", "13", "2", "3", "20", "10"} {
		lazies[tag] = newTopLazy(tag, addr, delays[tag])
		outbounds = append(outbounds, lazies[tag])
	}
	tiered := &movingSelector{pickSelector: pickSelector{fakeGroup{
		fakeOutbound: fakeOutbound{tag: "tiered", deps: []string{"12", "13", "2", "3", "20", "10"}},
		all:          []string{"12", "13", "2", "3", "20", "10"},
	}}}
	tiered.now.Store(lazies["12"])
	outbounds = append(outbounds, tiered)
	m := newTestMonitor(t, nil, option.MonitoringOptions{
		URLs:           []string{link},
		Interval:       badoption.Duration(time.Hour),
		URLTestTimeout: badoption.Duration(2 * time.Second),
		OnDemandTags:   []string{"20", "10"},
		KeepTop:        &option.KeepTopOptions{Count: 2},
	}, outbounds...)
	m.SetUntestable([]string{"20", "10"})
	require.NoError(t, htest.Start(m, adapter.StartStateInitialize))
	require.NoError(t, htest.Start(m, adapter.StartStatePostStart))
	require.Eventually(t, keptAre(m, "12", "13"), 20*time.Second, 5*time.Millisecond)

	// B stops answering; the group moves to the second tier
	lazies["12"].delay.Store(-1)
	lazies["13"].delay.Store(-1)
	tiered.now.Store(lazies["2"])
	require.NoError(t, m.SignalChange("tiered"))
	require.NoError(t, m.TestNow("12"))
	require.NoError(t, m.TestNow("13"))
	require.Eventually(t, keptAre(m, "2", "3"), 20*time.Second, 5*time.Millisecond, "keep top finds the other server")

	// what else asks for tests: the app's test of the group's members, the endpoint's test of
	// itself when it comes up, the rest of the cycle
	require.NoError(t, m.TestNow("tiered"))
	require.NoError(t, m.TestNow("20"))
	m.TestOutbounds([]string{"10", "20"}, "asked for by the app")
	time.Sleep(500 * time.Millisecond)

	for _, tag := range []string{"20", "10"} {
		require.Zero(t, lazies[tag].tests.Load(), "%s was tested before the user agreed", tag)
		require.False(t, lazies[tag].Loaded(), "%s was created", tag)
		require.NotContains(t, keptLazies(m), tag)
	}

	// once the user agreed to 20, it is tested as any other
	m.SetUntestable([]string{"10"})
	require.NoError(t, m.TestNow("20"))
	require.Eventually(t, func() bool { return lazies["20"].tests.Load() > 0 }, 10*time.Second, 5*time.Millisecond)
	require.Zero(t, lazies["10"].tests.Load())
}

// movingSelector is a group whose selection moves while the monitoring reads it.
type movingSelector struct {
	pickSelector
	now atomic.Value // *topLazy
}

func (g *movingSelector) Selected(string) adapter.Outbound {
	selected, _ := g.now.Load().(*topLazy)
	return selected
}
