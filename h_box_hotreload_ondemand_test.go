package box

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/stretchr/testify/require"
)

// A hot reload changes on_demand_tags in place: the proxies of a subscription that no automatic
// group uses change with the subscription (a server adds UDP variants, a ranking another last
// resort), and the refusal ("hot reload cannot change: experimental.monitoring.on_demand_tags")
// restarted the box and dropped every connection. The rest of the monitoring still cannot change.
func TestH_HotReloadOnDemandTags(t *testing.T) {
	ctx := context.Background()
	options := func(verifyIPv6 bool, tags ...string) option.Options {
		return option.Options{Experimental: &option.ExperimentalOptions{Monitoring: &option.MonitoringOptions{
			URLs: []string{"https://example.com/generate_204"}, VerifyIPv6: verifyIPv6, OnDemandTags: tags,
		}}}
	}
	running := options(false, "9 HTTP3", "10 WG")
	next := options(false, "9 HTTP3", "19 HTTP3", "20 WG")

	require.NoError(t, CheckHotReload(ctx, running, next))
	require.NoError(t, CheckHotReload(ctx, options(false), next), "from none")
	require.NoError(t, CheckHotReload(ctx, next, options(false)), "to none")

	plan, err := planHotReload(ctx, running, next)
	require.NoError(t, err)
	require.True(t, plan.result.OnDemand)
	require.False(t, plan.result.IsEmpty(), "applied, not skipped as nothing to do")

	plan, err = planHotReload(ctx, running, options(false, "9 HTTP3", "10 WG"))
	require.NoError(t, err)
	require.False(t, plan.result.OnDemand)
	require.True(t, plan.result.IsEmpty())

	require.EqualError(t, CheckHotReload(ctx, running, options(true, "9 HTTP3", "19 HTTP3")),
		"hot reload cannot change: experimental.monitoring.verify_ipv6")
}
