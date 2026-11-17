package rule

import (
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	E "github.com/sagernet/sing/common/exceptions"
)

var _ RuleItem = (*UserIDRangeItem)(nil)

// UserIDRangeItem matches a connection whose owner was found, with a user id in one of the ranges
// ("1000:1999", or one id). A connection whose owner is unknown (no lookup, a failed one, or
// Android's INVALID_UID, -1) never matches: with invert, a rule matches exactly those, e.g. to
// reject what an app outside an Android VPN sends into the TUN by binding to its interface. //H
type UserIDRangeItem struct {
	ranges      [][2]int64
	description string
}

func NewUserIDRangeItem(ranges []string) (*UserIDRangeItem, error) {
	item := &UserIDRangeItem{description: "user_id_range=" + strings.Join(ranges, ",")}
	for _, r := range ranges {
		from, to, found := strings.Cut(strings.TrimSpace(r), ":")
		if !found {
			to = from
		}
		start, err := strconv.ParseInt(strings.TrimSpace(from), 10, 64)
		if err != nil {
			return nil, E.Cause(err, "parse user_id_range ", r)
		}
		end, err := strconv.ParseInt(strings.TrimSpace(to), 10, 64)
		if err != nil {
			return nil, E.Cause(err, "parse user_id_range ", r)
		}
		if start < 0 || end < start {
			return nil, E.New("bad user_id_range ", r)
		}
		item.ranges = append(item.ranges, [2]int64{start, end})
	}
	return item, nil
}

func (r *UserIDRangeItem) Match(metadata *adapter.InboundContext) bool {
	if metadata.ProcessInfo == nil || metadata.ProcessInfo.UserId < 0 {
		return false
	}
	uid := int64(metadata.ProcessInfo.UserId)
	for _, rng := range r.ranges {
		if uid >= rng[0] && uid <= rng[1] {
			return true
		}
	}
	return false
}

func (r *UserIDRangeItem) String() string {
	return r.description
}
