package monitoring

import (
	"errors"

	"github.com/sagernet/sing-box/adapter"
	E "github.com/sagernet/sing/common/exceptions"
)

// monitoringRegistry is the set of monitored outbounds and groups. It is never modified once
// stored: Reload builds a new one, so readers need no lock.
type monitoringRegistry struct {
	outbounds map[string]*outboundState
	groups    map[string]*groupState
}

func newMonitoringRegistry() *monitoringRegistry {
	return &monitoringRegistry{
		outbounds: make(map[string]*outboundState),
		groups:    make(map[string]*groupState),
	}
}

func (m *OutboundMonitoring) reg() *monitoringRegistry {
	return m.registry.Load()
}

// buildRegistry reads the current outbounds, endpoints and groups. An outbound that is still the
// same instance keeps its test history from previous; one replaced by a hot reload keeps its
// last result as a cached one, due for a test, the way a result loaded at start is: the groups
// can still fall back on it, the cycle tests it before the untested, and the app shows it as
// waiting until the new instance has answered. A group that still exists keeps its observer, so
// subscribers keep receiving its events.
func (m *OutboundMonitoring) buildRegistry(previous *monitoringRegistry) (*monitoringRegistry, error) {
	registry := newMonitoringRegistry()
	add := func(outbound adapter.Outbound) {
		if m.scope.excluded(outbound) { // never tested (exclude_types)
			return
		}
		state := &outboundState{groupTags: []string{}, invalid: true, outbound: outbound, dependencies: outbound.Dependencies()}
		if old, ok := previous.outbounds[outbound.Tag()]; ok {
			old.mu.Lock()
			state.history = old.history
			state.lastURL = old.lastURL
			if old.outbound == outbound {
				state.invalid = old.invalid
				state.from_cache = old.from_cache
			} else {
				state.from_cache = state.history.Delay != 0
				state.history.IpInfoFromCache = state.history.IpInfo != nil
			}
			old.mu.Unlock()
		}
		registry.outbounds[outbound.Tag()] = state
	}
	for _, outbound := range m.outboundManager.Outbounds() {
		add(outbound)
	}
	for _, endpoint := range m.endpointManager.Endpoints() {
		add(endpoint)
	}
	for tag, state := range registry.outbounds {
		for _, dependency := range state.dependencies {
			if dependencyState, ok := registry.outbounds[dependency]; ok {
				dependencyState.dependenciesInverse = append(dependencyState.dependenciesInverse, tag)
			}
		}
	}

	all := m.registryGroup(registry, previous, "")
	for tag, state := range registry.outbounds {
		all.outbounds[tag] = struct{}{}
		state.groupTags = append(state.groupTags, "")
	}
	for _, outbound := range m.outboundManager.Outbounds() {
		group, isGroup := outbound.(adapter.OutboundGroup)
		if !isGroup {
			continue
		}
		groupTag := group.Tag()
		grp := m.registryGroup(registry, previous, groupTag)
		for _, tag := range group.All() {
			state, exists := registry.outbounds[tag]
			if !exists {
				return nil, errors.New("outbound monitoring: outbound not found: " + tag + " in group " + groupTag)
			}
			grp.outbounds[tag] = struct{}{}
			state.groupTags = append(state.groupTags, groupTag)
		}
	}
	return registry, nil
}

func (m *OutboundMonitoring) registryGroup(registry, previous *monitoringRegistry, tag string) *groupState {
	if grp, ok := registry.groups[tag]; ok {
		return grp
	}
	grp := &groupState{tag: tag, outbounds: make(map[string]struct{})}
	if old, ok := previous.groups[tag]; ok {
		grp.observer = old.observer
		grp.notifyCh = old.notifyCh
		grp.bestDelay = old.bestDelay
	} else if pending, ok := m.pendingGroups[tag]; ok {
		// subscribed before this registry had it: its subscribers get its events from now on
		grp.observer = pending
		grp.notifyCh = make(chan struct{}, 1)
		delete(m.pendingGroups, tag)
	} else {
		grp.observer = NewBroadcaster[GroupEvent](m.ctx)
		grp.notifyCh = make(chan struct{}, 1)
	}
	registry.groups[tag] = grp
	return grp
}

// loadRegistry builds the registry from the outbounds as they are and stores it, under
// reloadAccess (see subscribePendingGroup).
func (m *OutboundMonitoring) loadRegistry() (*monitoringRegistry, error) {
	m.reloadAccess.Lock()
	defer m.reloadAccess.Unlock()
	registry, err := m.buildRegistry(newMonitoringRegistry())
	if err != nil {
		return nil, err
	}
	m.registry.Store(registry)
	return registry, nil
}

// subscribePendingGroup subscribes to a group the registry does not have yet. A hot reload
// creates and starts the new outbounds first and reloads the monitoring after: a balancer it adds
// subscribes from its PostStart, before the reload registers it, and got "group not found", so it
// never followed the tests (the balancer stayed on its first choice for the whole run). The
// observer waits here and the next registry that has the group takes it (registryGroup). Under
// reloadAccess, so a reload either already stored a registry with the group, or takes the
// observer when it builds one.
func (m *OutboundMonitoring) subscribePendingGroup(groupTag string) (<-chan GroupEvent, error) {
	m.reloadAccess.Lock()
	defer m.reloadAccess.Unlock()
	if g, ok := m.reg().groups[groupTag]; ok {
		return g.observer.Subscribe(8), nil
	}
	if m.ctx.Err() != nil {
		return nil, E.New("group not found ", groupTag, ": monitoring closed")
	}
	if m.pendingGroups == nil {
		m.pendingGroups = make(map[string]*Broadcaster[GroupEvent])
	}
	observer, ok := m.pendingGroups[groupTag]
	if !ok {
		observer = NewBroadcaster[GroupEvent](m.ctx)
		m.pendingGroups[groupTag] = observer
	}
	return observer.Subscribe(8), nil
}

func (m *OutboundMonitoring) unsubscribePendingGroup(groupTag string, observer <-chan GroupEvent) bool {
	m.reloadAccess.Lock()
	defer m.reloadAccess.Unlock()
	pending, ok := m.pendingGroups[groupTag]
	if ok {
		pending.Unsubscribe(observer)
	}
	return ok
}

// closePendingGroups ends the subscriptions of groups that never came.
func (m *OutboundMonitoring) closePendingGroups() {
	m.reloadAccess.Lock()
	defer m.reloadAccess.Unlock()
	for tag, observer := range m.pendingGroups {
		observer.Close()
		delete(m.pendingGroups, tag)
	}
}

// Reload re-reads the outbounds and endpoints after they were replaced at runtime (hot reload).
// New and replaced outbounds are tested; groups that no longer exist close their subscriptions.
func (m *OutboundMonitoring) Reload() error {
	m.reloadAccess.Lock()
	defer m.reloadAccess.Unlock()
	previous := m.reg()
	registry, err := m.buildRegistry(previous)
	if err != nil {
		return err
	}
	m.registry.Store(registry)
	m.keepTopReload(registry) // before the changed ones are tested: the ones that rest are not
	if m.started {
		for tag, grp := range registry.groups {
			if _, existed := previous.groups[tag]; !existed {
				m.schedulerWG.Add(1)
				go m.groupNotifierLoop(grp)
			}
		}
	}
	for tag, grp := range previous.groups {
		if _, kept := registry.groups[tag]; !kept && grp.observer != nil {
			grp.observer.Close()
		}
	}
	m.logger.Info("reloaded ", len(registry.outbounds), " outbounds and ", len(registry.groups), " groups for monitoring")
	if m.started {
		m.emitAllGroupEvents(registry)
		m.testChanged(previous, registry)
	}
	return nil
}

// testChanged queues a test of every outbound the reload created or replaced, and of nothing
// else: the others keep their result until their regular time. A whole cycle here used to test
// every outbound whose result was older than the interval, which after a profile update was all
// of them, and the changed ones waited behind them, or for the next tick when a cycle was
// already running. Before the first cycle there is nothing to do: it tests everything.
func (m *OutboundMonitoring) testChanged(previous, registry *monitoringRegistry) {
	cycleID := m.cycleSeq.Load()
	if cycleID == 0 {
		return
	}
	for tag, state := range registry.outbounds {
		if _, isGroup := registry.groups[tag]; isGroup {
			continue
		}
		if old, ok := previous.outbounds[tag]; ok && old.outbound == state.outbound {
			continue
		}
		if m.parked(tag, state) { // tested when it is taken out of rest
			continue
		}
		m.enqueueTask(&testTask{outboundTag: tag, cycleID: cycleID, reason: "replaced by a reload"})
	}
}
