package node

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"math/rand/v2"
	"net"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pires/go-proxyproto"
	"golang.org/x/time/rate"
	"hopx/internal/relay"
	"hopx/internal/wire"
)

type counter struct {
	in, out atomic.Int64
	// A negative value means the counter was collected and retired.
	writers atomic.Int64
}

type countKey struct {
	id, ratio, epoch int64
	quotaManaged     bool
}

func (c *counter) retain() bool {
	for {
		writers := c.writers.Load()
		if writers < 0 {
			return false
		}
		if c.writers.CompareAndSwap(writers, writers+1) {
			return true
		}
	}
}

func billingCounterKey(f wire.Forward, ratio int64, managed bool) countKey {
	epoch := int64(-1)
	if !managed && ratio > 0 {
		epoch = f.QuotaEpoch
	}
	return countKey{id: f.ID, ratio: ratio, epoch: epoch, quotaManaged: managed}
}

type ruleRuntime struct {
	lifetime         context.Context
	cancelLifetime   context.CancelFunc
	quota            *quotaBook
	rule             wire.Forward
	cert             *tls.Config
	shared           map[string]*ruleRuntime
	primary, backup  []*relay.Session
	failover         *routeFailover
	sequence         atomic.Uint64
	lastTCPRoute     atomic.Int64
	lastUDPRoute     atomic.Int64
	targetLoad       []atomic.Int64
	limit            *rate.Limiter
	accounting       *counter
	backupAccounting *counter
	splitAccounting  *counter
	ruleAdmission    *admission
	userAdmission    *admission
}

type dialCandidate struct {
	network             string
	route, path, target int
}

type dialFailure struct {
	count   int
	retryAt time.Time
}

type routeFailover struct {
	mu        sync.Mutex
	threshold int
	recovery  time.Duration
	failures  map[dialCandidate]dialFailure
}

func (f *routeFailover) available(candidate dialCandidate) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	failure := f.failures[candidate]
	return failure.retryAt.IsZero() || !time.Now().Before(failure.retryAt)
}

func (f *routeFailover) record(candidate dialCandidate, success bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if success {
		delete(f.failures, candidate)
		return
	}
	failure := f.failures[candidate]
	now := time.Now()
	if now.Before(failure.retryAt) {
		return
	}
	failure.count++
	if failure.count >= f.threshold {
		failure.retryAt = now.Add(f.recovery)
	}
	f.failures[candidate] = failure
}

type admission struct {
	mu      sync.Mutex
	ips     map[string]int
	active  int
	rate    int
	limiter *rate.Limiter
}

func (a *admission) enter(ip string, maxConnections, maxIPs int) bool {
	if a == nil {
		return true
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if maxConnections > 0 && a.active >= maxConnections {
		return false
	}
	if maxIPs > 0 && a.ips[ip] == 0 && len(a.ips) >= maxIPs {
		return false
	}
	a.ips[ip]++
	a.active++
	return true
}

func (a *admission) leave(ip string) {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.active--
	if a.ips[ip] <= 1 {
		delete(a.ips, ip)
	} else {
		a.ips[ip]--
	}
}

func newAdmission(mbps int) *admission {
	a := &admission{ips: make(map[string]int), rate: mbps}
	if mbps > 0 {
		a.limiter = rate.NewLimiter(rate.Limit(int64(mbps)*125000), 128<<10)
	}
	return a
}

type listenerKey struct {
	host    string
	network string
	port    int
}

type listener struct {
	tcp   net.Listener
	udp   *net.UDPConn
	route atomic.Pointer[ruleRuntime]
}

func (l *listener) close() {
	if l.tcp != nil {
		_ = l.tcp.Close()
	}
	if l.udp != nil {
		_ = l.udp.Close()
	}
}

type Engine struct {
	meter         atomic.Pointer[meterVerifier]
	exitMu        sync.Mutex
	exitWorkers   sync.WaitGroup
	exitCounters  map[string]*exitTraffic
	proxy         proxyEngine
	reverse       *relay.ReverseHub
	mux           relay.MuxPool
	quota         quotaBook
	activeTCP     atomic.Int64
	activeUDP     atomic.Int64
	udpQueued     atomic.Int64
	udpDropped    atomic.Int64
	bind          []string
	udpBind       []string
	maxListeners  int
	slots         chan struct{}
	mu            sync.Mutex
	listeners     map[listenerKey]*listener
	counters      map[countKey]*counter
	userAdmission map[int64]*admission
	ruleAdmission map[int64]*admission
	activeRules   map[int64]*ruleRuntime
	workers       sync.WaitGroup
	applied       string
}

func bindAddresses(value string) []string {
	addresses := []string{}
	used := make(map[string]bool)
	for _, part := range strings.Split(value, ",") {
		address := strings.TrimSpace(part)
		if address != "" && !used[address] {
			addresses = append(addresses, address)
			used[address] = true
		}
	}
	if len(addresses) == 0 {
		return []string{""}
	}
	return addresses
}

func NewEngine(bind string, maxListeners, maxConnections int) *Engine {
	return &Engine{bind: bindAddresses(bind), maxListeners: maxListeners, slots: make(chan struct{}, maxConnections), listeners: make(map[listenerKey]*listener), exitCounters: make(map[string]*exitTraffic), counters: make(map[countKey]*counter), userAdmission: make(map[int64]*admission), ruleAdmission: make(map[int64]*admission), activeRules: make(map[int64]*ruleRuntime), quota: quotaBook{active: make(map[quotaKey]*localGrant), wake: make(chan struct{}, 1)}}
}

type pathCache struct {
	bySlice map[hopSlice]*relay.Session
	byHash  map[[32]byte]*relay.Session
	mux     *relay.MuxPool
}

type hopSlice struct {
	first *wire.Hop
	count int
}

func compile(f wire.Forward, stats, backupStats *counter, user, rule *admission, paths pathCache, quota *quotaBook, reverse *relay.ReverseHub) (*ruleRuntime, error) {
	if !f.TLSShared && len(f.Targets) == 0 {
		return nil, errors.New("rule has no targets")
	}
	rr := &ruleRuntime{rule: f, accounting: stats, backupAccounting: backupStats, userAdmission: user, ruleAdmission: rule, limit: rule.limiter, quota: quota}
	if f.MaxFailures > 0 {
		recovery := f.RecoverySeconds
		if recovery == 0 {
			recovery = 30
		}
		rr.failover = &routeFailover{threshold: f.MaxFailures, recovery: time.Duration(recovery) * time.Second, failures: make(map[dialCandidate]dialFailure)}
	}
	if f.Strategy == "least-connections" {
		rr.targetLoad = make([]atomic.Int64, len(f.Targets))
	}
	if f.TLSCert != "" {
		cert, e := tls.X509KeyPair([]byte(f.TLSCert), []byte(f.TLSKey))
		if e != nil {
			return nil, e
		}
		rr.cert = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, NextProtos: f.TLSALPN}
		if f.HasTLSPolicy() || f.Ingress.InspectsTCP() {
			rr.cert.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
				if err := matchIngressTLS(hello, f.Ingress); err != nil {
					return nil, err
				}
				return nil, matchTLSHello(hello, f.Rule)
			}
		}
	} else if (f.HasTLSPolicy() && f.TLSSharedPort == 0) || f.TLSShared {
		return nil, errors.New("TLS policy requires a certificate")
	}
	for _, p := range f.Routes {
		if reverse == nil && len(p) > 0 && p[0].ReverseID != "" {
			continue
		}
		s, err := sharedPath(p, paths, reverse)
		if err != nil {
			return nil, err
		}
		rr.primary = append(rr.primary, s)
	}
	for _, p := range f.Backup {
		if reverse == nil && len(p) > 0 && p[0].ReverseID != "" {
			continue
		}
		s, err := sharedPath(p, paths, reverse)
		if err != nil {
			return nil, err
		}
		rr.backup = append(rr.backup, s)
	}
	if len(f.Path) == 0 {
		rr.primary = []*relay.Session{{}}
	}
	return rr, nil
}

func matchTLSHello(hello *tls.ClientHelloInfo, rule wire.Rule) error {
	name := strings.ToLower(hello.ServerName)
	if (rule.TLSRequireEmpty && name != "") || (len(rule.TLSServerNames) > 0 && !slices.Contains(rule.TLSServerNames, name)) {
		return errors.New("TLS server name not allowed")
	}
	if len(rule.TLSALPN) > 0 && !slices.ContainsFunc(hello.SupportedProtos, func(protocol string) bool {
		return slices.Contains(rule.TLSALPN, protocol)
	}) {
		return errors.New("TLS application protocol not allowed")
	}
	return nil
}

func matchIngressTLS(hello *tls.ClientHelloInfo, policy *wire.IngressFilter) error {
	if policy != nil && ((policy.RejectEmptySNI && hello.ServerName == "") || !allowIngressHost(hello.ServerName, policy)) {
		return errors.New("ingress TLS server name rejected")
	}
	return nil
}

func attachSharedRoutes(rules map[int64]*ruleRuntime) error {
	type sharedEntry struct {
		parent  *ruleRuntime
		configs map[string]*tls.Config
	}
	parents := make(map[int]sharedEntry)
	for _, rr := range rules {
		if !rr.rule.TLSShared {
			continue
		}
		if rr.cert == nil || rr.rule.Protocol != "tcp" || rr.rule.TLSSharedPort != 0 || parents[rr.rule.Port].parent != nil {
			return fmt.Errorf("invalid shared TLS rule %d", rr.rule.ID)
		}
		rr.shared = make(map[string]*ruleRuntime)
		parent := sharedEntry{parent: rr, configs: make(map[string]*tls.Config)}
		parents[rr.rule.Port] = parent
		rr.cert.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			if err := matchIngressTLS(hello, parent.parent.rule.Ingress); err != nil {
				return nil, err
			}
			name := strings.ToLower(hello.ServerName)
			child := parent.parent.shared[name]
			if child == nil {
				return nil, errors.New("no rule for TLS server name")
			}
			if err := matchTLSHello(hello, child.rule.Rule); err != nil {
				return nil, err
			}
			return parent.configs[name], nil
		}
	}
	for _, rr := range rules {
		if rr.rule.TLSSharedPort == 0 {
			continue
		}
		parent := parents[rr.rule.TLSSharedPort]
		if parent.parent == nil || rr.rule.Protocol != "tcp" || len(rr.rule.TLSServerNames) == 0 || rr.rule.TLSRequireEmpty || rr.rule.ProxyIn {
			return fmt.Errorf("invalid shared TLS child rule %d", rr.rule.ID)
		}
		childConfig := rr.cert
		if childConfig == nil {
			childConfig = &tls.Config{Certificates: parent.parent.cert.Certificates, MinVersion: tls.VersionTLS12, NextProtos: rr.rule.TLSALPN}
		}
		for _, name := range rr.rule.TLSServerNames {
			if name == "" || parent.parent.shared[name] != nil {
				return fmt.Errorf("duplicate or empty TLS server name in rule %d", rr.rule.ID)
			}
			parent.parent.shared[name] = rr
			parent.configs[name] = childConfig
		}
	}
	return nil
}

func sharedPath(path []wire.Hop, cache pathCache, reverse *relay.ReverseHub) (*relay.Session, error) {
	if len(path) == 0 {
		return nil, errors.New("empty relay route")
	}
	identity := hopSlice{first: &path[0], count: len(path)}
	if current := cache.bySlice[identity]; current != nil {
		return current, nil
	}
	raw, err := json.Marshal(path)
	if err != nil {
		return nil, err
	}
	key := sha256.Sum256(raw)
	if current := cache.byHash[key]; current != nil {
		cache.bySlice[identity] = current
		return current, nil
	}
	current, err := relay.PrepareWithMux(path, reverse, cache.mux)
	if err == nil {
		cache.byHash[key] = current
		cache.bySlice[identity] = current
	}
	return current, err
}
func ensureCounter(old, pending map[countKey]*counter, key countKey) *counter {
	if c := old[key]; c != nil {
		return c
	}
	if pending[key] == nil {
		pending[key] = &counter{}
	}
	return pending[key]
}

// Apply removals before staging listeners so an unrelated bind or reload
// failure cannot keep a revoked forward or its established sessions alive.
func (e *Engine) revokeMissingRules(rules []wire.Forward) bool {
	if len(e.activeRules) == 0 {
		return false
	}
	enabled := make(map[int64]bool, len(rules))
	for _, rule := range rules {
		if rule.Enabled {
			enabled[rule.ID] = true
		}
	}
	removed := false
	for id, active := range e.activeRules {
		if enabled[id] {
			continue
		}
		active.cancelLifetime()
		delete(e.activeRules, id)
		removed = true
	}
	if !removed {
		return false
	}
	for key, listener := range e.listeners {
		if !enabled[listener.route.Load().rule.ID] {
			listener.close()
			delete(e.listeners, key)
		}
	}
	for _, proxy := range []*proxyProcess{e.proxy.active, e.proxy.draining} {
		proxy.stopFrontends(func(id int64, _ proxyFrontend) bool { return !enabled[id] })
	}
	if e.proxy.active.running() {
		e.proxy.listeners = len(e.proxy.active.frontends) * len(e.bind)
	} else {
		e.proxy.listeners = 0
	}
	e.scheduleProxyExpiry()
	activeRules := make([]wire.Forward, 0, len(e.activeRules))
	for _, active := range e.activeRules {
		activeRules = append(activeRules, active.rule)
	}
	e.quota.updateRules(activeRules)
	e.applied = ""
	return true
}

func (e *Engine) Apply(ctx context.Context, c wire.Config, save func() error) error {
	return e.apply(ctx, c, save, nil)
}

func (e *Engine) apply(ctx context.Context, c wire.Config, save, invalidateCache func() error) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if c.Revision == e.applied {
		return nil
	}
	if e.revokeMissingRules(c.Rules) && invalidateCache != nil {
		if err := invalidateCache(); err != nil {
			return fmt.Errorf("remove revoked rules from cache: %w", err)
		}
	}
	next := map[listenerKey]*ruleRuntime{}
	proxyRules := make([]proxyRule, 0)
	newCounters := make(map[countKey]*counter)
	users := make(map[int64]*admission)
	rules := make(map[int64]*admission)
	candidates := make(map[int64]*ruleRuntime, len(c.Rules))
	paths := pathCache{bySlice: make(map[hopSlice]*relay.Session), byHash: make(map[[32]byte]*relay.Session), mux: &e.mux}
	for _, f := range c.Rules {
		if !f.Enabled {
			continue
		}
		if f.Port < 1 || f.Port > 65535 {
			return fmt.Errorf("rule %d has invalid port", f.ID)
		}
		stats := ensureCounter(e.counters, newCounters, billingCounterKey(f, f.Ratio, f.QuotaManaged))
		if f.HAProxy {
			if f.Protocol != "tcp" && f.Protocol != "both" {
				return fmt.Errorf("rule %d has invalid HAProxy network", f.ID)
			}
			proxyStats := ensureCounter(e.counters, newCounters, billingCounterKey(f, f.HAProxyRatio, false))
			proxyRules = append(proxyRules, proxyRule{Forward: f, stats: proxyStats})
		}
		backupStats := stats
		if f.BackupRatio != nil {
			backupStats = ensureCounter(e.counters, newCounters, billingCounterKey(f, *f.BackupRatio, f.QuotaManaged))
		}
		splitStats := stats
		if f.ExitMeter != "" || f.BackupExitMeter != "" {
			splitStats = ensureCounter(e.counters, newCounters, billingCounterKey(f, f.EntryRatio, f.QuotaManaged))
		}
		rule := e.ruleAdmission[f.ID]
		if rule == nil || rule.rate != f.RateMbps {
			rule = newAdmission(f.RateMbps)
		}
		rules[f.ID] = rule
		var user *admission
		if f.UserRate > 0 || f.UserConnections > 0 || f.UserIPs > 0 {
			user = users[f.Owner]
			if user == nil {
				user = e.userAdmission[f.Owner]
			}
			if user == nil || user.rate != f.UserRate {
				user = newAdmission(f.UserRate)
			}
			users[f.Owner] = user
		}
		rr := e.activeRules[f.ID]
		if rr == nil || f.TLSShared || !reflect.DeepEqual(rr.rule, f) {
			var err error
			rr, err = compile(f, stats, backupStats, user, rule, paths, &e.quota, e.reverse)
			if err != nil {
				return fmt.Errorf("rule %d: %w", f.ID, err)
			}
			rr.splitAccounting = splitStats
		}
		candidates[f.ID] = rr
		if f.TLSSharedPort != 0 {
			continue
		}
		for _, network := range []string{"tcp", "udp"} {
			if f.HAProxy && network == "tcp" {
				continue
			}
			if f.Protocol != network && f.Protocol != "both" {
				continue
			}
			bind := e.bind
			if network == "udp" && len(e.udpBind) > 0 {
				bind = e.udpBind
			}
			for _, host := range bind {
				lk := listenerKey{host: host, network: network, port: f.Port}
				if next[lk] != nil {
					return fmt.Errorf("duplicate listener %s/%d on %s", network, f.Port, host)
				}
				next[lk] = rr
			}
		}
	}
	if err := attachSharedRoutes(candidates); err != nil {
		return err
	}
	proxyListeners := len(proxyRules) * len(e.bind)
	if len(next)+proxyListeners > e.maxListeners {
		return fmt.Errorf("requested %d listeners, limit %d", len(next)+proxyListeners, e.maxListeners)
	}
	needed := len(e.listeners)
	for key := range next {
		if e.listeners[key] == nil {
			needed++
		}
	}
	if needed+proxyListeners > e.maxListeners {
		return fmt.Errorf("configuration switch needs %d listeners with predecessor, limit %d", needed, e.maxListeners)
	}
	newListeners := make(map[listenerKey]*listener)
	success := false
	newReservation := len(proxyRules) > 0 && e.proxy.reserved == 0
	if newReservation {
		if err := e.reserveProxySessions(); err != nil {
			return err
		}
	}
	defer func() {
		if !success {
			if newReservation {
				e.releaseProxySessions()
			}
			for _, l := range newListeners {
				l.close()
			}
		}
	}()
	for key, rr := range next {
		if e.listeners[key] != nil {
			continue
		}
		l := &listener{}
		addr := net.JoinHostPort(key.host, strconv.Itoa(key.port))
		var err error
		if key.network == "tcp" {
			l.tcp, err = net.Listen("tcp", addr)
		} else {
			var udpAddr *net.UDPAddr
			udpAddr, err = net.ResolveUDPAddr("udp", addr)
			if err == nil {
				l.udp, err = net.ListenUDP("udp", udpAddr)
				if err == nil {
					_ = l.udp.SetReadBuffer(256 << 10)
				}
			}
		}
		if err != nil {
			return fmt.Errorf("rule %d: listen %s %s: %w", rr.rule.ID, key.network, addr, err)
		}
		l.route.Store(rr)
		newListeners[key] = l
	}
	staged, proxyConfig, err := e.stageProxy(ctx, proxyRules)
	if err != nil {
		return err
	}
	defer func() {
		if !success && staged != nil && staged != e.proxy.active {
			staged.stop()
		}
	}()
	if save != nil {
		if err := save(); err != nil {
			return err
		}
	}
	for id, candidate := range candidates {
		old := e.activeRules[id]
		if candidate == old {
			continue
		}
		if old != nil && old.rule.Expires == candidate.rule.Expires && old.rule.QuotaEpoch == candidate.rule.QuotaEpoch {
			candidate.lifetime, candidate.cancelLifetime = old.lifetime, old.cancelLifetime
		} else if expires := candidate.rule.Expires; expires > 0 {
			candidate.lifetime, candidate.cancelLifetime = context.WithDeadline(ctx, time.Unix(expires, 0))
		} else {
			candidate.lifetime, candidate.cancelLifetime = context.WithCancel(ctx)
		}
	}
	for id, old := range e.activeRules {
		if candidate := candidates[id]; candidate == nil || candidate.lifetime != old.lifetime {
			old.cancelLifetime()
		}
	}
	e.commitProxy(staged, proxyConfig, proxyRules)
	for key, l := range e.listeners {
		if rr := next[key]; rr != nil {
			l.route.Store(rr)
		} else {
			l.close()
			delete(e.listeners, key)
		}
	}
	for key, l := range newListeners {
		e.listeners[key] = l
		e.workers.Go(func() {
			if l.tcp != nil {
				e.serveTCP(ctx, l)
			} else {
				e.serveUDP(ctx, l)
			}
		})
	}
	for key, stats := range newCounters {
		e.counters[key] = stats
	}
	e.userAdmission, e.ruleAdmission, e.activeRules = users, rules, candidates
	success = true
	e.applied = c.Revision
	e.quota.updateRules(c.Rules)
	return nil
}

func (e *Engine) Status() (string, int, int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.proxy.listeners > 0 && !e.proxy.active.running() {
		e.applied = ""
	}
	if e.proxy.listeners == 0 && !e.proxy.draining.running() {
		e.releaseProxySessions()
	}
	return e.applied, len(e.listeners) + e.proxy.listeners, len(e.slots) - e.proxy.reserved + e.proxy.connections
}

func (e *Engine) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, rr := range e.activeRules {
		rr.cancelLifetime()
	}
	for _, l := range e.listeners {
		l.close()
	}
	e.mux.Close()
	for _, process := range []*proxyProcess{e.proxy.active, e.proxy.draining} {
		if process.running() {
			_, _ = process.sample()
			process.stop()
		}
	}
	e.scheduleProxyExpiry()
	e.releaseProxySessions()
}

func (e *Engine) Traffic() []wire.Traffic {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.proxy.connections = 0
	for _, process := range []*proxyProcess{e.proxy.active, e.proxy.draining} {
		if process.running() {
			connections, _ := process.sample()
			e.proxy.connections += connections
		}
	}
	values := []wire.Traffic{}
	activeProxy, drainingProxy := e.proxy.active.running(), e.proxy.draining.running()
	for k, v := range e.counters {
		active := e.activeRules[k.id]
		if (active == nil || (active.accounting != v && active.backupAccounting != v && active.splitAccounting != v)) &&
			(!activeProxy || e.proxy.active.counters[k.id] != v) &&
			(!drainingProxy || e.proxy.draining.counters[k.id] != v) &&
			v.writers.CompareAndSwap(0, -1) {
			delete(e.counters, k)
		}
		in, out := v.in.Swap(0), v.out.Swap(0)
		if in != 0 || out != 0 {
			row := wire.Traffic{RuleID: k.id, In: in, Out: out, Ratio: k.ratio, QuotaManaged: k.quotaManaged}
			if k.epoch >= 0 {
				row.QuotaEpoch = new(k.epoch)
			}
			values = append(values, row)
		}
	}
	return e.collectExitTraffic(values)
}

func (e *Engine) restore(values []wire.Traffic) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.exitMu.Lock()
	defer e.exitMu.Unlock()
	for _, v := range values {
		if v.ExitMeter != "" {
			stats := e.exitCounters[v.ExitMeter]
			if stats == nil {
				stats = &exitTraffic{}
				e.exitCounters[v.ExitMeter] = stats
			}
			stats.in.Add(v.In)
			stats.out.Add(v.Out)
			continue
		}
		epoch := int64(-1)
		if v.QuotaEpoch != nil {
			epoch = *v.QuotaEpoch
		}
		k := countKey{id: v.RuleID, ratio: v.Ratio, epoch: epoch, quotaManaged: v.QuotaManaged}
		if e.counters[k] == nil {
			e.counters[k] = &counter{}
		}
		e.counters[k].in.Add(v.In)
		e.counters[k].out.Add(v.Out)
	}
}

func (rr *ruleRuntime) admit(ip string) bool {
	if rr.rule.Expires > 0 && time.Now().Unix() >= rr.rule.Expires {
		return false
	}
	if !rr.userAdmission.enter(ip, rr.rule.UserConnections, rr.rule.UserIPs) {
		return false
	}
	if rr.ruleAdmission.enter(ip, rr.rule.MaxConns, rr.rule.MaxIPs) {
		return true
	}
	rr.userAdmission.leave(ip)
	return false
}

func (rr *ruleRuntime) leave(ip string) {
	rr.ruleAdmission.leave(ip)
	rr.userAdmission.leave(ip)
}

func (rr *ruleRuntime) userLimiter() *rate.Limiter {
	if rr.userAdmission == nil {
		return nil
	}
	return rr.userAdmission.limiter
}

func (rr *ruleRuntime) dial(ctx context.Context, netw, sourceIP string) (net.Conn, bool, error) {
	conn, backup, _, err := rr.dialForward(ctx, netw, sourceIP, false)
	return conn, backup, err
}

func (rr *ruleRuntime) dialForward(ctx context.Context, netw, sourceIP string, meter bool) (net.Conn, bool, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	seq := int(rr.sequence.Add(1)-1) & 0x7fffffff
	switch rr.rule.Strategy {
	case "random":
		seq = rand.IntN(1 << 30)
	case "first":
		seq = 0
	case "ip-hash":
		hash := fnv.New32a()
		_, _ = hash.Write([]byte(sourceIP))
		seq = int(hash.Sum32() & 0x7fffffff)
	case "least-connections":
		selected := seq % len(rr.targetLoad)
		for i := range rr.targetLoad {
			if rr.targetLoad[i].Load() < rr.targetLoad[selected].Load() {
				selected = i
			}
		}
		seq = selected
	}
	var last = errors.New("链路暂无可用设备")
	for route, group := range [][]*relay.Session{rr.primary, rr.backup} {
		if len(group) == 0 {
			continue
		}
		routeContext := ctx
		cancelRoute := func() {}
		if route == 0 && len(rr.backup) > 0 {
			deadline, _ := ctx.Deadline()
			routeContext, cancelRoute = context.WithTimeout(ctx, time.Until(deadline)/2)
		}
		publicOnly := (route == 0 && rr.rule.PublicTargets) || (route > 0 && rr.rule.PublicBackupTargets)
		attempts := 0
		for i := 0; i < max(len(group), len(rr.rule.Targets)) && attempts < 4; i++ {
			if routeContext.Err() != nil {
				last = routeContext.Err()
				break
			}
			targetIndex := (seq + i) % len(rr.rule.Targets)
			pathIndex := (seq + i) % len(group)
			candidate := dialCandidate{network: netw, route: route, path: pathIndex, target: targetIndex}
			if rr.failover != nil && !rr.failover.available(candidate) {
				continue
			}
			attempts++
			target := rr.rule.Targets[targetIndex]

			ticket := ""
			if meter {
				ticket = rr.rule.ExitMeter
				if route > 0 {
					ticket = rr.rule.BackupExitMeter
				}
			}
			conn, metered, e := dialRuleTarget(routeContext, group[pathIndex], netw, target, ticket, publicOnly)
			if rr.failover != nil && !errors.Is(e, context.Canceled) {
				rr.failover.record(candidate, e == nil)
			}
			if e == nil {
				cancelRoute()
				if len(rr.targetLoad) > 0 {
					slot := &rr.targetLoad[targetIndex]
					slot.Add(1)
					conn = &loadConn{Conn: conn, load: slot}
				}
				return conn, route > 0, metered, nil
			}
			last = e
		}
		cancelRoute()
	}
	return nil, false, false, last
}

func (rr *ruleRuntime) recordRoute(last *atomic.Int64, backup bool) {
	if len(rr.rule.BackupPath) == 0 {
		return
	}
	at := time.Now().Unix()
	if backup {
		at = -at
	}
	last.Store(at)
}

func (rr *ruleRuntime) billing(backup, metered bool) (wire.Forward, *counter) {
	rule := rr.rule
	if metered {
		rule.Ratio = rule.EntryRatio
		return rule, rr.splitAccounting
	}
	if backup && rule.BackupRatio != nil {
		rule.Ratio = *rule.BackupRatio
		return rule, rr.backupAccounting
	}
	return rule, rr.accounting
}

type loadConn struct {
	net.Conn
	load *atomic.Int64
	once sync.Once
}

func (c *loadConn) Close() error {
	c.once.Do(func() { c.load.Add(-1) })
	return c.Conn.Close()
}
func (c *loadConn) CloseWrite() error {
	if underlying, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return underlying.CloseWrite()
	}
	return c.Close()
}

func (e *Engine) serveTCP(ctx context.Context, l *listener) {
	for {
		conn, err := l.tcp.Accept()
		if err != nil {
			return
		}
		select {
		case e.slots <- struct{}{}:
			rr := l.route.Load()
			e.activeTCP.Add(1)
			e.workers.Go(func() {
				defer func() { e.activeTCP.Add(-1); <-e.slots }()
				rr.serveTCP(ctx, conn)
			})
		default:
			conn.Close()
		}
	}
}

type prefixedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *prefixedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func (c *prefixedConn) CloseWrite() error {
	if conn, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return conn.CloseWrite()
	}
	return c.Conn.Close()
}

func proxyInput(c net.Conn, version int) (net.Conn, net.Addr, net.Addr, error) {
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer c.SetReadDeadline(time.Time{})
	reader := bufio.NewReaderSize(c, 256)
	header, err := proxyproto.Read(reader)
	if err != nil {
		return nil, nil, nil, err
	}
	if version != 0 && int(header.Version) != version {
		return nil, nil, nil, errors.New("unexpected PROXY protocol version")
	}
	connection := &prefixedConn{c, reader}
	if header.Command == proxyproto.LOCAL {
		return connection, c.RemoteAddr(), c.LocalAddr(), nil
	}
	source, destination, ok := header.TCPAddrs()
	if !ok {
		return nil, nil, nil, errors.New("invalid TCP PROXY header")
	}
	return connection, source, destination, nil
}

func proxyOutput(dst net.Conn, source, destination net.Addr, version int) error {
	if version == 0 {
		version = 1
	}
	header := proxyproto.HeaderProxyFromAddrs(byte(version), source, destination)
	if source, destination, ok := header.TCPAddrs(); ok && (source.IP.To4() == nil) != (destination.IP.To4() == nil) {
		header = &proxyproto.Header{Version: byte(version), Command: proxyproto.LOCAL, TransportProtocol: proxyproto.UNSPEC}
	}
	_, err := header.WriteTo(dst)
	return err
}

func (rr *ruleRuntime) serveTCP(ctx context.Context, client net.Conn) {
	defer client.Close()
	if rr.lifetime != nil {
		ctx = rr.lifetime
	}
	if ctx.Err() != nil {
		return
	}
	entryContext := ctx
	originalClient := client
	stop := context.AfterFunc(ctx, func() { originalClient.Close() })
	defer stop()
	source, destination := client.RemoteAddr(), client.LocalAddr()
	if rr.rule.ProxyIn {
		c, src, dst, e := proxyInput(client, rr.rule.ProxyInVersion)
		if e != nil {
			return
		}
		client, source, destination = c, src, dst
	}
	ip, _, _ := net.SplitHostPort(source.String())
	serverName := ""
	var sharedFilters []int
	terminatedTLS := rr.cert != nil
	if rr.shared == nil {
		if !rr.admit(ip) {
			return
		}
		defer rr.leave(ip)
	}
	if rr.cert != nil {
		conn := tls.Server(client, rr.cert)
		deadline, cancel := context.WithTimeout(ctx, 8*time.Second)
		err := conn.HandshakeContext(deadline)
		cancel()
		if err != nil {
			return
		}
		client = conn
		serverName = conn.ConnectionState().ServerName
		if rr.shared != nil {
			sharedFilters = rr.rule.ResponseFilters
			rr = rr.shared[strings.ToLower(serverName)]
			if rr == nil || !rr.admit(ip) {
				return
			}
			defer rr.leave(ip)
			if rr.lifetime != nil {
				ctx = rr.lifetime
				stopChild := context.AfterFunc(ctx, func() { originalClient.Close() })
				defer stopChild()
			}
		}
	}
	client, err := inspectIngress(client, rr.rule.Ingress, serverName, terminatedTLS)
	if err != nil {
		return
	}
	target, backup, metered, err := rr.dialForward(ctx, "tcp", ip, true)
	if err != nil {
		return
	}
	defer target.Close()
	rawTarget := target
	stopTarget := context.AfterFunc(ctx, func() { rawTarget.Close() })
	defer stopTarget()
	if entryContext != ctx {
		stopEntry := context.AfterFunc(entryContext, func() { rawTarget.Close() })
		defer stopEntry()
	}
	if rr.rule.ProxyOut && proxyOutput(target, source, destination, rr.rule.ProxyOutVersion) != nil {
		return
	}
	if mode := rr.rule.TLSOrigin; mode != 0 {
		if mode == 1 {
			serverName = ""
		}
		tlsTarget := tls.Client(target, &tls.Config{
			ServerName: serverName, InsecureSkipVerify: mode != 3, MinVersion: tls.VersionTLS12,
		})
		deadline, cancel := context.WithTimeout(ctx, 8*time.Second)
		err := tlsTarget.HandshakeContext(deadline)
		cancel()
		if err != nil {
			return
		}
		target = tlsTarget
	}
	rr.recordRoute(&rr.lastTCPRoute, backup)
	billing, counts := rr.billing(backup, metered)
	if !counts.retain() {
		return
	}
	defer counts.writers.Add(-1)
	done := make(chan struct{}, 1)
	go func() { rr.copy(ctx, target, client, billing, &counts.in); done <- struct{}{} }()
	response, e := filterResponse(target, ip, rr.rule.ResponseFilters, sharedFilters)
	if e == nil {
		rr.copy(ctx, client, response, billing, &counts.out)
	} else {
		target.Close()
		client.Close()
	}
	<-done
}

var tcpBuffers = sync.Pool{New: func() any { return new([16 << 10]byte) }}

type countedWriter struct {
	runtime *ruleRuntime
	billing wire.Forward
	ctx     context.Context
	io.Writer
	limit     *rate.Limiter
	userLimit *rate.Limiter
	bytes     *atomic.Int64
}

func (w countedWriter) Write(p []byte) (int, error) {
	if w.limit != nil {
		if e := w.limit.WaitN(w.ctx, len(p)); e != nil {
			return 0, e
		}
	}
	if w.userLimit != nil {
		if e := w.userLimit.WaitN(w.ctx, len(p)); e != nil {
			return 0, e
		}
	}
	finish, ok := w.runtime.quota.take(w.billing, len(p))
	if !ok {
		return 0, errors.New("quota allowance exhausted")
	}
	n, e := w.Writer.Write(p)
	finish(n)
	w.bytes.Add(int64(n))
	return n, e
}

func (rr *ruleRuntime) copy(ctx context.Context, dst, src net.Conn, billing wire.Forward, bytes *atomic.Int64) {
	buf := tcpBuffers.Get().(*[16 << 10]byte)
	defer tcpBuffers.Put(buf)
	_, e := io.CopyBuffer(countedWriter{rr, billing, ctx, dst, rr.limit, rr.userLimiter(), bytes}, struct{ io.Reader }{src}, buf[:])
	if closer, ok := dst.(interface{ CloseWrite() error }); ok && e == nil {
		_ = closer.CloseWrite()
	} else {
		dst.Close()
	}
}
