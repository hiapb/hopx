package node

import (
	"sync"
	"time"

	"hopx/internal/wire"
)

type quotaKey struct{ owner, epoch int64 }

type quotaBook struct {
	wake    chan struct{}
	mu      sync.Mutex
	rules   map[quotaKey]bool
	exits   map[quotaKey]map[string]int
	active  map[quotaKey]*localGrant
	retired []wire.QuotaClaim
	changes map[quotaKey]chan struct{}
}

type localGrant struct {
	wire.QuotaGrant
	spent, pending int64
	reported       int64
	closing        bool
	sample         time.Time
	rate           float64
}

func (q *quotaBook) updateRules(rules []wire.Forward) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.rules = make(map[quotaKey]bool)
	for _, rule := range rules {
		if rule.Enabled && rule.QuotaManaged && (!rule.HAProxy || rule.Protocol != "tcp") {
			q.rules[quotaKey{rule.Owner, rule.QuotaEpoch}] = true
		}
	}
	for key := range q.changes {
		if !q.rules[key] && len(q.exits[key]) == 0 {
			q.signalChange(key)
		}
	}
}

func (q *quotaBook) attachExit(rule wire.Forward, ticket string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	key := quotaKey{rule.Owner, rule.QuotaEpoch}
	if q.exits == nil {
		q.exits = make(map[quotaKey]map[string]int)
	}
	if q.exits[key] == nil {
		q.exits[key] = make(map[string]int)
		q.requestSync()
	}
	q.exits[key][ticket]++
}

func (q *quotaBook) detachExit(rule wire.Forward, ticket string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	key := quotaKey{rule.Owner, rule.QuotaEpoch}
	tickets := q.exits[key]
	if tickets[ticket] <= 1 {
		delete(tickets, ticket)
	} else {
		tickets[ticket]--
	}
	if len(tickets) == 0 {
		delete(q.exits, key)
		if !q.rules[key] {
			q.signalChange(key)
		}
	}
}

func (q *quotaBook) claims(closeAll bool) []wire.QuotaClaim {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := append([]wire.QuotaClaim(nil), q.retired...)
	clock := time.Now()
	now := clock.Unix()
	for key, grant := range q.active {
		want := q.rules[key] || len(q.exits[key]) > 0
		grant.closing = grant.closing || grant.pending == 0 && (closeAll || !want || grant.Expires <= now)
		var requested int64
		if !grant.sample.IsZero() && clock.Sub(grant.sample) >= 500*time.Millisecond {
			rate := float64(grant.spent-grant.reported) / clock.Sub(grant.sample).Seconds()
			grant.rate = max(rate, grant.rate*0.80)
			grant.reported, grant.sample = grant.spent, clock
		}
		if grant.sample.IsZero() {
			grant.sample = clock
		}
		if grant.rate > 0 {
			requested = int64(min(grant.rate*12, float64(1024*1024*1024*1000)))
		}
		out = append(out, wire.QuotaClaim{Owner: key.owner, Epoch: key.epoch, ID: grant.ID, Spent: grant.spent, Close: grant.closing, Want: want && !closeAll, Requested: requested, ExitMeter: exitClaim(q.exits[key])})
	}
	if !closeAll {
		for key := range q.rules {
			if q.active[key] == nil {
				out = append(out, wire.QuotaClaim{Owner: key.owner, Epoch: key.epoch, Want: true, ExitMeter: exitClaim(q.exits[key])})
			}
		}
		for key, tickets := range q.exits {
			if !q.rules[key] && q.active[key] == nil {
				out = append(out, wire.QuotaClaim{Owner: key.owner, Epoch: key.epoch, Want: true, ExitMeter: exitClaim(tickets)})
			}
		}
	}
	return out
}

func exitClaim(tickets map[string]int) string {
	for ticket := range tickets {
		return ticket
	}
	return ""
}

func (q *quotaBook) apply(grants []wire.QuotaGrant, closed []string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, id := range closed {
		for key, g := range q.active {
			if g.ID == id {
				delete(q.active, key)
				q.signalChange(key)
			}
		}
		for i := len(q.retired) - 1; i >= 0; i-- {
			if q.retired[i].ID == id {
				q.retired = append(q.retired[:i], q.retired[i+1:]...)
			}
		}
	}
	for _, grant := range grants {
		key := quotaKey{grant.Owner, grant.Epoch}
		if current := q.active[key]; current != nil && current.ID == grant.ID {
			if current.QuotaGrant != grant {
				current.QuotaGrant = grant
				q.signalChange(key)
			}
			continue
		}
		q.active[key] = &localGrant{QuotaGrant: grant}
		q.signalChange(key)
	}
}

// The caller holds q.mu.
func (q *quotaBook) signalChange(key quotaKey) {
	if changed := q.changes[key]; changed != nil {
		delete(q.changes, key)
		close(changed)
	}
}

type quotaReservation struct {
	book         *quotaBook
	grant        *localGrant
	key          quotaKey
	ratio        int64
	reservedSize int
}

func (r quotaReservation) finish(actual int) {
	if r.grant == nil {
		return
	}
	r.book.mu.Lock()
	r.grant.pending -= int64(r.reservedSize) * r.ratio
	r.grant.spent += int64(actual) * r.ratio
	if actual < r.reservedSize {
		r.book.signalChange(r.key)
	}
	r.book.mu.Unlock()
}

func (q *quotaBook) take(rule wire.Forward, length int) (quotaReservation, bool) {
	reservation, ok, _ := q.reserve(rule, length, false)
	return reservation, ok
}

func (q *quotaBook) reserve(rule wire.Forward, length int, wait bool) (quotaReservation, bool, <-chan struct{}) {
	if !rule.QuotaManaged || rule.Ratio == 0 {
		return quotaReservation{}, true, nil
	}
	cost := int64(length) * rule.Ratio
	q.mu.Lock()
	key := quotaKey{rule.Owner, rule.QuotaEpoch}
	g := q.active[key]
	eligible := q.rules[key] || len(q.exits[key]) > 0
	if !eligible || g == nil || g.closing || g.Expires <= time.Now().Unix() || cost > g.Allocated-g.spent-g.pending {
		var changed chan struct{}
		if eligible {
			q.requestSync()
			if wait {
				if q.changes == nil {
					q.changes = make(map[quotaKey]chan struct{})
				}
				changed = q.changes[key]
				if changed == nil {
					changed = make(chan struct{})
					q.changes[key] = changed
				}
			}
		}
		q.mu.Unlock()
		return quotaReservation{}, false, changed
	}
	g.pending += cost
	if g.Allocated-g.spent-g.pending < 8*1024*1024*1000 && g.Allocated >= 16*1024*1024*1000 {
		q.requestSync()
	}
	q.mu.Unlock()
	return quotaReservation{book: q, grant: g, key: key, ratio: rule.Ratio, reservedSize: length}, true, nil
}

func (q *quotaBook) requestSync() {
	select {
	case q.wake <- struct{}{}:
	default:
	}
}
