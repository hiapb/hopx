package panel

import (
	"crypto/ed25519"
	"database/sql"
	"fmt"
	"math"
	"time"

	"hopx/internal/wire"
)

const quotaChunk int64 = 32 * 1024 * 1024 * 1000
const maximumQuotaChunk int64 = 1024 * 1024 * 1024 * 1000

func (s *Server) allocateQuota(node int64, generation string, rules []wire.Forward, claims []wire.QuotaClaim) ([]wire.QuotaGrant, []string, error) {
	return s.allocateNodeQuota(node, 0, generation, rules, claims, false)
}

func (s *Server) allocateNodeQuota(node, group int64, generation string, rules []wire.Forward, claims []wire.QuotaClaim, metered bool) ([]wire.QuotaGrant, []string, error) {
	if len(claims) > 4096 || len(generation) != 26 {
		return nil, nil, fmt.Errorf("invalid quota claims")
	}
	eligible := make(map[int64]int64)
	paired := make(map[int64]bool)
	for _, rule := range rules {
		if rule.QuotaManaged && (!rule.HAProxy || rule.Protocol != "tcp") {
			eligible[rule.Owner] = rule.QuotaEpoch
			paired[rule.Owner] = paired[rule.Owner] || metered && rule.EntryRatio > 0 &&
				(rule.ExitMeter != "" && rule.Ratio > rule.EntryRatio ||
					rule.BackupExitMeter != "" && rule.BackupRatio != nil && *rule.BackupRatio > rule.EntryRatio)
		}
	}
	tx, e := s.db.Begin()
	if e != nil {
		return nil, nil, e
	}
	defer tx.Rollback()
	grants := []wire.QuotaGrant{}
	closed := []string{}
	now := time.Now().Unix()
	for _, claim := range claims {
		if claim.ID != "" {
			ok, e := observeGrant(tx, node, claim)
			if e != nil {
				return nil, nil, e
			}
			if ok && claim.Close {
				closed = append(closed, claim.ID)
			}
		}
	}
	granted := make(map[int64]bool)
	for _, claim := range claims {
		if !claim.Want || granted[claim.Owner] {
			continue
		}
		epoch, ok := eligible[claim.Owner]
		if metered && claim.ExitMeter != "" {
			meter, valid := wire.VerifyExitMeter(s.meterKey.Public().(ed25519.PublicKey), claim.ExitMeter, group)
			if valid && meter.Managed && meter.Owner == claim.Owner && meter.Epoch == claim.Epoch {
				epoch, ok = meter.Epoch, true
			}
		}
		if !ok || epoch != claim.Epoch {
			continue
		}
		granted[claim.Owner] = true
		grant, e := nextGrant(tx, node, claim.Owner, epoch, generation, now, max(quotaChunk, min(maximumQuotaChunk, claim.Requested)), paired[claim.Owner])
		if e != nil {
			return nil, nil, e
		}
		if grant.ID != "" {
			grants = append(grants, grant)
		}
	}
	if e = tx.Commit(); e != nil {
		return nil, nil, e
	}
	return grants, closed, nil
}

func observeGrant(tx *sql.Tx, node int64, claim wire.QuotaClaim) (bool, error) {
	var allocated, spent, owner, epoch int64
	var closed bool
	e := tx.QueryRow("SELECT allocated,spent,user_id,epoch,closed FROM quota_grants WHERE id=? AND node=?", claim.ID, node).Scan(&allocated, &spent, &owner, &epoch, &closed)
	if e == sql.ErrNoRows {
		return true, nil
	}
	if e != nil {
		return false, e
	}
	if owner != claim.Owner || epoch != claim.Epoch || claim.Spent > allocated || claim.Spent < 0 {
		return false, fmt.Errorf("invalid quota settlement")
	}
	if closed {
		return true, nil
	}
	delta := max(0, claim.Spent-spent)
	if delta > 0 {
		_, e = tx.Exec("UPDATE users SET used=used+?+(billing_remainder+?)/1000,billing_remainder=(billing_remainder+?)%1000 WHERE id=? AND quota_epoch=?", delta/1000, delta%1000, delta%1000, owner, epoch)
		if e != nil {
			return false, e
		}
	}
	_, e = tx.Exec("UPDATE quota_grants SET spent=?,closed=? WHERE id=?", max(spent, claim.Spent), claim.Close, claim.ID)
	return true, e
}

func nextGrant(tx *sql.Tx, node, owner, epoch int64, generation string, now, window int64, paired bool) (wire.QuotaGrant, error) {
	grant := wire.QuotaGrant{Owner: owner, Epoch: epoch}
	var spent int64
	e := tx.QueryRow("SELECT id,allocated,spent,expires FROM quota_grants WHERE node=? AND user_id=? AND epoch=? AND generation=? AND closed=0", node, owner, epoch, generation).Scan(&grant.ID, &grant.Allocated, &spent, &grant.Expires)
	if e != nil && e != sql.ErrNoRows {
		return grant, e
	}
	if grant.ID != "" && grant.Expires <= now {
		return wire.QuotaGrant{}, nil
	}
	var quota, used, remainder, expires int64
	e = tx.QueryRow("SELECT quota,used,billing_remainder,expires FROM users u WHERE id=? AND quota_epoch=? AND "+
		ruleServiceActiveSQL+" AND u.unlimited_traffic=0", owner, epoch).Scan(&quota, &used, &remainder, &expires)
	if e == sql.ErrNoRows {
		return wire.QuotaGrant{}, nil
	}
	if e != nil {
		return grant, e
	}
	if quota <= 0 || expires <= now {
		return wire.QuotaGrant{}, nil
	}
	if grant.ID != "" && grant.Allocated-spent >= window*2/3 {
		if grant.Expires-now < 30 {
			grant.Expires = min(expires, now+90)
			_, e = tx.Exec("UPDATE quota_grants SET expires=? WHERE id=?", grant.Expires, grant.ID)
		}
		return grant, e
	}
	var reserved int64
	e = tx.QueryRow("SELECT coalesce(sum(allocated-spent),0) FROM quota_grants WHERE user_id=? AND epoch=? AND closed=0", owner, epoch).Scan(&reserved)
	if e != nil {
		return grant, e
	}
	available := min(quota-used, math.MaxInt64/1000)*1000 - remainder
	unreserved := max(0, available-reserved)
	if paired && unreserved > 1 {
		unreserved /= 2
	}
	add := min(unreserved, max(0, window-(grant.Allocated-spent)))
	if add == 0 {
		return grant, nil
	}
	grant.Expires = min(expires, now+90)
	if grant.ID == "" {
		grant.ID = token()
		grant.Allocated = add
		_, e = tx.Exec("INSERT INTO quota_grants(id,node,user_id,epoch,generation,allocated,expires) VALUES(?,?,?,?,?,?,?)", grant.ID, node, owner, epoch, generation, add, grant.Expires)
	} else {
		if grant.Allocated > math.MaxInt64-add {
			return wire.QuotaGrant{}, fmt.Errorf("quota lease limit")
		}
		grant.Allocated += add
		_, e = tx.Exec("UPDATE quota_grants SET allocated=?,expires=? WHERE id=?", grant.Allocated, grant.Expires, grant.ID)
	}
	return grant, e
}
