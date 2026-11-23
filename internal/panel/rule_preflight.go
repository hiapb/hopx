package panel

import (
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
	"sync"

	"hopx/internal/wire"
)

const portCheckPageSize = 8

type rulePortCheck struct {
	Name     string             `json:"name"`
	Status   string             `json:"status"`
	Bindings []wire.PortBinding `json:"bindings,omitempty"`
}

func (s *Server) preflightRule(w http.ResponseWriter, r *http.Request, u User) {
	var rule wire.Rule
	if !decode(w, r, &rule) {
		return
	}
	existingID := rule.ID
	var group wire.DeviceGroup
	status, err := s.previewRule(r, u, &rule, &group)
	if err != nil {
		if status == 500 {
			dbFailure(w, err)
		} else {
			fail(w, status, err.Error())
		}
		return
	}
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	check := wire.PortCheck{Port: rule.Port, Network: group.RuleNetwork(rule), HAProxy: rule.UsesHAProxy()}
	if group.Ingress != nil && (group.Ingress.DisableUDP || len(group.Ingress.AllowedHosts) > 0) && check.Network == "both" {
		check.Network = "tcp"
	}
	if rule.TLSSharedPort != 0 || (!u.Admin && group.Owner != u.ID) {
		port := rule.Port
		if rule.TLSSharedPort != 0 {
			port = rule.TLSSharedPort
		}
		respond(w, 200, map[string]any{"port": port, "network": check.Network, "mode": "panel", "nodes": []rulePortCheck{}})
		return
	}
	devices, err := s.deviceGroupSnapshot(false, rule.Entry)
	if err != nil {
		dbFailure(w, err)
		return
	}
	page = min(max(page, 1), max(1, (len(devices)+portCheckPageSize-1)/portCheckPageSize))
	start := (page - 1) * portCheckPageSize
	end := min(start+portCheckPageSize, len(devices))
	results := make([]rulePortCheck, end-start)
	var checks sync.WaitGroup
	showName := group.Routing.StatusVisibility != "none"
	for i, device := range devices[start:end] {
		name := fmt.Sprintf("入口 %d", start+i+1)
		if showName {
			name = device.Name
		}
		results[i] = rulePortCheck{Name: name, Status: "offline"}
		if !device.Online || device.Revoked {
			continue
		}
		if !device.AcceptPortCheck {
			results[i].Status = "upgrade"
			continue
		}
		checks.Go(func() {
			task := wire.DiagnosticTask{ID: token(), RuleID: existingID, PortCheck: &check}
			result, code := s.waitDiagnostic(r.Context(), device.ID, task)
			switch {
			case code == 200 && len(result.Bindings) != 0:
				results[i].Status = "checked"
				results[i].Bindings = result.Bindings
			case code == 429:
				results[i].Status = "busy"
			default:
				results[i].Status = "timeout"
			}
		})
	}
	checks.Wait()
	respond(w, 200, map[string]any{"port": check.Port, "network": check.Network, "mode": "node", "nodes": results,
		"page": page, "pageSize": portCheckPageSize, "total": len(devices)})
}

func (s *Server) previewRule(r *http.Request, u User, rule *wire.Rule, group *wire.DeviceGroup) (int, error) {
	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		return 500, err
	}
	defer tx.Rollback()
	if err = storeRule(tx, u, rule); err != nil {
		return 400, err
	}
	if rule.Enabled {
		if err = s.checkGroupCapacity(tx, rule.Entry); err != nil {
			return 409, err
		}
	}
	*group, err = scanGroup(tx.QueryRowContext(r.Context(), groupSelect+" WHERE id=?", rule.Entry))
	if err == sql.ErrNoRows {
		return 400, err
	}
	if err != nil {
		return 500, err
	}
	return 0, nil
}
