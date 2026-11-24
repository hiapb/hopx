package panel

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"hopx/internal/wire"
)

const portCheckPageSize = 8
const automaticPortCheckTimeout = 12 * time.Second

type rulePortCheck struct {
	Name     string             `json:"name"`
	Status   string             `json:"status"`
	Bindings []wire.PortBinding `json:"bindings,omitempty"`
}

func forwardingPortCheck(rule wire.Rule, group wire.DeviceGroup) wire.PortCheck {
	check := wire.PortCheck{Port: rule.Port, Network: group.RuleNetwork(rule), HAProxy: rule.UsesHAProxy()}
	if group.Ingress.BlocksUDP() && check.Network == "both" {
		check.Network = "tcp"
	}
	return check
}

func (s *Server) hasPortCheckNode(group int64) bool {
	now := time.Now()
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, node := range s.devices {
		if node.GroupID == group && node.AcceptPortCheck && now.Sub(node.LastSeen) < time.Hour {
			return true
		}
	}
	return false
}

func (s *Server) checkNewRulePort(ctx context.Context, check wire.PortCheck, group wire.DeviceGroup, user User) (int, error) {
	devices, err := s.deviceGroupSnapshot(false, group.ID)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	ctx, cancel := context.WithTimeout(ctx, automaticPortCheckTimeout)
	defer cancel()

	type outcome struct {
		status int
		err    error
	}
	results := make(chan outcome, portCheckPageSize)
	var pending int
	consume := func() outcome {
		pending--
		return <-results
	}
	for _, device := range devices {
		if !device.Online || device.Revoked || !device.AcceptPortCheck {
			continue
		}
		if pending == cap(results) {
			if result := consume(); result.err != nil {
				return result.status, result.err
			}
		}
		if ctx.Err() != nil {
			return http.StatusServiceUnavailable, errors.New("入口节点端口检查超时，请稍后再试")
		}
		pending++
		go func() {
			task := wire.DiagnosticTask{ID: token(), PortCheck: &check}
			result, status := s.waitDiagnostic(ctx, device.ID, task)
			if status != http.StatusOK || len(result.Bindings) == 0 {
				if status == http.StatusTooManyRequests {
					results <- outcome{http.StatusServiceUnavailable, errors.New("入口节点正在处理其他检查，请稍后再试")}
				} else {
					results <- outcome{http.StatusServiceUnavailable, errors.New("入口节点端口检查超时，请稍后再试")}
				}
				return
			}
			source := "入口节点"
			if (user.Admin || group.Owner == user.ID) && group.Routing.StatusVisibility != "none" {
				source = device.Name
			}
			for _, binding := range result.Bindings {
				switch binding.Status {
				case "available":
					continue
				case "occupied":
					results <- outcome{http.StatusConflict, fmt.Errorf("%s的 %s 端口 %d 已被占用，请更换监听端口", source, strings.ToUpper(binding.Network), check.Port)}
				case "no_haproxy":
					results <- outcome{http.StatusConflict, fmt.Errorf("%s 尚未安装 HAProxy", source)}
				default:
					results <- outcome{http.StatusConflict, fmt.Errorf("%s 无法监听端口 %d", source, check.Port)}
				}
				return
			}
			results <- outcome{}
		}()
	}
	for pending > 0 {
		if result := consume(); result.err != nil {
			return result.status, result.err
		}
	}
	return 0, nil
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
	check := forwardingPortCheck(rule, group)
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
