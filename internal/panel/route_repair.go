package panel

import (
	"database/sql"
	"encoding/json"
	"errors"

	"hopx/internal/wire"
)

const ruleRouteReadySQL = "coalesce(json_type(r.json,'$.routeRepair'),'null')='null'"
const ruleRouteRepairMessage = "请重新选择有权限的线路并保存规则"

// Keep the last entry and port in the relational columns so a pending rule
// retains its historical port reservation. Only the JSON route is editable.
func clearUnauthorizedRuleRoutes(tx *sql.Tx, group int64, scope string, args ...any) error {
	rows, err := tx.Query(`SELECT r.id,r.owner,r.entry,json_object(
		'path',json_extract(r.json,'$.path'),'backupPath',json_extract(r.json,'$.backupPath'),
		'routeRepair',json_extract(r.json,'$.routeRepair'))
		FROM rules r JOIN users u ON u.id=r.owner WHERE `+scope, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	var candidates []wire.Rule
	for rows.Next() {
		var rule wire.Rule
		var routes []byte
		if err = rows.Scan(&rule.ID, &rule.Owner, &rule.Entry, &routes); err != nil {
			return err
		}
		if err = json.Unmarshal(routes, &rule); err != nil {
			return err
		}
		candidates = append(candidates, rule)
	}
	if err = rows.Err(); err != nil {
		return err
	}
	if err = rows.Close(); err != nil {
		return err
	}

	groups := make(map[int64]wire.DeviceGroup)
	lookup := func(id int64) (wire.DeviceGroup, error) {
		device, found := groups[id]
		if !found {
			var err error
			device, err = scanGroup(tx.QueryRow(groupSelect+" WHERE id=?", id))
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return device, err
			}
			groups[id] = device
		}
		return device, nil
	}
	allowed := func(owner, id int64) (bool, error) {
		device, err := lookup(id)
		if err != nil {
			return false, err
		}
		return device.ID != 0 && canUse(User{ID: owner, Group: group}, device), nil
	}
	for _, rule := range candidates {
		var repair wire.RuleRouteRepair
		if rule.RouteRepair != nil {
			repair = *rule.RouteRepair
		}
		before := repair
		if !repair.Entry {
			ok, err := allowed(rule.Owner, rule.Entry)
			if err != nil {
				return err
			}
			repair.Entry = !ok
		}
		if repair.Entry {
			rule.Entry = 0
		}
		for _, lane := range []struct {
			path    *[]int64
			missing *bool
		}{{&rule.Path, &repair.Path}, {&rule.BackupPath, &repair.BackupPath}} {
			for _, id := range *lane.path {
				ok, err := allowed(rule.Owner, id)
				if err != nil {
					return err
				}
				if !ok {
					*lane.path = nil
					*lane.missing = true
					break
				}
			}
		}
		if before == repair {
			continue
		}
		primary, _ := json.Marshal(rule.Path)
		backup, _ := json.Marshal(rule.BackupPath)
		missing, _ := json.Marshal(repair)
		if _, err = tx.Exec(`UPDATE rules SET json=json_set(json,'$.entry',?,'$.path',json(?),
			'$.backupPath',json(?),'$.routeRepair',json(?)) WHERE id=?`,
			rule.Entry, string(primary), string(backup), string(missing), rule.ID); err != nil {
			return err
		}
	}
	return nil
}
