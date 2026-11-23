package panel

import (
	"database/sql"
	"errors"
	"slices"
	"strconv"
	"strings"

	"hopx/internal/wire"
)

type portSpan struct{ first, last int }

func groupPorts(g wire.DeviceGroup) ([]portSpan, error) {
	if g.PortRanges == "" {
		return []portSpan{{g.FirstPort, g.LastPort}}, nil
	}
	parts := strings.Split(strings.ReplaceAll(g.PortRanges, "，", ","), ",")
	if len(parts) > 128 {
		return nil, errors.New("端口池最多支持 128 个端口或范围")
	}
	spans := make([]portSpan, 0, len(parts))
	for _, part := range parts {
		start, stop, pair := strings.Cut(part, "-")
		first, err := strconv.Atoi(strings.TrimSpace(start))
		last := first
		if pair && err == nil {
			last, err = strconv.Atoi(strings.TrimSpace(stop))
		}
		if err != nil || first < 1 || last < first || last > 65535 {
			return nil, errors.New("端口池格式无效，例如 443,10000-65525")
		}
		spans = append(spans, portSpan{first, last})
	}
	slices.SortFunc(spans, func(a, b portSpan) int { return a.first - b.first })
	merged := spans[:0]
	for _, span := range spans {
		if n := len(merged); n > 0 && span.first <= merged[n-1].last+1 {
			merged[n-1].last = max(merged[n-1].last, span.last)
		} else {
			merged = append(merged, span)
		}
	}
	return merged, nil
}

func selectRulePort(tx *sql.Tx, g wire.DeviceGroup, rule *wire.Rule) error {
	spans, err := groupPorts(g)
	if err != nil {
		return err
	}
	if rule.Port != 0 {
		for _, span := range spans {
			if rule.Port >= span.first && rule.Port <= span.last {
				return nil
			}
		}
		return errors.New("端口不在入口设备组可用范围")
	}
	rows, err := tx.Query("SELECT port FROM rules WHERE entry=? AND id<>? ORDER BY port", g.ID, rule.ID)
	if err != nil {
		return err
	}
	defer rows.Close()
	i, port := 0, spans[0].first
	for rows.Next() {
		var used int
		if err := rows.Scan(&used); err != nil {
			return err
		}
		if used > port {
			break
		}
		if used == port {
			port++
			if port > spans[i].last {
				i++
				if i == len(spans) {
					return errors.New("入口端口池已满")
				}
				port = spans[i].first
			}
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rule.Port = port
	return nil
}
