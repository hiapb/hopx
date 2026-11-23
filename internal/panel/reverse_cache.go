package panel

import (
	"slices"
	"time"

	"hopx/internal/wire"
)

func reverseEnabled(entry wire.DeviceGroup, group int64) bool {
	return slices.Contains(entry.ReverseGroups, 0) != slices.Contains(entry.ReverseGroups, group)
}

type reverseRoute struct {
	wire.ReverseEndpoint
	scoped bool
}

func (s *Server) reverseEndpoints(group int64, egressID string) ([]wire.ReverseEndpoint, error) {
	routes, err := s.reverseRouteSnapshot(group)
	if err != nil {
		return nil, err
	}
	endpoints := make([]wire.ReverseEndpoint, 0, len(routes))
	for _, route := range routes {
		endpoint := route.ReverseEndpoint
		if route.scoped {
			endpoint.Token = wire.ReverseCredential(endpoint.Token, egressID)
		}
		endpoints = append(endpoints, endpoint)
	}
	return endpoints, nil
}

func (s *Server) reverseRouteSnapshot(group int64) ([]reverseRoute, error) {
	s.reverseMu.Lock()
	defer s.reverseMu.Unlock()
	if s.reverseRoutes != nil && time.Now().Before(s.reverseRoutesUntil) {
		return s.reverseRoutes[group], nil
	}
	groups, err := s.groups()
	if err != nil {
		return nil, err
	}
	byID := make(map[int64]wire.DeviceGroup, len(groups))
	for _, g := range groups {
		byID[g.ID] = g
	}
	rows, err := s.db.Query(`WITH links AS (
		SELECT r.entry, json_extract(r.json,'$.path[0]') AS egress,
			coalesce(json_array_length(r.json,'$.path'),0) AS hops, r.owner
		FROM rules r WHERE json_extract(r.json,'$.enabled')=1
		UNION ALL
		SELECT r.entry, json_extract(r.json,'$.backupPath[0]'),
			coalesce(json_array_length(r.json,'$.backupPath'),0), r.owner
		FROM rules r WHERE json_extract(r.json,'$.enabled')=1
		UNION ALL
		SELECT r.entry, g.fallback_group, 1, r.owner
		FROM rules r JOIN groups g ON g.id=json_extract(r.json,'$.path[0]')
		WHERE json_extract(r.json,'$.enabled')=1 AND json_array_length(r.json,'$.path')=1
			AND coalesce(json_array_length(r.json,'$.backupPath'),0)=0 AND g.fallback_group>0
	)
	SELECT DISTINCT links.entry, links.egress, links.hops, u.id, u.admin, u.group_id
	FROM links JOIN users u ON u.id=links.owner
	WHERE links.hops>0 AND u.banned=0 AND (u.admin=1 OR (u.expires>unixepoch() AND (u.quota=0 OR u.used<u.quota)))`)
	if err != nil {
		return nil, err
	}
	relays := make(map[int64]map[int64]bool)
	for rows.Next() {
		var selected, entry int64
		var hops int
		var owner User
		if err = rows.Scan(&entry, &selected, &hops, &owner.ID, &owner.Admin, &owner.Group); err != nil {
			rows.Close()
			return nil, err
		}
		source, destination := byID[entry], byID[selected]
		if source.ID == 0 || destination.ID == 0 || (source.Kind != "entry" && source.Kind != "both") ||
			!canUse(owner, source) || !canUse(owner, destination) || !allowsLink(source, destination) ||
			source.Routing.IngressMode == "direct" {
			continue
		}
		if destination.Owner != 0 && hops != 1 {
			continue
		}
		if source.Routing.IngressMode == "personal" && (hops != 1 || destination.Owner != owner.ID) {
			continue
		}
		relay := destination.ID
		if destination.Kind == "chain" {
			if hops != 1 || len(destination.Chain) == 0 {
				continue
			}
			relay = destination.Chain[0]
		}
		if !reverseEnabled(source, relay) {
			continue
		}
		if relays[entry] == nil {
			relays[entry] = make(map[int64]bool)
		}
		relays[entry][relay] = true
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	devices, err := s.deviceSnapshot(false)
	if err != nil {
		return nil, err
	}
	index := make(map[int64][]reverseRoute)
	for _, device := range devices {
		if device.Revoked || device.ReverseAddress == "" {
			continue
		}
		for relay := range relays[device.GroupID] {
			if !slices.ContainsFunc(index[relay], func(endpoint reverseRoute) bool { return endpoint.Address == device.ReverseAddress }) {
				index[relay] = append(index[relay], reverseRoute{
					ReverseEndpoint: wire.ReverseEndpoint{Address: device.ReverseAddress, Token: device.ReverseToken, Certificate: device.ReverseCertificate},
					scoped:          device.AcceptScopedReverse,
				})
			}
		}
	}
	s.reverseRoutes = index
	s.reverseRoutesUntil = time.Now().Add(10 * time.Second)
	return index[group], nil
}

func (s *Server) invalidateReverseRoutes(pattern string) {
	switch pattern {
	case "POST /api/node/register", "DELETE /api/nodes/{id}", "DELETE /api/admin/nodes/{id}",
		"POST /api/rules", "PUT /api/rules/{id}", "DELETE /api/rules/{id}", "POST /api/rules/batch",
		"POST /api/rules/batch/by-port", "POST /api/groups/{id}/operations", "POST /api/admin/groups",
		"PUT /api/admin/groups/{id}", "DELETE /api/admin/groups/{id}", "DELETE /api/tunnels/{id}",
		"PUT /api/tunnels/{id}", "POST /api/tunnels", "POST /api/admin/rules/cleanup", "DELETE /api/admin/users/{id}",
		"POST /api/admin/users/cleanup", "PUT /api/admin/users/{id}", "PUT /api/admin/users/{id}/plan":
		s.reverseMu.Lock()
		s.reverseRoutes = nil
		s.reverseMu.Unlock()
	}
}
