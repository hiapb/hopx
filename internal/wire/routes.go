package wire

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"slices"
)

type HopTable struct {
	Hops []Hop     `json:"hops"`
	Sets [][][]int `json:"sets"`
}

// IndexHops stores each endpoint once across all candidate paths.
func IndexHops(sets [][][]Hop) *HopTable {
	if len(sets) == 0 {
		return nil
	}
	table := &HopTable{Sets: make([][][]int, len(sets))}
	byEndpoint := make(map[Hop]int)
	for i, routes := range sets {
		table.Sets[i] = make([][]int, len(routes))
		for j, route := range routes {
			indices := make([]int, 0, len(route))
			for _, hop := range route {
				index, exists := byEndpoint[hop]
				if !exists {
					index = len(table.Hops)
					byEndpoint[hop] = index
					table.Hops = append(table.Hops, hop)
				}
				indices = append(indices, index)
			}
			table.Sets[i][j] = indices
		}
	}
	return table
}

func (table *HopTable) expand() ([][][]Hop, error) {
	sets := make([][][]Hop, len(table.Sets))
	for i, routes := range table.Sets {
		if len(routes) == 0 || len(routes) > 16 {
			return nil, errors.New("invalid route count")
		}
		sets[i] = make([][]Hop, len(routes))
		for j, indices := range routes {
			if len(indices) == 0 || len(indices) > 8 {
				return nil, errors.New("invalid hop count")
			}
			hops := make([]Hop, len(indices))
			for k, index := range indices {
				if index < 0 || index >= len(table.Hops) {
					return nil, errors.New("invalid hop index")
				}
				hops[k] = table.Hops[index]
			}
			sets[i][j] = hops
		}
	}
	return sets, nil
}

func DecodeRoutes(rules []Forward, sets [][][]Hop, table *HopTable) error {
	if table != nil {
		if len(sets) != 0 {
			return errors.New("ambiguous route representation")
		}
		var err error
		sets, err = table.expand()
		if err != nil {
			return err
		}
	}
	return ExpandRoutes(rules, sets)
}

// PackRoutes replaces shared route slices with one-based references.
func PackRoutes(rules []Forward) ([]Forward, [][][]Hop) {
	var sets [][][]Hop
	type routeKey struct {
		first *[]Hop
		count int
	}
	bySlice := make(map[routeKey]int)
	byContent := make(map[[32]byte]int)
	ref := func(routes [][]Hop) int {
		if len(routes) == 0 {
			return 0
		}
		key := routeKey{first: &routes[0], count: len(routes)}
		if id := bySlice[key]; id != 0 {
			return id
		}
		raw, _ := json.Marshal(routes)
		sum := sha256.Sum256(raw)
		id := byContent[sum]
		if id == 0 {
			sets = append(sets, routes)
			id = len(sets)
			byContent[sum] = id
		}
		bySlice[key] = id
		return id
	}
	packed := slices.Clone(rules)
	for i := range packed {
		r := &packed[i]
		r.RoutesRef, r.BackupRef = ref(r.Routes), ref(r.Backup)
		r.Routes, r.Backup = nil, nil
	}
	return packed, sets
}

// ExpandRoutes assigns the shared slices to rules before applying the configuration.
func ExpandRoutes(rules []Forward, sets [][][]Hop) error {
	resolve := func(id int, inline [][]Hop) ([][]Hop, error) {
		if id == 0 {
			return inline, nil
		}
		if id < 0 || id > len(sets) || len(inline) > 0 || len(sets[id-1]) == 0 {
			return nil, errors.New("invalid route reference")
		}
		return sets[id-1], nil
	}
	for i := range rules {
		r := &rules[i]
		primary, err := resolve(r.RoutesRef, r.Routes)
		if err != nil {
			return err
		}
		backup, err := resolve(r.BackupRef, r.Backup)
		if err != nil {
			return err
		}
		r.Routes, r.Backup = primary, backup
		r.RoutesRef, r.BackupRef = 0, 0
	}
	return nil
}
