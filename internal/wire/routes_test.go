package wire

import (
	"reflect"
	"testing"
)

func TestPackRoutesDeduplicatesSeparateSnapshots(t *testing.T) {
	// A delta and the active snapshot can carry separately decoded copies.
	base := [][]Hop{{{Addr: "relay.example:443", Transport: "wss"}}}
	delta := [][]Hop{{{Addr: "relay.example:443", Transport: "wss"}}}
	active := []Forward{{Routes: base}, {Routes: delta, Backup: base}}
	packed, sets := PackRoutes(active)
	if len(sets) != 1 || packed[0].RoutesRef != 1 || packed[1].RoutesRef != 1 || packed[1].BackupRef != 1 {
		t.Fatalf("expected one shared route set: %v, %v", packed, sets)
	}
	if err := ExpandRoutes(packed, sets); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(active, packed) {
		t.Fatalf("round trip: %v, want %v", packed, active)
	}
	packed[0] = Forward{RoutesRef: 2}
	if err := ExpandRoutes(packed, sets); err == nil {
		t.Fatal("invalid route reference was accepted")
	}
}

func TestHopTableDeduplicatesAcrossPaths(t *testing.T) {
	first := Hop{Addr: "first.example:443", Cert: "fixture-cert", Transport: "wss"}
	second := Hop{Addr: "second.example:443", Cert: "fixture-cert-2"}
	rules := []Forward{{Routes: [][]Hop{{first, second}}}, {Routes: [][]Hop{{second}, {first}}}}
	packed, sets := PackRoutes(rules)
	table := IndexHops(sets)
	if len(table.Hops) != 2 {
		t.Fatalf("expected 2 unique endpoints, got %d", len(table.Hops))
	}
	if err := DecodeRoutes(packed, nil, table); err != nil || !reflect.DeepEqual(packed, rules) {
		t.Fatalf("route table round trip: %v, %v", packed, err)
	}
	table.Sets[0][0][0] = 2
	if err := DecodeRoutes(packed, nil, table); err == nil {
		t.Fatal("invalid hop index was accepted")
	}
}
