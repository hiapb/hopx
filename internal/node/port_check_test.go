package node

import (
	"context"
	"net"
	"strconv"
	"testing"

	"hopx/internal/wire"
)

func TestPortCheckReportsOccupiedAddress(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	engine := NewEngine("127.0.0.1", 16, 16)
	defer engine.Close()
	result := engine.checkPort(context.Background(), wire.DiagnosticTask{
		ID: "port-check",
		PortCheck: &wire.PortCheck{
			Port:    port,
			Network: "tcp",
		},
	})
	if len(result.Bindings) != 1 {
		t.Fatalf("expected configured address, got %+v", result.Bindings)
	}
	if result.Bindings[0].Status != "occupied" {
		t.Fatalf("address-specific port check: %+v", result.Bindings)
	}
	_ = probe.Close()
}

func TestPortCheckRecognizesListenerOwnedByThisRule(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	engine := NewEngine("127.0.0.1", 16, 16)
	defer engine.Close()
	ruleID := int64(42)
	if err = engine.Apply(context.Background(), wire.Config{Revision: "one", Rules: []wire.Forward{{
		Rule: wire.Rule{ID: ruleID, Name: "current", Port: port, Enabled: true, Protocol: "tcp", Targets: []string{"127.0.0.1:1"}},
	}}}, nil); err != nil {
		t.Fatal(err)
	}
	result := engine.checkPort(context.Background(), wire.DiagnosticTask{
		ID: "port-check",
		PortCheck: &wire.PortCheck{
			Port:    port,
			Network: "both",
		},
		RuleID: ruleID,
	})
	want := []string{"in_use_by_rule", "available"}
	if len(result.Bindings) != len(want) {
		t.Fatalf("expected TCP and UDP checks, got %+v", result.Bindings)
	}
	for index := range want {
		if result.Bindings[index].Status != want[index] || result.Bindings[index].Address != net.JoinHostPort("127.0.0.1", strconv.Itoa(port)) {
			t.Fatalf("unexpected binding at %d: %+v", index, result.Bindings[index])
		}
	}
}
