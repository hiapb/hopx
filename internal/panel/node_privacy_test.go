package panel

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"hopx/internal/wire"
)

func TestPublishedReleaseFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "1.2.3"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"1.2.3/node-arm64", "install-arm64.txt", "database.db"} {
		if err := os.WriteFile(filepath.Join(dir, path), []byte("fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(dir, "database.db"), filepath.Join(dir, "release.pem")); err != nil {
		t.Fatal(err)
	}
	s, err := Open(Options{Database: filepath.Join(t.TempDir(), "hopx.db"), ReleaseDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	handler := s.Handler()
	for path, status := range map[string]int{
		"/releases/1.2.3/node-arm64": 200, "/releases/install-arm64.txt": 200,
		"/releases/": 404, "/releases/1.2.3/": 404, "/releases/database.db": 404, "/releases/release.pem": 404,
	} {
		t.Run(path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
			if rec.Code != status {
				t.Fatalf("status = %d, want %d", rec.Code, status)
			}
		})
	}
}

func TestNodeAddressesAndCredentialsStayScoped(t *testing.T) {
	s, err := Open(Options{Database: filepath.Join(t.TempDir(), "hopx.db"), AdminPassword: "private-fixture"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	err = s.addUser("member", "member-password", false, sql.NullInt64{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.db.Exec(`
		INSERT INTO groups(id,name,kind,first_port,last_port,ratio,user_group,offline_seconds,owner) VALUES
			(1,'site entry','entry',10000,20000,1000,0,30,0),
			(2,'site exit','exit',10000,20000,1000,0,30,0),
			(3,'personal exit','exit',10000,20000,1000,0,30,2);
		INSERT INTO devices(id,group_id,token,registration) VALUES
			(1,1,'one','{"name":"site entry","address":"origin.example","ipv4":"192.0.2.1","reverseAddress":"relay.example:443","reverseToken":"fixture-secret","reverseCertificate":"fixture-cert"}'),
			(2,2,'two','{"name":"site exit","ipv4":"192.0.2.2","relayToken":"fixture-relay-secret"}'),
			(3,3,'three','{"name":"personal exit","ipv4":"192.0.2.3"}');
		INSERT INTO rules(id,owner,entry,port,json) VALUES
			(1,1,1,10001,'{"enabled":true,"path":[2],"targets":["backend.example:443"]}');
	`)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	s.listNodes(rec, httptest.NewRequest(http.MethodGet, "/api/nodes", nil), User{ID: 2})
	body := rec.Body.String()
	if rec.Code != 200 || !strings.Contains(body, "192.0.2.3") {
		t.Fatal("personal node should remain visible to its owner")
	}
	for _, forbidden := range []string{"origin.example", "192.0.2.1", "192.0.2.2", "relay.example", "fixture-secret", "fixture-relay-secret"} {
		if strings.Contains(body, forbidden) {
			t.Fatal("site node exposed a hidden address or credential")
		}
	}
	rec = httptest.NewRecorder()
	s.listNodes(rec, httptest.NewRequest(http.MethodGet, "/api/nodes", nil), User{ID: 1, Admin: true})
	if strings.Contains(rec.Body.String(), "fixture-secret") || !strings.Contains(rec.Body.String(), "192.0.2.2") {
		t.Fatal("administrator should see display addresses only")
	}
	if endpoints, err := s.reverseEndpoints(2, "egress-a"); err != nil || len(endpoints) != 0 {
		t.Fatalf("unexpected reverse authorizations: count %d, error %v", len(endpoints), err)
	}
	if _, err = s.db.Exec("UPDATE groups SET reverse_groups='[2]' WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	s.invalidateReverseRoutes("PUT /api/admin/groups/{id}")
	if endpoints, err := s.reverseEndpoints(2, "egress-a"); err != nil || len(endpoints) != 1 {
		t.Fatalf("missing configured reverse authorization: count %d, error %v", len(endpoints), err)
	}
	s.devices[1] = wire.Device{AcceptScopedReverse: true}
	s.invalidateReverseRoutes("PUT /api/admin/groups/{id}")
	first, err := s.reverseEndpoints(2, "egress-a")
	if err != nil || len(first) != 1 || first[0].Token != wire.ReverseCredential("fixture-secret", "egress-a") {
		t.Fatalf("scoped reverse credential missing, error %v", err)
	}
	second, err := s.reverseEndpoints(2, "egress-b")
	if err != nil || len(second) != 1 || second[0].Token == first[0].Token {
		t.Fatalf("reverse credentials should differ between egresses, error %v", err)
	}
	if endpoints, err := s.reverseEndpoints(3, "egress-b"); err != nil || len(endpoints) != 0 {
		t.Fatalf("personal node received an unconfigured reverse authorization: count %d, error %v", len(endpoints), err)
	}
}

func TestRoutingOnlyUsesConfiguredReverseNodes(t *testing.T) {
	source := wire.DeviceGroup{ID: 1}
	groups := map[int64]wire.DeviceGroup{2: {ID: 2}}
	available := map[int64][]wire.Device{
		2: {{Registration: wire.Registration{ReverseID: "reverse"}}, {Registration: wire.Registration{RelayAddress: "relay.example:443"}}},
	}
	s := &Server{}
	for _, reverse := range []bool{false, true} {
		if reverse {
			source.ReverseGroups = []int64{2}
		}
		routes := s.routes([]int64{2}, source, groups, available)
		if len(routes) != 1 || (routes[0][0].ReverseID != "") != reverse {
			t.Fatalf("wrong route selection for reverse=%v", reverse)
		}
	}
}

func TestPersonalExitCanOnlyTerminateTheRoute(t *testing.T) {
	entry := wire.DeviceGroup{ID: 1, Kind: "entry"}
	lookup := func(id int64) (wire.DeviceGroup, error) {
		group := wire.DeviceGroup{ID: id, Kind: "exit"}
		if id == 2 {
			group.Owner = 1
		}
		return group, nil
	}
	user := User{ID: 1}
	if _, _, err := resolvePath(user, entry, []int64{2, 3}, lookup); err == nil {
		t.Fatal("user-managed exit was allowed to relay another site's connection")
	}
	if _, _, err := resolvePath(user, entry, []int64{3, 2}, lookup); err != nil {
		t.Fatal(err)
	}
}

func TestSharedTargetPolicyPreservesTrustedPaths(t *testing.T) {
	s, err := Open(Options{Database: filepath.Join(t.TempDir(), "hopx.db"), AdminPassword: "private-fixture"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.addUser("member", "member-password", false, sql.NullInt64{}); err != nil {
		t.Fatal(err)
	}
	_, err = s.db.Exec(`
		UPDATE users SET expires=unixepoch()+86400 WHERE id=2;
		INSERT INTO groups(id,name,kind,first_port,last_port,ratio,user_group,offline_seconds,owner) VALUES
			(1,'site entry','entry',10000,20000,1000,0,30,0),
			(2,'site exit','exit',10000,20000,1000,0,30,0),
			(3,'personal exit','exit',10000,20000,1000,0,30,2);
		INSERT INTO rules(id,owner,entry,port,json) VALUES
			(1,2,1,10001,'{"enabled":true,"path":[2],"backupPath":[3],"targets":["localhost:443"]}'),
			(2,2,1,10002,'{"enabled":true,"targets":["8.8.8.8:443"]}'),
			(3,1,1,10003,'{"enabled":true,"targets":["localhost:443"]}');
	`)
	if err != nil {
		t.Fatal(err)
	}
	config, err := s.compileGroup(1)
	if err != nil || len(config.Rules) != 3 {
		t.Fatalf("load target policy: %d rules (%v)", len(config.Rules), err)
	}
	hosted, literal, admin := config.Rules[0], config.Rules[1], config.Rules[2]
	if !hosted.PublicTargets || hosted.PublicBackupTargets || !requiresPublicTargetPolicy(hosted) ||
		!literal.PublicTargets || requiresPublicTargetPolicy(literal) || admin.PublicTargets {
		t.Fatal("incorrect public target policy by user and route")
	}
	if _, err = s.db.Exec(`UPDATE groups SET routing='{"allowPrivateTargets":true}' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	config, err = s.compileGroup(1)
	if err != nil || len(config.Rules) != 3 || config.Rules[0].PublicTargets {
		t.Fatalf("trusted private forwarding is unavailable (%v)", err)
	}
}
