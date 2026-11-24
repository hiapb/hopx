package panel

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"hopx/internal/wire"
)

func (s *Server) canSwitchHAProxy(tx *sql.Tx, group int64, useProxy bool) (bool, error) {
	now := time.Now()
	rows, err := tx.Query(`SELECT id FROM devices WHERE group_id=? AND token NOT LIKE 'revoked:%' AND last_seen>=?`,
		group, now.Add(-time.Hour).Unix())
	if err != nil {
		return false, err
	}
	defer rows.Close()
	s.mu.RLock()
	defer s.mu.RUnlock()
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return false, err
		}
		node := s.devices[id]
		if !node.AcceptHAProxyHandoff || useProxy && !node.AcceptHAProxy {
			return false, nil
		}
	}
	return true, rows.Err()
}

func validateHAProxyRule(owner User, entry wire.DeviceGroup, rule wire.Rule) error {
	if !owner.Admin {
		return errors.New("HAProxy 模式仅支持管理员名下的规则")
	}
	if rule.Protocol == "haproxy-tcp" && len(rule.Path)+len(rule.BackupPath) != 0 {
		return errors.New("纯 HAProxy TCP 需直连目标")
	}
	if entry.Routing.IngressMode == "relay" || entry.Routing.IngressMode == "personal" {
		return errors.New("此入口要求所有流量经过出口，请选择内置转发")
	}
	if entry.Ingress.InspectsTCP() || rule.UsesSharedTLS() ||
		rule.TLSCert != "" || rule.HasTLSPolicy() || rule.ProxyIn || rule.ProxyOut ||
		rule.RateMbps > 0 || rule.MaxIPs > 0 || rule.MaxConns > 0 {
		return errors.New("TLS 策略、Proxy Protocol 和规则限额请选择内置转发")
	}
	if rule.Protocol == "haproxy-both" && entry.Ingress.BlocksUDP() {
		return errors.New("该入口设备组禁止 UDP，不能使用 HAProxy TCP + UDP")
	}
	for _, target := range rule.Targets {
		if !proxyEndpoint(target) {
			return errors.New("HAProxy 目标须为标准域名或 IP 加端口")
		}
	}
	return nil
}

func proxyEndpoint(value string) bool {
	host, port, err := net.SplitHostPort(value)
	number, portErr := strconv.Atoi(port)
	if err != nil || portErr != nil || number < 1 || number > 65535 || port != strconv.Itoa(number) || host == "" || len(host) > 253 {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	for _, char := range strings.ToLower(host) {
		if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' && char != '.' {
			return false
		}
	}
	return true
}

func (s *Server) haProxyConfig(w http.ResponseWriter, r *http.Request, _ User) {
	var input struct {
		Bind     string
		Backends []string
	}
	if !decode(w, r, &input) {
		return
	}
	if !proxyEndpoint(input.Bind) || len(input.Backends) == 0 || len(input.Backends) > 64 {
		fail(w, 400, "请输入监听地址及 1 至 64 个入口节点地址")
		return
	}
	for _, address := range input.Backends {
		if !proxyEndpoint(address) {
			fail(w, 400, "入口节点地址须为 host:port")
			return
		}
	}
	id := pathID(r)
	var raw string
	if err := s.db.QueryRow("SELECT json FROM rules WHERE id=?", id).Scan(&raw); err != nil {
		fail(w, 404, "转发规则不存在")
		return
	}
	var rule wire.Rule
	if json.Unmarshal([]byte(raw), &rule) != nil {
		fail(w, 400, "转发规则配置无效")
		return
	}
	group, err := scanGroup(s.db.QueryRow(groupSelect+" WHERE id=?", rule.Entry))
	if err != nil || group.RuleNetwork(rule) == "udp" {
		fail(w, 400, "HAProxy 配置需要 TCP 入口")
		return
	}
	bind := input.Bind
	if rule.TLSSharedPort > 0 {
		var parent string
		if err = s.db.QueryRow("SELECT json FROM rules WHERE entry=? AND port=?", rule.Entry, rule.TLSSharedPort).Scan(&parent); err != nil || json.Unmarshal([]byte(parent), &rule) != nil {
			fail(w, 400, "共享 TLS 入口不存在")
			return
		}
	}
	sendProxy := ""
	if rule.ProxyIn {
		sendProxy = " send-proxy"
		if rule.ProxyInVersion == 2 {
			sendProxy = " send-proxy-v2"
		}
	}
	var config strings.Builder
	fmt.Fprintf(&config, "defaults\n    mode tcp\n    timeout connect 5s\n    timeout client 5m\n    timeout server 5m\n\nfrontend hopx_%d\n    bind %s\n    default_backend hopx_%d_nodes\n\nbackend hopx_%d_nodes\n    balance leastconn\n    default-server inter 3s fall 3 rise 2\n", id, bind, id, id)
	for i, endpoint := range input.Backends {
		fmt.Fprintf(&config, "    server node_%d %s check%s\n", i+1, endpoint, sendProxy)
	}
	respond(w, 200, map[string]string{"config": config.String()})
}
