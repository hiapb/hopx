package panel

import (
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"hopx/internal/wire"
)

func authorizeTLSNames(parent, child wire.Rule, admin bool) bool {
	if !admin && parent.Owner != child.Owner {
		all := slices.Contains(parent.TLSAllowedUsers, 0)
		listed := slices.Contains(parent.TLSAllowedUsers, child.Owner)
		if all == listed {
			return false
		}
	}
	return len(child.TLSServerNames) > 0 && !slices.ContainsFunc(child.TLSServerNames, func(name string) bool {
		return len(parent.TLSAllowedNames) > 0 && !slices.ContainsFunc(parent.TLSAllowedNames, func(allowed string) bool {
			return name == allowed || (strings.HasPrefix(allowed, ".") && strings.HasSuffix(name, allowed))
		})
	})
}

func validateSharedTLS(tx *sql.Tx, user User, rule *wire.Rule) error {
	if !rule.UsesSharedTLS() {
		rule.TLSAllowedNames, rule.TLSAllowedUsers = nil, nil
		return nil
	}
	if rule.TLSShared {
		if !user.Admin || rule.TLSCert == "" || rule.TLSSharedPort != 0 || rule.Port == 0 ||
			len(rule.Path) != 0 || len(rule.BackupPath) != 0 || len(rule.TLSServerNames) != 0 ||
			len(rule.TLSALPN) != 0 || rule.TLSRequireEmpty || rule.TLSOrigin != 0 || rule.ProxyOut {
			return errors.New("共享 TLS 入口由管理员指定固定端口与证书")
		}
		if len(rule.TLSAllowedNames) > 128 {
			return errors.New("共享 TLS 入口最多允许 128 项域名")
		}
		if len(rule.TLSAllowedUsers) > 1024 || slices.ContainsFunc(rule.TLSAllowedUsers, func(id int64) bool { return id < 0 }) {
			return errors.New("共享 TLS 入口的授权用户无效")
		}
		for i, name := range rule.TLSAllowedNames {
			name = strings.ToLower(strings.TrimSpace(name))
			if name == "" || name == "." || len(name) > 253 || strings.ContainsAny(name, " *,/\\\t\r\n") {
				return errors.New("共享 TLS 入口的授权域名无效")
			}
			rule.TLSAllowedNames[i] = name
		}
		return nil
	}
	rule.TLSAllowedNames, rule.TLSAllowedUsers = nil, nil
	if rule.TLSSharedPort < 1 || rule.TLSSharedPort > 65535 || rule.TLSSharedPort == rule.Port ||
		rule.TLSRequireEmpty || rule.ProxyIn || len(rule.TLSServerNames) == 0 {
		return errors.New("SNI 子规则需要共享端口和有效域名")
	}
	var raw string
	if err := tx.QueryRow("SELECT json FROM rules WHERE entry=? AND port=? AND id<>?", rule.Entry, rule.TLSSharedPort, rule.ID).Scan(&raw); err != nil {
		return errors.New("该入口的共享 TLS 端口不存在")
	}
	var parent wire.Rule
	if json.Unmarshal([]byte(raw), &parent) != nil || !parent.TLSShared || !authorizeTLSNames(parent, *rule, user.Admin) {
		return errors.New("共享 TLS 入口未授权这些域名")
	}
	for _, name := range rule.TLSServerNames {
		var exists bool
		err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM rules r, json_each(r.json, '$.tlsServerNames') n
			WHERE r.entry=? AND json_extract(r.json,'$.tlsSharedPort')=? AND n.value=? AND r.id<>?)`,
			rule.Entry, rule.TLSSharedPort, name, rule.ID).Scan(&exists)
		if err != nil {
			return err
		}
		if exists {
			return errors.New("该共享端口已有相同 SNI 的规则")
		}
	}
	return nil
}
