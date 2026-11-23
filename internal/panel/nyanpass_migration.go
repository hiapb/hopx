package panel

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
)

var errMigrationTarget = errors.New("正式导入需要只含初始管理员的 HopX 实例")

type migrationIssue struct {
	ID     int64  `json:"id"`
	Reason string `json:"reason"`
}

type migrationDetails struct {
	MigrationResult
	Rules   []migrationIssue `json:"rulesToReview"`
	Orders  []int64          `json:"ordersToReview"`
	Devices []sourceDevice   `json:"devicesToEnroll"`
}

func migrationTarget(tx *sql.Tx, adminID int64) error {
	var clean bool
	err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM users WHERE id=? AND admin=1 AND banned=0 AND
		balance=0 AND affiliate_balance=0 AND used=0 AND plan_id=0 AND quota=0)
		AND (SELECT count(*) FROM users)=1
		AND NOT EXISTS(SELECT 1 FROM groups UNION ALL SELECT 1 FROM plans UNION ALL SELECT 1 FROM orders
			UNION ALL SELECT 1 FROM redeem UNION ALL SELECT 1 FROM notifications UNION ALL SELECT 1 FROM migrations
			UNION ALL SELECT 1 FROM user_groups WHERE id<>0 UNION ALL SELECT 1 FROM telegram_links)`, adminID).Scan(&clean)
	if err == nil && !clean {
		return errMigrationTarget
	}
	return err
}

func keepMigrationAdmin(in *snapshot, name, hash string, report *MigrationResult) (int64, error) {
	for i, user := range in.Users {
		if !strings.EqualFold(user.Name, name) {
			continue
		}
		if !user.Admin || user.Banned {
			return 0, errors.New("HopX 初始管理员与源库普通或停用账号重名")
		}
		in.Users = slices.Clone(in.Users)
		if user.ResetRequired {
			report.PasswordResets--
		}
		in.Users[i].ResetRequired = false
		in.Users[i].PasswordHash = hash
		return user.ID, nil
	}
	return 0, nil
}

func readOnlineNyanpass(ctx context.Context, cfg *mysql.Config) (snapshot, error) {
	connector, err := mysql.NewConnector(cfg)
	if err != nil {
		return snapshot{}, errors.New("MySQL 连接设置无效")
	}
	db := sql.OpenDB(connector)
	defer db.Close()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return snapshot{}, errors.New("无法打开只读 MySQL 事务，请检查地址、凭据与 TLS 设置")
	}
	defer tx.Rollback()
	data, err := readNyanpass(tx)
	if err != nil {
		return snapshot{}, errors.New("读取源库失败，请检查 SELECT 权限和 nyanpass 20261022 数据库结构")
	}
	return data, nil
}

// MigrateNyanpass imports a read-only MySQL snapshot into a freshly installed panel,
// preserving the local administrator's credentials.
func (s *Server) MigrateNyanpass(ctx context.Context, address, database, username, password, adminName string, tls bool) (migrationDetails, error) {
	var report migrationDetails
	address = strings.TrimSpace(address)
	if host := strings.Trim(address, "[]"); net.ParseIP(host) != nil {
		address = net.JoinHostPort(host, "3306")
	} else if address != "" && !strings.Contains(address, ":") {
		address = net.JoinHostPort(address, "3306")
	}
	if !proxyEndpoint(address) || strings.TrimSpace(username) == "" || strings.TrimSpace(database) == "" {
		return report, errors.New("请输入服务器地址、数据库名和用户名")
	}
	cfg := mysql.NewConfig()
	cfg.Net, cfg.Addr, cfg.DBName = "tcp", address, database
	cfg.User, cfg.Passwd = username, password
	cfg.Timeout, cfg.ReadTimeout, cfg.WriteTimeout = 5*time.Second, 30*time.Second, 5*time.Second
	if tls {
		cfg.TLSConfig = "true"
	}

	var admin User
	var hash string
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return report, err
	}
	defer tx.Rollback()
	if err := scanUser(tx.QueryRowContext(ctx, userSelect+" WHERE name=?", adminName), &admin); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return report, errMigrationTarget
		}
		return report, err
	}
	if err := migrationTarget(tx, admin.ID); err != nil {
		return report, err
	}
	if err := tx.QueryRowContext(ctx, "SELECT password FROM users WHERE id=?", admin.ID).Scan(&hash); err != nil {
		return report, err
	}
	in, err := readOnlineNyanpass(ctx, cfg)
	if err != nil {
		return report, err
	}
	raw, err := json.Marshal(in)
	if err != nil {
		return report, err
	}
	report.MigrationResult = summarizeSnapshot(in)
	adminID, err := keepMigrationAdmin(&in, admin.Name, hash, &report.MigrationResult)
	if err != nil {
		return report, err
	}
	if _, err = tx.Exec("DELETE FROM users WHERE id=?", admin.ID); err != nil {
		return report, err
	}
	if _, err = tx.Exec("INSERT INTO migrations(source,checksum) VALUES(?,?)", in.Source, digest(string(raw))); err != nil {
		return report, err
	}
	if err = applySnapshot(tx, in, "", "", &report.MigrationResult); err != nil {
		return report, err
	}
	if adminID == 0 {
		if _, err = tx.Exec("INSERT INTO users(name,password,admin,invite) VALUES(?,?,1,?)", admin.Name, []byte(hash), token()[:16]); err != nil {
			return report, err
		}
	}
	report.Rules, err = queryLegacy(tx, "SELECT rule_id,reason FROM migration_rule_issues WHERE source=? ORDER BY rule_id", func(row scanner) (issue migrationIssue, err error) {
		err = row.Scan(&issue.ID, &issue.Reason)
		return
	}, in.Source)
	if err != nil {
		return report, err
	}
	report.Orders, err = queryLegacy(tx, "SELECT order_id FROM migration_order_issues WHERE source=? ORDER BY order_id", func(row scanner) (id int64, err error) {
		err = row.Scan(&id)
		return
	}, in.Source)
	if err != nil {
		return report, err
	}
	report.Devices, err = queryLegacy(tx, "SELECT id,group_id,name,address FROM migration_devices WHERE source=? ORDER BY id", func(row scanner) (device sourceDevice, err error) {
		err = row.Scan(&device.ID, &device.GroupID, &device.Name, &device.Address)
		return
	}, in.Source)
	if err != nil {
		return report, err
	}
	raw, err = json.Marshal(report.MigrationResult)
	if err != nil {
		return report, err
	}
	if _, err = tx.Exec("INSERT INTO migration_reports(source,report) VALUES(?,?)", in.Source, raw); err != nil {
		return report, err
	}
	return report, tx.Commit()
}
