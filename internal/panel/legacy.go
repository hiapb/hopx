package panel

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
)

func openLegacy(path string) (*sql.DB, error) {
	full, e := filepath.Abs(path)
	if e != nil {
		return nil, e
	}
	u := url.URL{Scheme: "file", Path: full}
	options := u.Query()
	options.Set("mode", "ro")
	options.Set("_pragma", "query_only(1)")
	u.RawQuery = options.Encode()
	db, e := sql.Open("sqlite", u.String())
	if e != nil {
		return nil, e
	}
	db.SetMaxOpenConns(1)
	if e = db.Ping(); e != nil {
		db.Close()
		return nil, e
	}
	return db, nil
}

type legacyTable struct {
	Name string `json:"name"`
	SQL  string `json:"sql"`
}

// LegacySchema reads DDL only. It does not enumerate record values.
func LegacySchema(path string) ([]legacyTable, error) {
	db, e := openLegacy(path)
	if e != nil {
		return nil, e
	}
	defer db.Close()
	rows, e := db.Query("SELECT name,sql FROM sqlite_schema WHERE type IN ('table','index','view') AND sql IS NOT NULL AND name NOT LIKE 'sqlite_%' ORDER BY type,name")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	list := []legacyTable{}
	for rows.Next() {
		var table legacyTable
		if e = rows.Scan(&table.Name, &table.SQL); e != nil {
			return nil, e
		}
		list = append(list, table)
	}
	return list, rows.Err()
}

func CheckDatabase(path string) error {
	db, e := openLegacy(path)
	if e != nil {
		return e
	}
	defer db.Close()
	var health string
	if e = db.QueryRow("PRAGMA quick_check").Scan(&health); e != nil {
		return e
	}
	if health != "ok" {
		return fmt.Errorf("数据库检查失败: %s", health)
	}
	var invalid bool
	if e = db.QueryRow("SELECT EXISTS(SELECT 1 FROM pragma_foreign_key_check)").Scan(&invalid); e != nil {
		return e
	}
	if invalid {
		return errors.New("数据库存在无效关联")
	}
	return nil
}

type legacyMapping struct {
	Source  string            `json:"source"`
	Queries map[string]string `json:"queries"`
}

// ImportLegacy maps versioned SELECT results to the same audited import path as
// a normalized JSON snapshot. Both dry runs and imports open the source read-only.
func (s *Server) ImportLegacy(path string, mapping io.Reader, dryRun bool) (MigrationResult, error) {
	var result MigrationResult
	var spec legacyMapping
	if err := json.NewDecoder(io.LimitReader(mapping, 2<<20)).Decode(&spec); err != nil {
		return result, err
	}
	if spec.Source == "" || len(spec.Queries) == 0 {
		return result, errors.New("缺少来源标识或字段映射")
	}
	db, err := openLegacy(path)
	if err != nil {
		return result, err
	}
	defer db.Close()
	tx, err := db.Begin()
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	tables := []string{"userGroups", "users", "deviceGroups", "devices", "rules", "plans", "orders", "vouchers", "notifications"}
	records := map[string]any{"format": 1, "source": spec.Source}
	for table, query := range spec.Queries {
		if !slices.Contains(tables, table) || !strings.HasPrefix(strings.ToLower(strings.TrimSpace(query)), "select ") {
			return result, fmt.Errorf("%s 必须提供 SELECT 映射", table)
		}
		rows, e := tx.Query(query)
		if e != nil {
			return result, fmt.Errorf("%s 映射: %w", table, e)
		}
		data, e := mappedRows(rows)
		rows.Close()
		if e != nil {
			return result, fmt.Errorf("%s 映射: %w", table, e)
		}
		records[table] = data
	}
	payload, e := json.Marshal(records)
	if e != nil {
		return result, e
	}
	return s.Import(bytes.NewReader(payload), dryRun)
}

func mappedRows(rows *sql.Rows) ([]map[string]any, error) {
	fields, e := rows.Columns()
	if e != nil {
		return nil, e
	}
	result := []map[string]any{}
	values := make([]any, len(fields))
	pointers := make([]any, len(fields))
	for i := range fields {
		pointers[i] = &values[i]
	}
	for rows.Next() {
		if e = rows.Scan(pointers...); e != nil {
			return nil, e
		}
		record := make(map[string]any, len(fields))
		for i, name := range fields {
			v := values[i]
			if data, ok := v.([]byte); ok {
				v = string(data)
			}
			switch name {
			case "admin", "banned", "autoRenew", "enabled", "proxyIn", "proxyOut":
				if n, ok := v.(int64); ok {
					v = n != 0
				}
			case "targets", "path", "backupPath", "allowedFrom", "allowedTo":
				if value, ok := v.(string); ok {
					raw := []byte(value)
					if !json.Valid(raw) {
						return nil, fmt.Errorf("字段 %s 的值需要用 JSON 数组表示", name)
					}
					v = json.RawMessage(raw)
				}
			}
			record[name] = v
		}
		result = append(result, record)
	}
	return result, rows.Err()
}
