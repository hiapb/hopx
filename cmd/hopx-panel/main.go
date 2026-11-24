package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"hopx/internal/panel"
	"hopx/web"
)

var version = "dev"

func main() {
	addr := flag.String("listen", env("HOPX_LISTEN", ":38471"), "HTTP listen address")
	database := flag.String("db", env("HOPX_DB", "data/hopx.db"), "SQLite database")
	backup := flag.String("backup", "", "write a consistent SQLite backup and exit")
	check := flag.String("check-db", "", "check a database file without modifying it")
	showVersion := flag.Bool("version", false, "print version")
	initAdmin := flag.Bool("init-admin", false, "initialize the administrator with a password read from stdin")
	snapshot := flag.String("import-snapshot", "", "import a normalized migration snapshot")
	preview := flag.Bool("dry-run", false, "validate without committing a migration snapshot")
	legacy := flag.String("legacy-db", "", "read-only source SQLite database")
	legacyMySQL := flag.Bool("legacy-mysql", false, "import from a read-only MySQL source configured with HOPX_LEGACY_MYSQL_DSN")
	migrateNyanpass := flag.Bool("migrate-nyanpass", false, "import a MySQL source into a freshly installed panel")
	mapping := flag.String("legacy-map", "", "source SQL mapping file")
	schema := flag.Bool("legacy-schema", false, "print source SQLite schema without reading record data")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	if *check != "" {
		if err := panel.CheckDatabase(*check); err != nil {
			log.Fatal(err)
		}
		return
	}
	if *schema {
		if *legacy == "" {
			log.Fatal("--legacy-schema requires --legacy-db")
		}
		tables, err := panel.LegacySchema(*legacy)
		if err != nil {
			log.Fatal(err)
		}
		if err = json.NewEncoder(os.Stdout).Encode(tables); err != nil {
			log.Fatal(err)
		}
		return
	}
	if (*legacy != "" && *snapshot != "") || (*legacyMySQL && (*legacy != "" || *snapshot != "" || *mapping != "")) ||
		(*migrateNyanpass && (*legacyMySQL || *legacy != "" || *snapshot != "" || *mapping != "" || *preview || *backup != "")) {
		log.Fatal("choose one migration source")
	}
	if *legacy != "" {
		source, err := os.Stat(*legacy)
		if err != nil {
			log.Fatal(err)
		}
		destination, err := os.Stat(*database)
		if err == nil && os.SameFile(source, destination) {
			log.Fatal("source database and target database must be different files")
		}
		if err != nil && !os.IsNotExist(err) {
			log.Fatal(err)
		}
	}
	password := os.Getenv("HOPX_PASSWORD")
	if *initAdmin {
		if *snapshot != "" || *legacy != "" || *legacyMySQL || *migrateNyanpass || *backup != "" {
			log.Fatal("--init-admin must run alone")
		}
		raw, err := io.ReadAll(io.LimitReader(os.Stdin, 73))
		if err != nil || len(raw) < 10 || len(raw) > 72 {
			log.Fatal("initial administrator password must be 10–72 bytes")
		}
		password = string(raw)
	}
	if *snapshot != "" || *legacy != "" || *legacyMySQL || *migrateNyanpass {
		password = ""
	}
	if err := os.MkdirAll(filepath.Dir(*database), 0700); err != nil {
		log.Fatal(err)
	}
	s, err := panel.Open(panel.Options{Database: *database, CountryDatabase: os.Getenv("HOPX_GEOIP_DB"), AdminName: env("HOPX_ADMIN", "admin"), AdminPassword: password, PublicURL: os.Getenv("HOPX_PUBLIC_URL"), ReleaseDir: os.Getenv("HOPX_RELEASES"), PaymentSecret: os.Getenv("HOPX_PAYMENT_SECRET"), Version: version, UI: web.Assets()})
	if err != nil {
		log.Fatal(err)
	}
	defer s.Close()
	if *initAdmin {
		return
	}
	if *migrateNyanpass {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		report, err := s.MigrateNyanpass(ctx, os.Getenv("HOPX_NY_ADDRESS"), os.Getenv("HOPX_NY_DATABASE"),
			os.Getenv("HOPX_NY_USER"), os.Getenv("HOPX_NY_PASSWORD"), env("HOPX_ADMIN", "admin"), os.Getenv("HOPX_NY_TLS") != "false")
		if err != nil {
			log.Fatal(err)
		}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		if err = encoder.Encode(report); err != nil {
			log.Fatal(err)
		}
		return
	}
	if *legacyMySQL {
		dsn := os.Getenv("HOPX_LEGACY_MYSQL_DSN")
		if dsn == "" {
			log.Fatal("HOPX_LEGACY_MYSQL_DSN is required")
		}
		report, err := s.ImportNyanpassMySQL(dsn, env("HOPX_ADMIN", "admin"), os.Getenv("HOPX_MIGRATION_ADMIN_PASSWORD"), *preview)
		if err != nil {
			log.Fatal(err)
		}
		if err = json.NewEncoder(os.Stdout).Encode(report); err != nil {
			log.Fatal(err)
		}
		return
	}
	if *snapshot != "" {
		file, err := os.Open(*snapshot)
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()
		report, err := s.Import(file, *preview)
		if err != nil {
			log.Fatal(err)
		}
		if err = json.NewEncoder(os.Stdout).Encode(report); err != nil {
			log.Fatal(err)
		}
		return
	}
	if *legacy != "" {
		var report panel.MigrationResult
		if *mapping == "" {
			report, err = s.ImportNyanpass(*legacy, env("HOPX_ADMIN", "admin"), os.Getenv("HOPX_MIGRATION_ADMIN_PASSWORD"), *preview)
		} else {
			spec, openErr := os.Open(*mapping)
			if openErr != nil {
				log.Fatal(openErr)
			}
			defer spec.Close()
			report, err = s.ImportLegacy(*legacy, spec, *preview)
		}
		if err != nil {
			log.Fatal(err)
		}
		if err = json.NewEncoder(os.Stdout).Encode(report); err != nil {
			log.Fatal(err)
		}
		return
	}

	if *backup != "" {
		if err = s.Backup(*backup); err != nil {
			log.Fatal(err)
		}
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go s.Maintenance(ctx)
	server := &http.Server{Addr: *addr, Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 32 << 10}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	fmt.Println("HopX listening on", *addr)
	cert, key := os.Getenv("HOPX_TLS_CERT"), os.Getenv("HOPX_TLS_KEY")
	if cert != "" && key != "" {
		err = server.ListenAndServeTLS(cert, key)
	} else {
		err = server.ListenAndServe()
	}
	if err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
