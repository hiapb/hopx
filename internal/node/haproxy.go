package node

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"hopx/internal/wire"
)

type proxyRule struct {
	wire.Forward
	stats *counter
}

type proxyProcess struct {
	socket    string
	command   *exec.Cmd
	done      chan struct{}
	counters  map[int64]*counter
	last      map[int64][2]int64
	frontends map[int64]proxyFrontend
}

type proxyFrontend struct {
	expires int64
	targets int
	metered bool
}

type proxyStartupLog struct{ bytes.Buffer }

func (log *proxyStartupLog) Write(p []byte) (int, error) {
	keep := min(len(p), max(0, 4096-log.Len()))
	_, _ = log.Buffer.Write(p[:keep])
	return len(p), nil
}

type proxyEngine struct {
	binary                 string
	config                 string
	active, draining       *proxyProcess
	listeners, connections int
	reserved               int
	expiry                 *time.Timer
	reportUntil            time.Time
}

func meteredProxy(rule wire.Forward) bool { return rule.HAProxy && rule.QuotaManaged }

func (e *Engine) authorizeProxyTraffic(period time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.proxy.reportUntil = time.Now().Add(max(30*time.Second, 3*period))
}

func (p *proxyProcess) running() bool {
	if p == nil {
		return false
	}
	select {
	case <-p.done:
		return false
	default:
		return true
	}
}

func (p *proxyProcess) stop() {
	if p.running() {
		_ = p.command.Process.Kill()
		<-p.done
	}
}

func (p *proxyProcess) stopFrontends(shouldStop func(int64, proxyFrontend) bool) {
	if !p.running() {
		return
	}
	var commands strings.Builder
	for id, frontend := range p.frontends {
		if !shouldStop(id, frontend) {
			continue
		}
		if commands.Len() >= 4000 {
			if !p.runCommands(commands.String()) {
				p.stop()
				return
			}
			commands.Reset()
		}
		fmt.Fprintf(&commands, "disable frontend hopx_%d;", id)
		for i := 1; i <= frontend.targets; i++ {
			fmt.Fprintf(&commands, "shutdown sessions server hopx_%d/target_%d;", id, i)
		}
		delete(p.frontends, id)
	}
	if commands.Len() != 0 && !p.runCommands(commands.String()) {
		p.stop()
	}
}

func (p *proxyProcess) runCommands(commands string) bool {
	conn, err := net.DialTimeout("unix", p.socket, 250*time.Millisecond)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	if _, err = io.WriteString(conn, commands+"\n"); err != nil {
		return false
	}
	result, err := io.ReadAll(io.LimitReader(conn, 4096))
	return err == nil && len(bytes.TrimSpace(result)) == 0
}

// One timer per node covers the active and draining HAProxy processes.
func (e *Engine) scheduleProxyExpiry() {
	if e.proxy.expiry != nil {
		e.proxy.expiry.Stop()
		e.proxy.expiry = nil
	}
	var earliest time.Time
	reportUntil := e.proxy.reportUntil
	if reportUntil.IsZero() {
		reportUntil = time.Now()
	}
	for _, process := range []*proxyProcess{e.proxy.active, e.proxy.draining} {
		if !process.running() {
			continue
		}
		for _, frontend := range process.frontends {
			if frontend.expires > 0 {
				deadline := time.Unix(frontend.expires, 0)
				if earliest.IsZero() || deadline.Before(earliest) {
					earliest = deadline
				}
			}
			if frontend.metered && (earliest.IsZero() || reportUntil.Before(earliest)) {
				earliest = reportUntil
			}
		}
	}
	if !earliest.IsZero() {
		e.proxy.expiry = time.AfterFunc(time.Until(earliest), func() {
			e.mu.Lock()
			defer e.mu.Unlock()
			now := time.Now()
			for _, process := range []*proxyProcess{e.proxy.active, e.proxy.draining} {
				process.stopFrontends(func(_ int64, frontend proxyFrontend) bool {
					if frontend.metered && !now.Before(e.proxy.reportUntil) {
						if process == e.proxy.active {
							e.applied = ""
						}
						return true
					}
					return frontend.expires > 0 && frontend.expires <= now.Unix()
				})
			}
			e.scheduleProxyExpiry()
		})
	}
}

func (p *proxyProcess) sample() (int, error) {
	conn, err := net.DialTimeout("unix", p.socket, 250*time.Millisecond)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	if _, err := io.WriteString(conn, "show stat\n"); err != nil {
		return 0, err
	}
	reader := csv.NewReader(conn)
	header, err := reader.Read()
	if err != nil {
		return 0, err
	}
	fields := make(map[string]int, len(header))
	for i, name := range header {
		fields[strings.TrimPrefix(name, "# ")] = i
	}
	for _, name := range []string{"pxname", "svname", "bin", "bout", "scur"} {
		if _, ok := fields[name]; !ok {
			return 0, fmt.Errorf("HAProxy stats missing %s", name)
		}
	}
	connections := 0
	for {
		row, err := reader.Read()
		if errors.Is(err, io.EOF) {
			return connections, nil
		}
		if err != nil {
			return 0, err
		}
		name := row[fields["pxname"]]
		if row[fields["svname"]] != "FRONTEND" || !strings.HasPrefix(name, "hopx_") {
			continue
		}
		id, _ := strconv.ParseInt(strings.TrimPrefix(name, "hopx_"), 10, 64)
		stats := p.counters[id]
		if stats == nil {
			continue
		}
		in, _ := strconv.ParseInt(row[fields["bin"]], 10, 64)
		out, _ := strconv.ParseInt(row[fields["bout"]], 10, 64)
		active, _ := strconv.Atoi(row[fields["scur"]])
		old := p.last[id]
		stats.in.Add(max(0, in-old[0]))
		stats.out.Add(max(0, out-old[1]))
		p.last[id] = [2]int64{in, out}
		connections += active
	}
}

func safeProxyAddress(address string, bind bool) bool {
	host, port, err := net.SplitHostPort(address)
	n, portErr := strconv.Atoi(port)
	if err != nil || portErr != nil || n < 1 || n > 65535 || port != strconv.Itoa(n) {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	if bind || host == "" || len(host) > 253 {
		return false
	}
	for _, c := range strings.ToLower(host) {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '.' && c != '-' {
			return false
		}
	}
	return !strings.HasPrefix(host, "-")
}

func proxyConfig(rules []proxyRule, hosts []string, maxConnections int) (string, error) {
	if len(rules) == 0 {
		return "", nil
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	var config strings.Builder
	fmt.Fprintf(&config, "    nbthread 1\n    maxconn %d\n    hard-stop-after 15s\n\nresolvers hopx_dns\n    parse-resolv-conf\n\ndefaults\n    mode tcp\n    timeout connect 5s\n    timeout client 5m\n    timeout server 5m\n    option redispatch\n    retries 2\n", maxConnections)
	for _, rule := range rules {
		fmt.Fprintf(&config, "\nlisten hopx_%d\n", rule.ID)
		if rule.HAProxyRatio > 0 {
			fmt.Fprintf(&config, "    # traffic quota epoch %d\n", rule.QuotaEpoch)
		}
		if rule.Expires > 0 {
			fmt.Fprintf(&config, "    tcp-request connection reject if { date ge %d }\n", rule.Expires)
		}
		for _, host := range hosts {
			if host == "" {
				fmt.Fprintf(&config, "    bind [::]:%d v4v6\n", rule.Port)
				continue
			}
			bind := net.JoinHostPort(host, strconv.Itoa(rule.Port))
			if !safeProxyAddress(bind, true) {
				return "", fmt.Errorf("HAProxy requires an IP bind address: %s", host)
			}
			fmt.Fprintf(&config, "    bind %s\n", bind)
		}
		balance := "roundrobin"
		switch rule.Strategy {
		case "random":
			balance = "random"
		case "first":
			balance = "first"
		case "ip-hash":
			balance = "source"
		case "least-connections":
			balance = "leastconn"
		}
		fmt.Fprintf(&config, "    balance %s\n", balance)
		for i, target := range rule.Targets {
			if !safeProxyAddress(target, false) {
				return "", fmt.Errorf("invalid HAProxy target for rule %d", rule.ID)
			}
			host, _, _ := net.SplitHostPort(target)
			resolve := ""
			if net.ParseIP(host) == nil {
				resolve = " resolvers hopx_dns resolve-opts allow-dup-ip init-addr last,libc,none"
			}
			fmt.Fprintf(&config, "    server target_%d %s%s\n", i+1, target, resolve)
		}
	}
	return config.String(), nil
}

func (e *Engine) stageProxy(ctx context.Context, rules []proxyRule) (*proxyProcess, string, error) {
	config, err := proxyConfig(rules, e.bind, max(1, cap(e.slots)/4))
	if err != nil {
		return nil, config, err
	}
	if e.proxy.active.running() && config == e.proxy.config && len(e.proxy.active.frontends) == len(rules) {
		return e.proxy.active, config, nil
	}
	if e.proxy.draining.running() && (config != "" || e.proxy.active.running()) {
		return nil, "", errors.New("previous HAProxy process is draining connections")
	}
	if config == "" {
		return nil, "", nil
	}
	if e.proxy.binary == "" {
		return nil, "", errors.New("HAProxy is missing from PATH")
	}
	dir, err := os.MkdirTemp("/tmp", "hopx-ha-")
	if err != nil {
		return nil, "", err
	}
	path := filepath.Join(dir, "haproxy.cfg")
	socket := filepath.Join(dir, "admin.sock")
	content := "global\n    stats socket " + socket + " mode 600 level admin expose-fd listeners\n" + config
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		_ = os.RemoveAll(dir)
		return nil, "", err
	}
	args := []string{"-db", "-f", path}
	if e.proxy.active.running() {
		args = append(args, "-x", e.proxy.active.socket)
	}
	command := exec.CommandContext(ctx, e.proxy.binary, args...)
	var stderr proxyStartupLog
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		_ = os.RemoveAll(dir)
		return nil, "", err
	}
	p := &proxyProcess{socket: socket, command: command, done: make(chan struct{}), counters: make(map[int64]*counter),
		last: make(map[int64][2]int64), frontends: make(map[int64]proxyFrontend, len(rules))}
	for _, rule := range rules {
		p.counters[rule.ID] = rule.stats
		p.frontends[rule.ID] = proxyFrontend{expires: rule.Expires, targets: len(rule.Targets), metered: meteredProxy(rule.Forward)}
	}
	go func() {
		_ = command.Wait()
		_ = os.RemoveAll(dir)
		close(p.done)
	}()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-p.done:
			return nil, "", fmt.Errorf("HAProxy failed to start: %s", strings.TrimSpace(stderr.String()))
		case <-timer.C:
			p.stop()
			return nil, "", errors.New("HAProxy startup timed out")
		case <-tick.C:
			if _, err := p.sample(); err == nil && p.running() {
				return p, config, nil
			}
		}
	}
}

func (e *Engine) commitProxy(next *proxyProcess, config string, rules []proxyRule) {
	if next != e.proxy.active {
		keep := make(map[int64]bool, len(rules))
		for _, rule := range rules {
			keep[rule.ID] = true
		}
		for _, old := range []*proxyProcess{e.proxy.active, e.proxy.draining} {
			old.stopFrontends(func(id int64, _ proxyFrontend) bool { return !keep[id] })
		}
		if current := e.proxy.active; current.running() {
			_, _ = current.sample()
			_ = current.command.Process.Signal(syscall.SIGUSR1)
			e.proxy.draining = current
		}
		e.proxy.active = next
	}
	if next != nil {
		for _, rule := range rules {
			next.counters[rule.ID] = rule.stats
			next.frontends[rule.ID] = proxyFrontend{expires: rule.Expires, targets: len(rule.Targets), metered: meteredProxy(rule.Forward)}
		}
	}
	e.proxy.config = config
	e.proxy.listeners = len(rules) * len(e.bind)
	e.scheduleProxyExpiry()
}

func (e *Engine) reserveProxySessions() error {
	want := 2 * max(1, cap(e.slots)/4)
	for e.proxy.reserved < want {
		select {
		case e.slots <- struct{}{}:
			e.proxy.reserved++
		default:
			e.releaseProxySessions()
			return errors.New("not enough free session capacity to activate HAProxy")
		}
	}
	return nil
}

func (e *Engine) releaseProxySessions() {
	for e.proxy.reserved > 0 {
		<-e.slots
		e.proxy.reserved--
	}
}
