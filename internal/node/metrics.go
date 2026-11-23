package node

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"hopx/internal/wire"
)

type sampler struct {
	iface                     string
	last                      time.Time
	cpuTotal, cpuIdle, rx, tx uint64
	proc                      procReader
}

func number(v string) uint64 { n, _ := strconv.ParseUint(v, 10, 64); return n }

type procReader struct {
	buffer [4096]byte
}

func (r *procReader) lines(path string, f func([]string)) {
	file, e := os.Open(path)
	if e != nil {
		return
	}
	defer file.Close()
	scan := bufio.NewScanner(file)
	scan.Buffer(r.buffer[:], bufio.MaxScanTokenSize)
	var fieldsBuffer [32]string
	for scan.Scan() {
		fields := fieldsBuffer[:0]
		for field := range strings.FieldsSeq(scan.Text()) {
			fields = append(fields, field)
		}
		if len(fields) > 0 {
			f(fields)
		}
	}
}

func (s *sampler) sample(dir string) wire.Metrics {
	var m wire.Metrics
	if descriptors, err := os.Open("/proc/self/fd"); err == nil {
		names, _ := descriptors.Readdirnames(-1)
		_ = descriptors.Close()
		m.FileDescriptors = max(0, len(names)-1)
		var limit unix.Rlimit
		if unix.Getrlimit(unix.RLIMIT_NOFILE, &limit) == nil {
			m.FileLimit = limit.Cur
		}
	}
	s.proc.lines("/proc/stat", func(f []string) {
		if f[0] != "cpu" || len(f) < 6 {
			return
		}
		var total uint64
		for _, v := range f[1:min(len(f), 9)] {
			total += number(v)
		}
		idle := number(f[4]) + number(f[5])
		if s.cpuTotal > 0 && total > s.cpuTotal && idle >= s.cpuIdle {
			m.CPU = clamp(100 * (1 - float64(idle-s.cpuIdle)/float64(total-s.cpuTotal)))
		}
		s.cpuTotal, s.cpuIdle = total, idle
	})
	var mem, free uint64
	s.proc.lines("/proc/meminfo", func(f []string) {
		if len(f) < 2 {
			return
		}
		switch f[0] {
		case "MemTotal:":
			mem = number(f[1])
		case "MemAvailable:":
			free = number(f[1])
		}
	})
	if mem > 0 && free <= mem {
		m.RAM = 100 * float64(mem-free) / float64(mem)
	}
	s.proc.lines("/proc/self/status", func(f []string) {
		if len(f) > 1 && f[0] == "VmRSS:" {
			m.RSS = int64(number(f[1]) * 1024)
		}
	})
	raw, _ := os.ReadFile("/proc/uptime")
	if values := strings.Fields(string(raw)); len(values) > 0 {
		seconds, _ := strconv.ParseFloat(values[0], 64)
		m.Uptime = int64(seconds)
	}
	interfaces := make(map[string]bool)
	for raw := range strings.SplitSeq(s.iface, ",") {
		if name := strings.TrimSpace(raw); name != "" && name != "lo" {
			interfaces[name] = true
		}
	}
	if len(interfaces) == 0 {
		s.proc.lines("/proc/net/route", func(f []string) {
			if len(f) > 1 && f[1] == "00000000" && len(interfaces) == 0 {
				interfaces[f[0]] = true
			}
		})
	}
	var rx, tx uint64
	s.proc.lines("/proc/net/dev", func(f []string) {
		if interfaces[strings.TrimSuffix(f[0], ":")] && len(f) > 9 {
			rx += number(f[1])
			tx += number(f[9])
		}
	})
	now := time.Now()
	if !s.last.IsZero() && rx >= s.rx && tx >= s.tx {
		seconds := now.Sub(s.last).Seconds()
		m.InMbps = float64(rx-s.rx) * 8 / 1e6 / seconds
		m.OutMbps = float64(tx-s.tx) * 8 / 1e6 / seconds
	}
	s.last, s.rx, s.tx = now, rx, tx
	m.Disk = diskUsage(dir)
	return m
}

func clamp(v float64) float64 { return min(100, max(0, v)) }
