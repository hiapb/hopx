//go:build linux || darwin

package node

import (
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func fileDescriptorBudget(listeners, connections int, relayEnabled bool) (int, int) {
	var limit unix.Rlimit
	if unix.Getrlimit(unix.RLIMIT_NOFILE, &limit) != nil || limit.Cur > 1<<30 {
		return listeners, connections
	}
	available := max(0, int(limit.Cur)-128)
	listeners = min(listeners, available/2)
	socketsPerSession := 2
	if relayEnabled {
		socketsPerSession = 4
	}
	return listeners, min(connections, (available-listeners)/socketsPerSession)
}

// Use a conservative fraction of the node's memory for blocking copy and datagram
// buffers. Listener sockets and runtime management have separate headroom.
func memorySessionLimit(configured int) int {
	var ram uint64
	var proc procReader
	proc.lines("/proc/meminfo", func(fields []string) {
		if len(fields) > 1 && fields[0] == "MemTotal:" {
			ram = number(fields[1]) * 1024
		}
	})
	for _, path := range []string{"/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes"} {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		limit, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
		if err == nil && limit > 0 && (ram == 0 || ram > limit) {
			ram = limit
		}
	}
	if ram == 0 {
		return configured
	}
	return min(configured, max(16, int(ram/4/(96<<10))))
}
