//go:build linux || darwin

package node

import "golang.org/x/sys/unix"

func diskUsage(path string) float64 {
	var stat unix.Statfs_t
	if unix.Statfs(path, &stat) != nil || stat.Blocks == 0 {
		return 0
	}
	return clamp(100 * (1 - float64(stat.Bavail)/float64(stat.Blocks)))
}
