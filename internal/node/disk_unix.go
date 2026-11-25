//go:build linux || darwin

package node

import (
	"golang.org/x/sys/unix"
	"hopx/internal/wire"
)

func diskUsage(path string) wire.ResourceBytes {
	var stat unix.Statfs_t
	if unix.Statfs(path, &stat) != nil || stat.Blocks == 0 || stat.Bsize <= 0 {
		return wire.ResourceBytes{}
	}
	blockSize := uint64(stat.Bsize)
	return wire.ResourceBytes{Used: (stat.Blocks - min(stat.Blocks, stat.Bavail)) * blockSize, Total: stat.Blocks * blockSize}
}
