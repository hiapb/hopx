package panel

import (
	"errors"
	"slices"
	"strings"

	"hopx/internal/wire"
)

func validateIngress(f *wire.IngressFilter) error {
	if f == nil {
		return nil
	}
	for _, values := range [][]string{f.AllowedHosts, f.BlockedHosts, f.BlockedPaths, f.BlockedTypes} {
		if len(values) > 128 {
			return errors.New("各项入口筛选最多填写 128 项")
		}
		for i, value := range values {
			value = strings.TrimSpace(value)
			if value == "" || len(value) > 1024 || strings.ContainsAny(value, "\x00\r\n") {
				return errors.New("入口筛选包含无效条目")
			}
			values[i] = value
		}
	}
	for _, value := range f.BlockedTypes {
		if !slices.Contains([]string{"tls", "http", "socks", "fet"}, value) {
			return errors.New("入口协议筛选支持 TLS、HTTP、SOCKS 和 FET")
		}
	}
	return nil
}
