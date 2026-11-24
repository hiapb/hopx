package main

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"hopx/internal/release"
)

func main() {
	if len(os.Args) != 3 {
		exit("用法：hopx-release-verify 公钥文件 发行清单")
	}
	publicKey, err := os.ReadFile(os.Args[1])
	if err != nil {
		exit("读取节点发行公钥失败")
	}
	raw, err := os.ReadFile(os.Args[2])
	if err != nil {
		exit("读取节点发行清单失败")
	}
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	if len(lines) != 4 {
		exit("节点发行清单格式无效")
	}
	platform := runtime.GOOS + "-" + runtime.GOARCH
	if err := release.Verify(publicKey, lines[0], platform, lines[2], lines[3]); err != nil {
		exit("节点发行签名校验失败，请核对面板公钥和发行清单")
	}
}

func exit(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
