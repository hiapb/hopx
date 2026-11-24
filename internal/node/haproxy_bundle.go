//go:build bundledhaproxy

package node

import _ "embed"

//go:embed haproxy.gz
var bundledHAProxy string
