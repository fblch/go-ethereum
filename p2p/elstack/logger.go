package elstack

import "github.com/ethereum/go-ethereum/log"

// Shared logger for elstack package.
var elLog = log.Root().New("cmp", "p2p/el_stack")
