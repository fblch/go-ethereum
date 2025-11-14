package elstack

/*
#cgo linux CFLAGS:  -I${SRCDIR}/../../../el-stack-rs/golang/el_stack
#cgo linux LDFLAGS: -L${SRCDIR}/../../../el-stack-rs/target/release -lel_stack -Wl,-rpath,${SRCDIR}/../../el-stack-rs/target/release

#cgo darwin CFLAGS:  -I${SRCDIR}/../../../el-stack-rs/golang/el_stack
#cgo darwin LDFLAGS: -L${SRCDIR}/../../../el-stack-rs/target/release -lel_stack -Wl,-rpath,${SRCDIR}/../../el-stack-rs/target/release

#include "el_stack.h"
*/
import "C"

import (
	"github.com/ethereum/go-ethereum/log"
)

var elLog = log.Root().New("cmp", "p2p/el_stack")
