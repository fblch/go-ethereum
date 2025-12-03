//go:build linux && !android && !ios

package elstack

/*
#cgo linux CFLAGS:  -I${SRCDIR}/../../../el-stack-rs/golang/el_stack
#cgo linux LDFLAGS: -L${SRCDIR}/../../../el-stack-rs/target/release -lel_stack -Wl,-rpath,${SRCDIR}/../../el-stack-rs/target/release

#include "el_stack.h"
*/
import "C"

// platform-specific cgo glue; logging is declared in logger.go
