//go:build android

package elstack

/*
#cgo android CFLAGS:  -I${SRCDIR}/../../../el-stack-rs/golang/el_stack
#cgo android LDFLAGS: -L${SRCDIR}/../../../el-stack-rs/android/app/src/main/jniLibs/arm64-v8a -lel_stack -Wl,-rpath,${SRCDIR}/../../el-stack-rs/android/app/src/main/jniLibs/arm64-v8a

#include "el_stack.h"
*/
import "C"

// platform-specific cgo glue; logging is declared in logger.go
