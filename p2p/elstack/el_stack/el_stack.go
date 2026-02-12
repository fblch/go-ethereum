package el_stack

// #cgo CFLAGS: -I${SRCDIR}
// #cgo !android LDFLAGS: ${SRCDIR}/libs/linux/libel_stack.a -lm
// #cgo android,arm64 LDFLAGS: ${SRCDIR}/libs/android_arm64/libel_stack.a -lm
// #include <el_stack.h>
import "C"

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"reflect"
	"runtime"
	"runtime/cgo"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

// This is needed, because as of go 1.24
// type RustBuffer C.RustBuffer cannot have methods,
// RustBuffer is treated as non-local type
type GoRustBuffer struct {
	inner C.RustBuffer
}

type RustBufferI interface {
	AsReader() *bytes.Reader
	Free()
	ToGoBytes() []byte
	Data() unsafe.Pointer
	Len() uint64
	Capacity() uint64
}

func RustBufferFromExternal(b RustBufferI) GoRustBuffer {
	return GoRustBuffer{
		inner: C.RustBuffer{
			capacity: C.uint64_t(b.Capacity()),
			len:      C.uint64_t(b.Len()),
			data:     (*C.uchar)(b.Data()),
		},
	}
}

func (cb GoRustBuffer) Capacity() uint64 {
	return uint64(cb.inner.capacity)
}

func (cb GoRustBuffer) Len() uint64 {
	return uint64(cb.inner.len)
}

func (cb GoRustBuffer) Data() unsafe.Pointer {
	return unsafe.Pointer(cb.inner.data)
}

func (cb GoRustBuffer) AsReader() *bytes.Reader {
	b := unsafe.Slice((*byte)(cb.inner.data), C.uint64_t(cb.inner.len))
	return bytes.NewReader(b)
}

func (cb GoRustBuffer) Free() {
	rustCall(func(status *C.RustCallStatus) bool {
		C.ffi_el_stack_rustbuffer_free(cb.inner, status)
		return false
	})
}

func (cb GoRustBuffer) ToGoBytes() []byte {
	return C.GoBytes(unsafe.Pointer(cb.inner.data), C.int(cb.inner.len))
}

func stringToRustBuffer(str string) C.RustBuffer {
	return bytesToRustBuffer([]byte(str))
}

func bytesToRustBuffer(b []byte) C.RustBuffer {
	if len(b) == 0 {
		return C.RustBuffer{}
	}
	// We can pass the pointer along here, as it is pinned
	// for the duration of this call
	foreign := C.ForeignBytes{
		len:  C.int(len(b)),
		data: (*C.uchar)(unsafe.Pointer(&b[0])),
	}

	return rustCall(func(status *C.RustCallStatus) C.RustBuffer {
		return C.ffi_el_stack_rustbuffer_from_bytes(foreign, status)
	})
}

type BufLifter[GoType any] interface {
	Lift(value RustBufferI) GoType
}

type BufLowerer[GoType any] interface {
	Lower(value GoType) C.RustBuffer
}

type BufReader[GoType any] interface {
	Read(reader io.Reader) GoType
}

type BufWriter[GoType any] interface {
	Write(writer io.Writer, value GoType)
}

func LowerIntoRustBuffer[GoType any](bufWriter BufWriter[GoType], value GoType) C.RustBuffer {
	// This might be not the most efficient way but it does not require knowing allocation size
	// beforehand
	var buffer bytes.Buffer
	bufWriter.Write(&buffer, value)

	bytes, err := io.ReadAll(&buffer)
	if err != nil {
		panic(fmt.Errorf("reading written data: %w", err))
	}
	return bytesToRustBuffer(bytes)
}

func LiftFromRustBuffer[GoType any](bufReader BufReader[GoType], rbuf RustBufferI) GoType {
	defer rbuf.Free()
	reader := rbuf.AsReader()
	item := bufReader.Read(reader)
	if reader.Len() > 0 {
		// TODO: Remove this
		leftover, _ := io.ReadAll(reader)
		panic(fmt.Errorf("Junk remaining in buffer after lifting: %s", string(leftover)))
	}
	return item
}

func rustCallWithError[E any, U any](converter BufReader[*E], callback func(*C.RustCallStatus) U) (U, *E) {
	var status C.RustCallStatus
	returnValue := callback(&status)
	err := checkCallStatus(converter, status)
	return returnValue, err
}

func checkCallStatus[E any](converter BufReader[*E], status C.RustCallStatus) *E {
	switch status.code {
	case 0:
		return nil
	case 1:
		return LiftFromRustBuffer(converter, GoRustBuffer{inner: status.errorBuf})
	case 2:
		// when the rust code sees a panic, it tries to construct a rustBuffer
		// with the message.  but if that code panics, then it just sends back
		// an empty buffer.
		if status.errorBuf.len > 0 {
			panic(fmt.Errorf("%s", FfiConverterStringINSTANCE.Lift(GoRustBuffer{inner: status.errorBuf})))
		} else {
			panic(fmt.Errorf("Rust panicked while handling Rust panic"))
		}
	default:
		panic(fmt.Errorf("unknown status code: %d", status.code))
	}
}

func checkCallStatusUnknown(status C.RustCallStatus) error {
	switch status.code {
	case 0:
		return nil
	case 1:
		panic(fmt.Errorf("function not returning an error returned an error"))
	case 2:
		// when the rust code sees a panic, it tries to construct a C.RustBuffer
		// with the message.  but if that code panics, then it just sends back
		// an empty buffer.
		if status.errorBuf.len > 0 {
			panic(fmt.Errorf("%s", FfiConverterStringINSTANCE.Lift(GoRustBuffer{
				inner: status.errorBuf,
			})))
		} else {
			panic(fmt.Errorf("Rust panicked while handling Rust panic"))
		}
	default:
		return fmt.Errorf("unknown status code: %d", status.code)
	}
}

func rustCall[U any](callback func(*C.RustCallStatus) U) U {
	returnValue, err := rustCallWithError[error](nil, callback)
	if err != nil {
		panic(err)
	}
	return returnValue
}

type NativeError interface {
	AsError() error
}

func writeInt8(writer io.Writer, value int8) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeUint8(writer io.Writer, value uint8) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeInt16(writer io.Writer, value int16) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeUint16(writer io.Writer, value uint16) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeInt32(writer io.Writer, value int32) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeUint32(writer io.Writer, value uint32) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeInt64(writer io.Writer, value int64) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeUint64(writer io.Writer, value uint64) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeFloat32(writer io.Writer, value float32) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeFloat64(writer io.Writer, value float64) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func readInt8(reader io.Reader) int8 {
	var result int8
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readUint8(reader io.Reader) uint8 {
	var result uint8
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readInt16(reader io.Reader) int16 {
	var result int16
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readUint16(reader io.Reader) uint16 {
	var result uint16
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readInt32(reader io.Reader) int32 {
	var result int32
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readUint32(reader io.Reader) uint32 {
	var result uint32
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readInt64(reader io.Reader) int64 {
	var result int64
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readUint64(reader io.Reader) uint64 {
	var result uint64
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readFloat32(reader io.Reader) float32 {
	var result float32
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readFloat64(reader io.Reader) float64 {
	var result float64
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func init() {

	FfiConverterCallbackInterfaceElStackIssueEventDelegateINSTANCE.register()
	FfiConverterCallbackInterfaceElStackVpnEventDelegateINSTANCE.register()
	uniffiCheckChecksums()
}

func uniffiCheckChecksums() {
	// Get the bindings contract version from our ComponentInterface
	bindingsContractVersion := 26
	// Get the scaffolding contract version by calling the into the dylib
	scaffoldingContractVersion := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint32_t {
		return C.ffi_el_stack_uniffi_contract_version()
	})
	if bindingsContractVersion != int(scaffoldingContractVersion) {
		// If this happens try cleaning and rebuilding your project
		panic("el_stack: UniFFI contract version mismatch")
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_el_stack_checksum_func_initialize()
		})
		if checksum != 5191 {
			// If this happens try cleaning and rebuilding your project
			panic("el_stack: uniffi_el_stack_checksum_func_initialize: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_el_stack_checksum_func_restart()
		})
		if checksum != 42599 {
			// If this happens try cleaning and rebuilding your project
			panic("el_stack: uniffi_el_stack_checksum_func_restart: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_el_stack_checksum_func_start()
		})
		if checksum != 11044 {
			// If this happens try cleaning and rebuilding your project
			panic("el_stack: uniffi_el_stack_checksum_func_start: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_el_stack_checksum_func_stop()
		})
		if checksum != 7174 {
			// If this happens try cleaning and rebuilding your project
			panic("el_stack: uniffi_el_stack_checksum_func_stop: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_el_stack_checksum_func_tcp_bind()
		})
		if checksum != 4457 {
			// If this happens try cleaning and rebuilding your project
			panic("el_stack: uniffi_el_stack_checksum_func_tcp_bind: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_el_stack_checksum_func_tcp_connect()
		})
		if checksum != 20420 {
			// If this happens try cleaning and rebuilding your project
			panic("el_stack: uniffi_el_stack_checksum_func_tcp_connect: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_el_stack_checksum_func_tls_connect()
		})
		if checksum != 39778 {
			// If this happens try cleaning and rebuilding your project
			panic("el_stack: uniffi_el_stack_checksum_func_tls_connect: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_el_stack_checksum_func_udp_bind()
		})
		if checksum != 59103 {
			// If this happens try cleaning and rebuilding your project
			panic("el_stack: uniffi_el_stack_checksum_func_udp_bind: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_el_stack_checksum_method_tcplistener_accept()
		})
		if checksum != 48341 {
			// If this happens try cleaning and rebuilding your project
			panic("el_stack: uniffi_el_stack_checksum_method_tcplistener_accept: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_el_stack_checksum_method_tcplistener_bind_addr()
		})
		if checksum != 23263 {
			// If this happens try cleaning and rebuilding your project
			panic("el_stack: uniffi_el_stack_checksum_method_tcplistener_bind_addr: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_el_stack_checksum_method_tcpstream_close()
		})
		if checksum != 57632 {
			// If this happens try cleaning and rebuilding your project
			panic("el_stack: uniffi_el_stack_checksum_method_tcpstream_close: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_el_stack_checksum_method_tcpstream_local_addr()
		})
		if checksum != 47199 {
			// If this happens try cleaning and rebuilding your project
			panic("el_stack: uniffi_el_stack_checksum_method_tcpstream_local_addr: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_el_stack_checksum_method_tcpstream_peer_addr()
		})
		if checksum != 29322 {
			// If this happens try cleaning and rebuilding your project
			panic("el_stack: uniffi_el_stack_checksum_method_tcpstream_peer_addr: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_el_stack_checksum_method_tcpstream_recv()
		})
		if checksum != 23618 {
			// If this happens try cleaning and rebuilding your project
			panic("el_stack: uniffi_el_stack_checksum_method_tcpstream_recv: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_el_stack_checksum_method_tcpstream_send()
		})
		if checksum != 14434 {
			// If this happens try cleaning and rebuilding your project
			panic("el_stack: uniffi_el_stack_checksum_method_tcpstream_send: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_el_stack_checksum_method_tlsstream_close()
		})
		if checksum != 21480 {
			// If this happens try cleaning and rebuilding your project
			panic("el_stack: uniffi_el_stack_checksum_method_tlsstream_close: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_el_stack_checksum_method_tlsstream_local_addr()
		})
		if checksum != 41017 {
			// If this happens try cleaning and rebuilding your project
			panic("el_stack: uniffi_el_stack_checksum_method_tlsstream_local_addr: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_el_stack_checksum_method_tlsstream_peer_addr()
		})
		if checksum != 14669 {
			// If this happens try cleaning and rebuilding your project
			panic("el_stack: uniffi_el_stack_checksum_method_tlsstream_peer_addr: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_el_stack_checksum_method_tlsstream_recv()
		})
		if checksum != 442 {
			// If this happens try cleaning and rebuilding your project
			panic("el_stack: uniffi_el_stack_checksum_method_tlsstream_recv: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_el_stack_checksum_method_tlsstream_send()
		})
		if checksum != 35674 {
			// If this happens try cleaning and rebuilding your project
			panic("el_stack: uniffi_el_stack_checksum_method_tlsstream_send: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_el_stack_checksum_method_udpsocket_local_addr()
		})
		if checksum != 62680 {
			// If this happens try cleaning and rebuilding your project
			panic("el_stack: uniffi_el_stack_checksum_method_udpsocket_local_addr: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_el_stack_checksum_method_udpsocket_recv_from()
		})
		if checksum != 4466 {
			// If this happens try cleaning and rebuilding your project
			panic("el_stack: uniffi_el_stack_checksum_method_udpsocket_recv_from: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_el_stack_checksum_method_udpsocket_send_to()
		})
		if checksum != 7356 {
			// If this happens try cleaning and rebuilding your project
			panic("el_stack: uniffi_el_stack_checksum_method_udpsocket_send_to: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_el_stack_checksum_constructor_elstackissueconfig_new()
		})
		if checksum != 52850 {
			// If this happens try cleaning and rebuilding your project
			panic("el_stack: uniffi_el_stack_checksum_constructor_elstackissueconfig_new: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_el_stack_checksum_constructor_elstackproductconfig_new()
		})
		if checksum != 20203 {
			// If this happens try cleaning and rebuilding your project
			panic("el_stack: uniffi_el_stack_checksum_constructor_elstackproductconfig_new: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_el_stack_checksum_constructor_elstacksocketbufferconfig_new()
		})
		if checksum != 34062 {
			// If this happens try cleaning and rebuilding your project
			panic("el_stack: uniffi_el_stack_checksum_constructor_elstacksocketbufferconfig_new: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_el_stack_checksum_constructor_elstackvcconfig_new()
		})
		if checksum != 63174 {
			// If this happens try cleaning and rebuilding your project
			panic("el_stack: uniffi_el_stack_checksum_constructor_elstackvcconfig_new: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_el_stack_checksum_constructor_elstackvpnconfig_new()
		})
		if checksum != 41342 {
			// If this happens try cleaning and rebuilding your project
			panic("el_stack: uniffi_el_stack_checksum_constructor_elstackvpnconfig_new: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_el_stack_checksum_method_elstackissueeventdelegate_on_generate_auth_vp()
		})
		if checksum != 8350 {
			// If this happens try cleaning and rebuilding your project
			panic("el_stack: uniffi_el_stack_checksum_method_elstackissueeventdelegate_on_generate_auth_vp: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_el_stack_checksum_method_elstackissueeventdelegate_on_el_pub_key()
		})
		if checksum != 37720 {
			// If this happens try cleaning and rebuilding your project
			panic("el_stack: uniffi_el_stack_checksum_method_elstackissueeventdelegate_on_el_pub_key: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_el_stack_checksum_method_elstackissueeventdelegate_on_el_vp_sign()
		})
		if checksum != 10604 {
			// If this happens try cleaning and rebuilding your project
			panic("el_stack: uniffi_el_stack_checksum_method_elstackissueeventdelegate_on_el_vp_sign: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_el_stack_checksum_method_elstackvpneventdelegate_on_status_change()
		})
		if checksum != 29612 {
			// If this happens try cleaning and rebuilding your project
			panic("el_stack: uniffi_el_stack_checksum_method_elstackvpneventdelegate_on_status_change: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_el_stack_checksum_method_elstackvpneventdelegate_on_connection_error()
		})
		if checksum != 13072 {
			// If this happens try cleaning and rebuilding your project
			panic("el_stack: uniffi_el_stack_checksum_method_elstackvpneventdelegate_on_connection_error: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_el_stack_checksum_method_elstackvpneventdelegate_on_linked_params()
		})
		if checksum != 61358 {
			// If this happens try cleaning and rebuilding your project
			panic("el_stack: uniffi_el_stack_checksum_method_elstackvpneventdelegate_on_linked_params: UniFFI API checksum mismatch")
		}
	}
}

type FfiConverterUint32 struct{}

var FfiConverterUint32INSTANCE = FfiConverterUint32{}

func (FfiConverterUint32) Lower(value uint32) C.uint32_t {
	return C.uint32_t(value)
}

func (FfiConverterUint32) Write(writer io.Writer, value uint32) {
	writeUint32(writer, value)
}

func (FfiConverterUint32) Lift(value C.uint32_t) uint32 {
	return uint32(value)
}

func (FfiConverterUint32) Read(reader io.Reader) uint32 {
	return readUint32(reader)
}

type FfiDestroyerUint32 struct{}

func (FfiDestroyerUint32) Destroy(_ uint32) {}

type FfiConverterUint64 struct{}

var FfiConverterUint64INSTANCE = FfiConverterUint64{}

func (FfiConverterUint64) Lower(value uint64) C.uint64_t {
	return C.uint64_t(value)
}

func (FfiConverterUint64) Write(writer io.Writer, value uint64) {
	writeUint64(writer, value)
}

func (FfiConverterUint64) Lift(value C.uint64_t) uint64 {
	return uint64(value)
}

func (FfiConverterUint64) Read(reader io.Reader) uint64 {
	return readUint64(reader)
}

type FfiDestroyerUint64 struct{}

func (FfiDestroyerUint64) Destroy(_ uint64) {}

type FfiConverterString struct{}

var FfiConverterStringINSTANCE = FfiConverterString{}

func (FfiConverterString) Lift(rb RustBufferI) string {
	defer rb.Free()
	reader := rb.AsReader()
	b, err := io.ReadAll(reader)
	if err != nil {
		panic(fmt.Errorf("reading reader: %w", err))
	}
	return string(b)
}

func (FfiConverterString) Read(reader io.Reader) string {
	length := readInt32(reader)
	buffer := make([]byte, length)
	read_length, err := reader.Read(buffer)
	if err != nil {
		panic(err)
	}
	if read_length != int(length) {
		panic(fmt.Errorf("bad read length when reading string, expected %d, read %d", length, read_length))
	}
	return string(buffer)
}

func (FfiConverterString) Lower(value string) C.RustBuffer {
	return stringToRustBuffer(value)
}

func (FfiConverterString) Write(writer io.Writer, value string) {
	if len(value) > math.MaxInt32 {
		panic("String is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	write_length, err := io.WriteString(writer, value)
	if err != nil {
		panic(err)
	}
	if write_length != len(value) {
		panic(fmt.Errorf("bad write length when writing string, expected %d, written %d", len(value), write_length))
	}
}

type FfiDestroyerString struct{}

func (FfiDestroyerString) Destroy(_ string) {}

type FfiConverterBytes struct{}

var FfiConverterBytesINSTANCE = FfiConverterBytes{}

func (c FfiConverterBytes) Lower(value []byte) C.RustBuffer {
	return LowerIntoRustBuffer[[]byte](c, value)
}

func (c FfiConverterBytes) Write(writer io.Writer, value []byte) {
	if len(value) > math.MaxInt32 {
		panic("[]byte is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	write_length, err := writer.Write(value)
	if err != nil {
		panic(err)
	}
	if write_length != len(value) {
		panic(fmt.Errorf("bad write length when writing []byte, expected %d, written %d", len(value), write_length))
	}
}

func (c FfiConverterBytes) Lift(rb RustBufferI) []byte {
	return LiftFromRustBuffer[[]byte](c, rb)
}

func (c FfiConverterBytes) Read(reader io.Reader) []byte {
	length := readInt32(reader)
	buffer := make([]byte, length)
	read_length, err := reader.Read(buffer)
	if err != nil {
		panic(err)
	}
	if read_length != int(length) {
		panic(fmt.Errorf("bad read length when reading []byte, expected %d, read %d", length, read_length))
	}
	return buffer
}

type FfiDestroyerBytes struct{}

func (FfiDestroyerBytes) Destroy(_ []byte) {}

// Below is an implementation of synchronization requirements outlined in the link.
// https://github.com/mozilla/uniffi-rs/blob/0dc031132d9493ca812c3af6e7dd60ad2ea95bf0/uniffi_bindgen/src/bindings/kotlin/templates/ObjectRuntime.kt#L31

type FfiObject struct {
	pointer       unsafe.Pointer
	callCounter   atomic.Int64
	cloneFunction func(unsafe.Pointer, *C.RustCallStatus) unsafe.Pointer
	freeFunction  func(unsafe.Pointer, *C.RustCallStatus)
	destroyed     atomic.Bool
}

func newFfiObject(
	pointer unsafe.Pointer,
	cloneFunction func(unsafe.Pointer, *C.RustCallStatus) unsafe.Pointer,
	freeFunction func(unsafe.Pointer, *C.RustCallStatus),
) FfiObject {
	return FfiObject{
		pointer:       pointer,
		cloneFunction: cloneFunction,
		freeFunction:  freeFunction,
	}
}

func (ffiObject *FfiObject) incrementPointer(debugName string) unsafe.Pointer {
	for {
		counter := ffiObject.callCounter.Load()
		if counter <= -1 {
			panic(fmt.Errorf("%v object has already been destroyed", debugName))
		}
		if counter == math.MaxInt64 {
			panic(fmt.Errorf("%v object call counter would overflow", debugName))
		}
		if ffiObject.callCounter.CompareAndSwap(counter, counter+1) {
			break
		}
	}

	return rustCall(func(status *C.RustCallStatus) unsafe.Pointer {
		return ffiObject.cloneFunction(ffiObject.pointer, status)
	})
}

func (ffiObject *FfiObject) decrementPointer() {
	if ffiObject.callCounter.Add(-1) == -1 {
		ffiObject.freeRustArcPtr()
	}
}

func (ffiObject *FfiObject) destroy() {
	if ffiObject.destroyed.CompareAndSwap(false, true) {
		if ffiObject.callCounter.Add(-1) == -1 {
			ffiObject.freeRustArcPtr()
		}
	}
}

func (ffiObject *FfiObject) freeRustArcPtr() {
	rustCall(func(status *C.RustCallStatus) int32 {
		ffiObject.freeFunction(ffiObject.pointer, status)
		return 0
	})
}

type ElStackIssueConfigInterface interface {
}
type ElStackIssueConfig struct {
	ffiObject FfiObject
}

func NewElStackIssueConfig(elIssuerUrlPrefix string, elIssuerPubKey []byte, clientId string) *ElStackIssueConfig {
	return FfiConverterElStackIssueConfigINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_el_stack_fn_constructor_elstackissueconfig_new(FfiConverterStringINSTANCE.Lower(elIssuerUrlPrefix), FfiConverterBytesINSTANCE.Lower(elIssuerPubKey), FfiConverterStringINSTANCE.Lower(clientId), _uniffiStatus)
	}))
}

func (object *ElStackIssueConfig) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterElStackIssueConfig struct{}

var FfiConverterElStackIssueConfigINSTANCE = FfiConverterElStackIssueConfig{}

func (c FfiConverterElStackIssueConfig) Lift(pointer unsafe.Pointer) *ElStackIssueConfig {
	result := &ElStackIssueConfig{
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_el_stack_fn_clone_elstackissueconfig(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_el_stack_fn_free_elstackissueconfig(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*ElStackIssueConfig).Destroy)
	return result
}

func (c FfiConverterElStackIssueConfig) Read(reader io.Reader) *ElStackIssueConfig {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterElStackIssueConfig) Lower(value *ElStackIssueConfig) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*ElStackIssueConfig")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterElStackIssueConfig) Write(writer io.Writer, value *ElStackIssueConfig) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerElStackIssueConfig struct{}

func (_ FfiDestroyerElStackIssueConfig) Destroy(value *ElStackIssueConfig) {
	value.Destroy()
}

type ElStackProductConfigInterface interface {
}
type ElStackProductConfig struct {
	ffiObject FfiObject
}

func NewElStackProductConfig(productName string, productVersion string, os string, caCert string, mtu uint64) *ElStackProductConfig {
	return FfiConverterElStackProductConfigINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_el_stack_fn_constructor_elstackproductconfig_new(FfiConverterStringINSTANCE.Lower(productName), FfiConverterStringINSTANCE.Lower(productVersion), FfiConverterStringINSTANCE.Lower(os), FfiConverterStringINSTANCE.Lower(caCert), FfiConverterUint64INSTANCE.Lower(mtu), _uniffiStatus)
	}))
}

func (object *ElStackProductConfig) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterElStackProductConfig struct{}

var FfiConverterElStackProductConfigINSTANCE = FfiConverterElStackProductConfig{}

func (c FfiConverterElStackProductConfig) Lift(pointer unsafe.Pointer) *ElStackProductConfig {
	result := &ElStackProductConfig{
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_el_stack_fn_clone_elstackproductconfig(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_el_stack_fn_free_elstackproductconfig(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*ElStackProductConfig).Destroy)
	return result
}

func (c FfiConverterElStackProductConfig) Read(reader io.Reader) *ElStackProductConfig {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterElStackProductConfig) Lower(value *ElStackProductConfig) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*ElStackProductConfig")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterElStackProductConfig) Write(writer io.Writer, value *ElStackProductConfig) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerElStackProductConfig struct{}

func (_ FfiDestroyerElStackProductConfig) Destroy(value *ElStackProductConfig) {
	value.Destroy()
}

type ElStackSocketBufferConfigInterface interface {
}
type ElStackSocketBufferConfig struct {
	ffiObject FfiObject
}

func NewElStackSocketBufferConfig(maxBurstSize uint64, tcpBuffSize *uint64, udpBuffSize *uint64, udpMetaSize *uint64) *ElStackSocketBufferConfig {
	return FfiConverterElStackSocketBufferConfigINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_el_stack_fn_constructor_elstacksocketbufferconfig_new(FfiConverterUint64INSTANCE.Lower(maxBurstSize), FfiConverterOptionalUint64INSTANCE.Lower(tcpBuffSize), FfiConverterOptionalUint64INSTANCE.Lower(udpBuffSize), FfiConverterOptionalUint64INSTANCE.Lower(udpMetaSize), _uniffiStatus)
	}))
}

func (object *ElStackSocketBufferConfig) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterElStackSocketBufferConfig struct{}

var FfiConverterElStackSocketBufferConfigINSTANCE = FfiConverterElStackSocketBufferConfig{}

func (c FfiConverterElStackSocketBufferConfig) Lift(pointer unsafe.Pointer) *ElStackSocketBufferConfig {
	result := &ElStackSocketBufferConfig{
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_el_stack_fn_clone_elstacksocketbufferconfig(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_el_stack_fn_free_elstacksocketbufferconfig(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*ElStackSocketBufferConfig).Destroy)
	return result
}

func (c FfiConverterElStackSocketBufferConfig) Read(reader io.Reader) *ElStackSocketBufferConfig {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterElStackSocketBufferConfig) Lower(value *ElStackSocketBufferConfig) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*ElStackSocketBufferConfig")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterElStackSocketBufferConfig) Write(writer io.Writer, value *ElStackSocketBufferConfig) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerElStackSocketBufferConfig struct{}

func (_ FfiDestroyerElStackSocketBufferConfig) Destroy(value *ElStackSocketBufferConfig) {
	value.Destroy()
}

type ElStackVcConfigInterface interface {
}
type ElStackVcConfig struct {
	ffiObject FfiObject
}

func NewElStackVcConfig(elVc string, elVcPrivKey string, elIssuerPubKey string) *ElStackVcConfig {
	return FfiConverterElStackVcConfigINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_el_stack_fn_constructor_elstackvcconfig_new(FfiConverterStringINSTANCE.Lower(elVc), FfiConverterStringINSTANCE.Lower(elVcPrivKey), FfiConverterStringINSTANCE.Lower(elIssuerPubKey), _uniffiStatus)
	}))
}

func (object *ElStackVcConfig) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterElStackVcConfig struct{}

var FfiConverterElStackVcConfigINSTANCE = FfiConverterElStackVcConfig{}

func (c FfiConverterElStackVcConfig) Lift(pointer unsafe.Pointer) *ElStackVcConfig {
	result := &ElStackVcConfig{
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_el_stack_fn_clone_elstackvcconfig(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_el_stack_fn_free_elstackvcconfig(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*ElStackVcConfig).Destroy)
	return result
}

func (c FfiConverterElStackVcConfig) Read(reader io.Reader) *ElStackVcConfig {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterElStackVcConfig) Lower(value *ElStackVcConfig) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*ElStackVcConfig")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterElStackVcConfig) Write(writer io.Writer, value *ElStackVcConfig) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerElStackVcConfig struct{}

func (_ FfiDestroyerElStackVcConfig) Destroy(value *ElStackVcConfig) {
	value.Destroy()
}

type ElStackVpnConfigInterface interface {
}
type ElStackVpnConfig struct {
	ffiObject FfiObject
}

func NewElStackVpnConfig(serverHost string, serverServ string, antiOverlap string, recvTimeout uint64, keepaliveInterval uint64, connectionType ElStackVpnConnectionType) *ElStackVpnConfig {
	return FfiConverterElStackVpnConfigINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_el_stack_fn_constructor_elstackvpnconfig_new(FfiConverterStringINSTANCE.Lower(serverHost), FfiConverterStringINSTANCE.Lower(serverServ), FfiConverterStringINSTANCE.Lower(antiOverlap), FfiConverterUint64INSTANCE.Lower(recvTimeout), FfiConverterUint64INSTANCE.Lower(keepaliveInterval), FfiConverterElStackVpnConnectionTypeINSTANCE.Lower(connectionType), _uniffiStatus)
	}))
}

func (object *ElStackVpnConfig) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterElStackVpnConfig struct{}

var FfiConverterElStackVpnConfigINSTANCE = FfiConverterElStackVpnConfig{}

func (c FfiConverterElStackVpnConfig) Lift(pointer unsafe.Pointer) *ElStackVpnConfig {
	result := &ElStackVpnConfig{
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_el_stack_fn_clone_elstackvpnconfig(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_el_stack_fn_free_elstackvpnconfig(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*ElStackVpnConfig).Destroy)
	return result
}

func (c FfiConverterElStackVpnConfig) Read(reader io.Reader) *ElStackVpnConfig {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterElStackVpnConfig) Lower(value *ElStackVpnConfig) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*ElStackVpnConfig")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterElStackVpnConfig) Write(writer io.Writer, value *ElStackVpnConfig) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerElStackVpnConfig struct{}

func (_ FfiDestroyerElStackVpnConfig) Destroy(value *ElStackVpnConfig) {
	value.Destroy()
}

type TcpListenerInterface interface {
	Accept(timeoutSecs uint64) (*TcpStream, *SocketError)
	BindAddr() string
}
type TcpListener struct {
	ffiObject FfiObject
}

func (_self *TcpListener) Accept(timeoutSecs uint64) (*TcpStream, *SocketError) {
	_pointer := _self.ffiObject.incrementPointer("*TcpListener")
	defer _self.ffiObject.decrementPointer()
	res, err := uniffiRustCallAsync[SocketError](
		FfiConverterSocketErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) unsafe.Pointer {
			res := C.ffi_el_stack_rust_future_complete_pointer(handle, status)
			return res
		},
		// liftFn
		func(ffi unsafe.Pointer) *TcpStream {
			return FfiConverterTcpStreamINSTANCE.Lift(ffi)
		},
		C.uniffi_el_stack_fn_method_tcplistener_accept(
			_pointer, FfiConverterUint64INSTANCE.Lower(timeoutSecs)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_el_stack_rust_future_poll_pointer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_el_stack_rust_future_free_pointer(handle)
		},
	)

	return res, err
}

func (_self *TcpListener) BindAddr() string {
	_pointer := _self.ffiObject.incrementPointer("*TcpListener")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterStringINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_el_stack_fn_method_tcplistener_bind_addr(
				_pointer, _uniffiStatus),
		}
	}))
}
func (object *TcpListener) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterTcpListener struct{}

var FfiConverterTcpListenerINSTANCE = FfiConverterTcpListener{}

func (c FfiConverterTcpListener) Lift(pointer unsafe.Pointer) *TcpListener {
	result := &TcpListener{
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_el_stack_fn_clone_tcplistener(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_el_stack_fn_free_tcplistener(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*TcpListener).Destroy)
	return result
}

func (c FfiConverterTcpListener) Read(reader io.Reader) *TcpListener {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterTcpListener) Lower(value *TcpListener) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*TcpListener")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterTcpListener) Write(writer io.Writer, value *TcpListener) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerTcpListener struct{}

func (_ FfiDestroyerTcpListener) Destroy(value *TcpListener) {
	value.Destroy()
}

type TcpStreamInterface interface {
	Close()
	LocalAddr() string
	PeerAddr() string
	Recv(timeoutSecs uint64) ([]byte, *SocketError)
	Send(buf []byte, timeoutSecs uint64) *SocketError
}
type TcpStream struct {
	ffiObject FfiObject
}

func (_self *TcpStream) Close() {
	_pointer := _self.ffiObject.incrementPointer("*TcpStream")
	defer _self.ffiObject.decrementPointer()
	uniffiRustCallAsync[struct{}](
		nil,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) struct{} {
			C.ffi_el_stack_rust_future_complete_void(handle, status)
			return struct{}{}
		},
		// liftFn
		func(_ struct{}) struct{} { return struct{}{} },
		C.uniffi_el_stack_fn_method_tcpstream_close(
			_pointer),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_el_stack_rust_future_poll_void(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_el_stack_rust_future_free_void(handle)
		},
	)

}

func (_self *TcpStream) LocalAddr() string {
	_pointer := _self.ffiObject.incrementPointer("*TcpStream")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterStringINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_el_stack_fn_method_tcpstream_local_addr(
				_pointer, _uniffiStatus),
		}
	}))
}

func (_self *TcpStream) PeerAddr() string {
	_pointer := _self.ffiObject.incrementPointer("*TcpStream")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterStringINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_el_stack_fn_method_tcpstream_peer_addr(
				_pointer, _uniffiStatus),
		}
	}))
}

func (_self *TcpStream) Recv(timeoutSecs uint64) ([]byte, *SocketError) {
	_pointer := _self.ffiObject.incrementPointer("*TcpStream")
	defer _self.ffiObject.decrementPointer()
	res, err := uniffiRustCallAsync[SocketError](
		FfiConverterSocketErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) RustBufferI {
			res := C.ffi_el_stack_rust_future_complete_rust_buffer(handle, status)
			return GoRustBuffer{
				inner: res,
			}
		},
		// liftFn
		func(ffi RustBufferI) []byte {
			return FfiConverterBytesINSTANCE.Lift(ffi)
		},
		C.uniffi_el_stack_fn_method_tcpstream_recv(
			_pointer, FfiConverterUint64INSTANCE.Lower(timeoutSecs)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_el_stack_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_el_stack_rust_future_free_rust_buffer(handle)
		},
	)

	return res, err
}

// RecvSafe は panic をキャッチしてエラーで返すラッパーです
func (_self *TcpStream) RecvSafe(timeoutSecs uint64) (data []byte, serr error) {
	defer func() {
		if r := recover(); r != nil {
			var e error
			switch x := r.(type) {
			case error:
				e = x
			default:
				e = fmt.Errorf("%v", x)
			}
			// ここで「EOF」系はio.EOFで返す！
			if e == io.EOF || e.Error() == "EOF" {
				data, serr = nil, io.EOF
			} else {
				data, serr = nil, &SocketError{err: e}
			}
		}
	}()
	data, socketErr := _self.Recv(timeoutSecs)
	if socketErr != nil {
		return data, socketErr
	}
	if len(data) == 0 {
		// 受信データ長が0 = EOF
		return nil, io.EOF
	}
	return data, nil
}

func (_self *TcpStream) Send(buf []byte, timeoutSecs uint64) *SocketError {
	_pointer := _self.ffiObject.incrementPointer("*TcpStream")
	defer _self.ffiObject.decrementPointer()
	_, err := uniffiRustCallAsync[SocketError](
		FfiConverterSocketErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) struct{} {
			C.ffi_el_stack_rust_future_complete_void(handle, status)
			return struct{}{}
		},
		// liftFn
		func(_ struct{}) struct{} { return struct{}{} },
		C.uniffi_el_stack_fn_method_tcpstream_send(
			_pointer, FfiConverterBytesINSTANCE.Lower(buf), FfiConverterUint64INSTANCE.Lower(timeoutSecs)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_el_stack_rust_future_poll_void(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_el_stack_rust_future_free_void(handle)
		},
	)

	return err
}
func (object *TcpStream) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterTcpStream struct{}

var FfiConverterTcpStreamINSTANCE = FfiConverterTcpStream{}

func (c FfiConverterTcpStream) Lift(pointer unsafe.Pointer) *TcpStream {
	result := &TcpStream{
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_el_stack_fn_clone_tcpstream(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_el_stack_fn_free_tcpstream(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*TcpStream).Destroy)
	return result
}

func (c FfiConverterTcpStream) Read(reader io.Reader) *TcpStream {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterTcpStream) Lower(value *TcpStream) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*TcpStream")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterTcpStream) Write(writer io.Writer, value *TcpStream) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerTcpStream struct{}

func (_ FfiDestroyerTcpStream) Destroy(value *TcpStream) {
	value.Destroy()
}

type TlsStreamInterface interface {
	Close()
	LocalAddr() string
	PeerAddr() string
	Recv(timeoutSecs uint64) ([]byte, *SocketError)
	Send(buf []byte, timeoutSecs uint64) *SocketError
}
type TlsStream struct {
	ffiObject FfiObject
}

func (_self *TlsStream) Close() {
	_pointer := _self.ffiObject.incrementPointer("*TlsStream")
	defer _self.ffiObject.decrementPointer()
	uniffiRustCallAsync[struct{}](
		nil,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) struct{} {
			C.ffi_el_stack_rust_future_complete_void(handle, status)
			return struct{}{}
		},
		// liftFn
		func(_ struct{}) struct{} { return struct{}{} },
		C.uniffi_el_stack_fn_method_tlsstream_close(
			_pointer),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_el_stack_rust_future_poll_void(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_el_stack_rust_future_free_void(handle)
		},
	)

}

func (_self *TlsStream) LocalAddr() string {
	_pointer := _self.ffiObject.incrementPointer("*TlsStream")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterStringINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_el_stack_fn_method_tlsstream_local_addr(
				_pointer, _uniffiStatus),
		}
	}))
}

func (_self *TlsStream) PeerAddr() string {
	_pointer := _self.ffiObject.incrementPointer("*TlsStream")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterStringINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_el_stack_fn_method_tlsstream_peer_addr(
				_pointer, _uniffiStatus),
		}
	}))
}

func (_self *TlsStream) Recv(timeoutSecs uint64) ([]byte, *SocketError) {
	_pointer := _self.ffiObject.incrementPointer("*TlsStream")
	defer _self.ffiObject.decrementPointer()
	res, err := uniffiRustCallAsync[SocketError](
		FfiConverterSocketErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) RustBufferI {
			res := C.ffi_el_stack_rust_future_complete_rust_buffer(handle, status)
			return GoRustBuffer{
				inner: res,
			}
		},
		// liftFn
		func(ffi RustBufferI) []byte {
			return FfiConverterBytesINSTANCE.Lift(ffi)
		},
		C.uniffi_el_stack_fn_method_tlsstream_recv(
			_pointer, FfiConverterUint64INSTANCE.Lower(timeoutSecs)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_el_stack_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_el_stack_rust_future_free_rust_buffer(handle)
		},
	)

	return res, err
}

// Recv は内部 panic をキャッチして *StreamError で返すラッパーです
func (_self *TlsStream) RecvSafe(timeoutSecs uint64) (data []byte, serr error) {
	defer func() {
		if r := recover(); r != nil {
			var e error
			switch x := r.(type) {
			case error:
				e = x
			default:
				e = fmt.Errorf("%v", x)
			}
			// ここで「EOF」系はio.EOFで返す！
			if e == io.EOF || e.Error() == "EOF" {
				data, serr = nil, io.EOF
			} else {
				data, serr = nil, &SocketError{err: e}
			}
		}
	}()
	data, socketErr := _self.Recv(timeoutSecs)
	if socketErr != nil {
		return data, socketErr
	}
	if len(data) == 0 {
		// 受信データ長が0 = EOF
		return nil, io.EOF
	}
	return data, nil
}

func (_self *TlsStream) Send(buf []byte, timeoutSecs uint64) *SocketError {
	_pointer := _self.ffiObject.incrementPointer("*TlsStream")
	defer _self.ffiObject.decrementPointer()
	_, err := uniffiRustCallAsync[SocketError](
		FfiConverterSocketErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) struct{} {
			C.ffi_el_stack_rust_future_complete_void(handle, status)
			return struct{}{}
		},
		// liftFn
		func(_ struct{}) struct{} { return struct{}{} },
		C.uniffi_el_stack_fn_method_tlsstream_send(
			_pointer, FfiConverterBytesINSTANCE.Lower(buf), FfiConverterUint64INSTANCE.Lower(timeoutSecs)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_el_stack_rust_future_poll_void(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_el_stack_rust_future_free_void(handle)
		},
	)

	return err
}
func (object *TlsStream) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterTlsStream struct{}

var FfiConverterTlsStreamINSTANCE = FfiConverterTlsStream{}

func (c FfiConverterTlsStream) Lift(pointer unsafe.Pointer) *TlsStream {
	result := &TlsStream{
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_el_stack_fn_clone_tlsstream(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_el_stack_fn_free_tlsstream(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*TlsStream).Destroy)
	return result
}

func (c FfiConverterTlsStream) Read(reader io.Reader) *TlsStream {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterTlsStream) Lower(value *TlsStream) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*TlsStream")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterTlsStream) Write(writer io.Writer, value *TlsStream) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerTlsStream struct{}

func (_ FfiDestroyerTlsStream) Destroy(value *TlsStream) {
	value.Destroy()
}

type UdpSocketInterface interface {
	LocalAddr() string
	RecvFrom(timeoutSecs uint64) (RecvFromResult, *SocketError)
	SendTo(buf []byte, target string, timeoutSecs uint64) (uint32, *SocketError)
}
type UdpSocket struct {
	ffiObject FfiObject
}

func (_self *UdpSocket) LocalAddr() string {
	_pointer := _self.ffiObject.incrementPointer("*UdpSocket")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterStringINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_el_stack_fn_method_udpsocket_local_addr(
				_pointer, _uniffiStatus),
		}
	}))
}

func (_self *UdpSocket) RecvFrom(timeoutSecs uint64) (RecvFromResult, *SocketError) {
	_pointer := _self.ffiObject.incrementPointer("*UdpSocket")
	defer _self.ffiObject.decrementPointer()
	res, err := uniffiRustCallAsync[SocketError](
		FfiConverterSocketErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) RustBufferI {
			res := C.ffi_el_stack_rust_future_complete_rust_buffer(handle, status)
			return GoRustBuffer{
				inner: res,
			}
		},
		// liftFn
		func(ffi RustBufferI) RecvFromResult {
			return FfiConverterRecvFromResultINSTANCE.Lift(ffi)
		},
		C.uniffi_el_stack_fn_method_udpsocket_recv_from(
			_pointer, FfiConverterUint64INSTANCE.Lower(timeoutSecs)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_el_stack_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_el_stack_rust_future_free_rust_buffer(handle)
		},
	)

	return res, err
}

func (_self *UdpSocket) SendTo(buf []byte, target string, timeoutSecs uint64) (uint32, *SocketError) {
	_pointer := _self.ffiObject.incrementPointer("*UdpSocket")
	defer _self.ffiObject.decrementPointer()
	res, err := uniffiRustCallAsync[SocketError](
		FfiConverterSocketErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) C.uint32_t {
			res := C.ffi_el_stack_rust_future_complete_u32(handle, status)
			return res
		},
		// liftFn
		func(ffi C.uint32_t) uint32 {
			return FfiConverterUint32INSTANCE.Lift(ffi)
		},
		C.uniffi_el_stack_fn_method_udpsocket_send_to(
			_pointer, FfiConverterBytesINSTANCE.Lower(buf), FfiConverterStringINSTANCE.Lower(target), FfiConverterUint64INSTANCE.Lower(timeoutSecs)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_el_stack_rust_future_poll_u32(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_el_stack_rust_future_free_u32(handle)
		},
	)

	return res, err
}
func (object *UdpSocket) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterUdpSocket struct{}

var FfiConverterUdpSocketINSTANCE = FfiConverterUdpSocket{}

func (c FfiConverterUdpSocket) Lift(pointer unsafe.Pointer) *UdpSocket {
	result := &UdpSocket{
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_el_stack_fn_clone_udpsocket(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_el_stack_fn_free_udpsocket(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*UdpSocket).Destroy)
	return result
}

func (c FfiConverterUdpSocket) Read(reader io.Reader) *UdpSocket {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterUdpSocket) Lower(value *UdpSocket) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*UdpSocket")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterUdpSocket) Write(writer io.Writer, value *UdpSocket) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerUdpSocket struct{}

func (_ FfiDestroyerUdpSocket) Destroy(value *UdpSocket) {
	value.Destroy()
}

type RecvFromResult struct {
	Buf      []byte
	FromAddr string
}

func (r *RecvFromResult) Destroy() {
	FfiDestroyerBytes{}.Destroy(r.Buf)
	FfiDestroyerString{}.Destroy(r.FromAddr)
}

type FfiConverterRecvFromResult struct{}

var FfiConverterRecvFromResultINSTANCE = FfiConverterRecvFromResult{}

func (c FfiConverterRecvFromResult) Lift(rb RustBufferI) RecvFromResult {
	return LiftFromRustBuffer[RecvFromResult](c, rb)
}

func (c FfiConverterRecvFromResult) Read(reader io.Reader) RecvFromResult {
	return RecvFromResult{
		FfiConverterBytesINSTANCE.Read(reader),
		FfiConverterStringINSTANCE.Read(reader),
	}
}

func (c FfiConverterRecvFromResult) Lower(value RecvFromResult) C.RustBuffer {
	return LowerIntoRustBuffer[RecvFromResult](c, value)
}

func (c FfiConverterRecvFromResult) Write(writer io.Writer, value RecvFromResult) {
	FfiConverterBytesINSTANCE.Write(writer, value.Buf)
	FfiConverterStringINSTANCE.Write(writer, value.FromAddr)
}

type FfiDestroyerRecvFromResult struct{}

func (_ FfiDestroyerRecvFromResult) Destroy(value RecvFromResult) {
	value.Destroy()
}

type ConnectionError struct {
	err error
}

// Convience method to turn *ConnectionError into error
// Avoiding treating nil pointer as non nil error interface
func (err *ConnectionError) AsError() error {
	if err == nil {
		return nil
	} else {
		return err
	}
}

func (err ConnectionError) Error() string {
	return fmt.Sprintf("ConnectionError: %s", err.err.Error())
}

func (err ConnectionError) Unwrap() error {
	return err.err
}

// Err* are used for checking error type with `errors.Is`
var ErrConnectionErrorNameResolvError = fmt.Errorf("ConnectionErrorNameResolvError")
var ErrConnectionErrorInvalidHostnameError = fmt.Errorf("ConnectionErrorInvalidHostnameError")
var ErrConnectionErrorTcpConnectError = fmt.Errorf("ConnectionErrorTcpConnectError")
var ErrConnectionErrorTlsHandshakeError = fmt.Errorf("ConnectionErrorTlsHandshakeError")
var ErrConnectionErrorQuicConnectError = fmt.Errorf("ConnectionErrorQuicConnectError")
var ErrConnectionErrorThereIsNoIpAddrError = fmt.Errorf("ConnectionErrorThereIsNoIpAddrError")
var ErrConnectionErrorInvalidIpAddrFormatError = fmt.Errorf("ConnectionErrorInvalidIpAddrFormatError")
var ErrConnectionErrorPrepareError = fmt.Errorf("ConnectionErrorPrepareError")
var ErrConnectionErrorFormatError = fmt.Errorf("ConnectionErrorFormatError")
var ErrConnectionErrorServerBusyError = fmt.Errorf("ConnectionErrorServerBusyError")
var ErrConnectionErrorMaintenanceError = fmt.Errorf("ConnectionErrorMaintenanceError")
var ErrConnectionErrorRequestNotSupportedError = fmt.Errorf("ConnectionErrorRequestNotSupportedError")
var ErrConnectionErrorUnsupportedClientError = fmt.Errorf("ConnectionErrorUnsupportedClientError")
var ErrConnectionErrorIncorrectRequestError = fmt.Errorf("ConnectionErrorIncorrectRequestError")
var ErrConnectionErrorAuthenticationError = fmt.Errorf("ConnectionErrorAuthenticationError")
var ErrConnectionErrorExceededConnectionForSameAccountError = fmt.Errorf("ConnectionErrorExceededConnectionForSameAccountError")
var ErrConnectionErrorFixAddressInUseError = fmt.Errorf("ConnectionErrorFixAddressInUseError")
var ErrConnectionErrorIncorrectProtocolTransitionError = fmt.Errorf("ConnectionErrorIncorrectProtocolTransitionError")
var ErrConnectionErrorFailedToGetAddressError = fmt.Errorf("ConnectionErrorFailedToGetAddressError")
var ErrConnectionErrorInternalServerError = fmt.Errorf("ConnectionErrorInternalServerError")
var ErrConnectionErrorNextRequestIsNoneError = fmt.Errorf("ConnectionErrorNextRequestIsNoneError")
var ErrConnectionErrorSendIoError = fmt.Errorf("ConnectionErrorSendIoError")
var ErrConnectionErrorRecvIoError = fmt.Errorf("ConnectionErrorRecvIoError")
var ErrConnectionErrorTimeoutError = fmt.Errorf("ConnectionErrorTimeoutError")
var ErrConnectionErrorElProtocolUnknownError = fmt.Errorf("ConnectionErrorElProtocolUnknownError")
var ErrConnectionErrorInvalidElvpFormat = fmt.Errorf("ConnectionErrorInvalidElvpFormat")
var ErrConnectionErrorRecvedZero = fmt.Errorf("ConnectionErrorRecvedZero")
var ErrConnectionErrorStateTransitionError = fmt.Errorf("ConnectionErrorStateTransitionError")
var ErrConnectionErrorConvertError = fmt.Errorf("ConnectionErrorConvertError")
var ErrConnectionErrorNotInitializedError = fmt.Errorf("ConnectionErrorNotInitializedError")

// Variant structs
type ConnectionErrorNameResolvError struct {
}

func NewConnectionErrorNameResolvError() *ConnectionError {
	return &ConnectionError{err: &ConnectionErrorNameResolvError{}}
}

func (e ConnectionErrorNameResolvError) destroy() {
}

func (err ConnectionErrorNameResolvError) Error() string {
	return fmt.Sprint("NameResolvError")
}

func (self ConnectionErrorNameResolvError) Is(target error) bool {
	return target == ErrConnectionErrorNameResolvError
}

type ConnectionErrorInvalidHostnameError struct {
}

func NewConnectionErrorInvalidHostnameError() *ConnectionError {
	return &ConnectionError{err: &ConnectionErrorInvalidHostnameError{}}
}

func (e ConnectionErrorInvalidHostnameError) destroy() {
}

func (err ConnectionErrorInvalidHostnameError) Error() string {
	return fmt.Sprint("InvalidHostnameError")
}

func (self ConnectionErrorInvalidHostnameError) Is(target error) bool {
	return target == ErrConnectionErrorInvalidHostnameError
}

type ConnectionErrorTcpConnectError struct {
}

func NewConnectionErrorTcpConnectError() *ConnectionError {
	return &ConnectionError{err: &ConnectionErrorTcpConnectError{}}
}

func (e ConnectionErrorTcpConnectError) destroy() {
}

func (err ConnectionErrorTcpConnectError) Error() string {
	return fmt.Sprint("TcpConnectError")
}

func (self ConnectionErrorTcpConnectError) Is(target error) bool {
	return target == ErrConnectionErrorTcpConnectError
}

type ConnectionErrorTlsHandshakeError struct {
}

func NewConnectionErrorTlsHandshakeError() *ConnectionError {
	return &ConnectionError{err: &ConnectionErrorTlsHandshakeError{}}
}

func (e ConnectionErrorTlsHandshakeError) destroy() {
}

func (err ConnectionErrorTlsHandshakeError) Error() string {
	return fmt.Sprint("TlsHandshakeError")
}

func (self ConnectionErrorTlsHandshakeError) Is(target error) bool {
	return target == ErrConnectionErrorTlsHandshakeError
}

type ConnectionErrorQuicConnectError struct {
}

func NewConnectionErrorQuicConnectError() *ConnectionError {
	return &ConnectionError{err: &ConnectionErrorQuicConnectError{}}
}

func (e ConnectionErrorQuicConnectError) destroy() {
}

func (err ConnectionErrorQuicConnectError) Error() string {
	return fmt.Sprint("QuicConnectError")
}

func (self ConnectionErrorQuicConnectError) Is(target error) bool {
	return target == ErrConnectionErrorQuicConnectError
}

type ConnectionErrorThereIsNoIpAddrError struct {
}

func NewConnectionErrorThereIsNoIpAddrError() *ConnectionError {
	return &ConnectionError{err: &ConnectionErrorThereIsNoIpAddrError{}}
}

func (e ConnectionErrorThereIsNoIpAddrError) destroy() {
}

func (err ConnectionErrorThereIsNoIpAddrError) Error() string {
	return fmt.Sprint("ThereIsNoIpAddrError")
}

func (self ConnectionErrorThereIsNoIpAddrError) Is(target error) bool {
	return target == ErrConnectionErrorThereIsNoIpAddrError
}

type ConnectionErrorInvalidIpAddrFormatError struct {
}

func NewConnectionErrorInvalidIpAddrFormatError() *ConnectionError {
	return &ConnectionError{err: &ConnectionErrorInvalidIpAddrFormatError{}}
}

func (e ConnectionErrorInvalidIpAddrFormatError) destroy() {
}

func (err ConnectionErrorInvalidIpAddrFormatError) Error() string {
	return fmt.Sprint("InvalidIpAddrFormatError")
}

func (self ConnectionErrorInvalidIpAddrFormatError) Is(target error) bool {
	return target == ErrConnectionErrorInvalidIpAddrFormatError
}

type ConnectionErrorPrepareError struct {
}

func NewConnectionErrorPrepareError() *ConnectionError {
	return &ConnectionError{err: &ConnectionErrorPrepareError{}}
}

func (e ConnectionErrorPrepareError) destroy() {
}

func (err ConnectionErrorPrepareError) Error() string {
	return fmt.Sprint("PrepareError")
}

func (self ConnectionErrorPrepareError) Is(target error) bool {
	return target == ErrConnectionErrorPrepareError
}

type ConnectionErrorFormatError struct {
}

func NewConnectionErrorFormatError() *ConnectionError {
	return &ConnectionError{err: &ConnectionErrorFormatError{}}
}

func (e ConnectionErrorFormatError) destroy() {
}

func (err ConnectionErrorFormatError) Error() string {
	return fmt.Sprint("FormatError")
}

func (self ConnectionErrorFormatError) Is(target error) bool {
	return target == ErrConnectionErrorFormatError
}

type ConnectionErrorServerBusyError struct {
}

func NewConnectionErrorServerBusyError() *ConnectionError {
	return &ConnectionError{err: &ConnectionErrorServerBusyError{}}
}

func (e ConnectionErrorServerBusyError) destroy() {
}

func (err ConnectionErrorServerBusyError) Error() string {
	return fmt.Sprint("ServerBusyError")
}

func (self ConnectionErrorServerBusyError) Is(target error) bool {
	return target == ErrConnectionErrorServerBusyError
}

type ConnectionErrorMaintenanceError struct {
}

func NewConnectionErrorMaintenanceError() *ConnectionError {
	return &ConnectionError{err: &ConnectionErrorMaintenanceError{}}
}

func (e ConnectionErrorMaintenanceError) destroy() {
}

func (err ConnectionErrorMaintenanceError) Error() string {
	return fmt.Sprint("MaintenanceError")
}

func (self ConnectionErrorMaintenanceError) Is(target error) bool {
	return target == ErrConnectionErrorMaintenanceError
}

type ConnectionErrorRequestNotSupportedError struct {
}

func NewConnectionErrorRequestNotSupportedError() *ConnectionError {
	return &ConnectionError{err: &ConnectionErrorRequestNotSupportedError{}}
}

func (e ConnectionErrorRequestNotSupportedError) destroy() {
}

func (err ConnectionErrorRequestNotSupportedError) Error() string {
	return fmt.Sprint("RequestNotSupportedError")
}

func (self ConnectionErrorRequestNotSupportedError) Is(target error) bool {
	return target == ErrConnectionErrorRequestNotSupportedError
}

type ConnectionErrorUnsupportedClientError struct {
}

func NewConnectionErrorUnsupportedClientError() *ConnectionError {
	return &ConnectionError{err: &ConnectionErrorUnsupportedClientError{}}
}

func (e ConnectionErrorUnsupportedClientError) destroy() {
}

func (err ConnectionErrorUnsupportedClientError) Error() string {
	return fmt.Sprint("UnsupportedClientError")
}

func (self ConnectionErrorUnsupportedClientError) Is(target error) bool {
	return target == ErrConnectionErrorUnsupportedClientError
}

type ConnectionErrorIncorrectRequestError struct {
}

func NewConnectionErrorIncorrectRequestError() *ConnectionError {
	return &ConnectionError{err: &ConnectionErrorIncorrectRequestError{}}
}

func (e ConnectionErrorIncorrectRequestError) destroy() {
}

func (err ConnectionErrorIncorrectRequestError) Error() string {
	return fmt.Sprint("IncorrectRequestError")
}

func (self ConnectionErrorIncorrectRequestError) Is(target error) bool {
	return target == ErrConnectionErrorIncorrectRequestError
}

type ConnectionErrorAuthenticationError struct {
}

func NewConnectionErrorAuthenticationError() *ConnectionError {
	return &ConnectionError{err: &ConnectionErrorAuthenticationError{}}
}

func (e ConnectionErrorAuthenticationError) destroy() {
}

func (err ConnectionErrorAuthenticationError) Error() string {
	return fmt.Sprint("AuthenticationError")
}

func (self ConnectionErrorAuthenticationError) Is(target error) bool {
	return target == ErrConnectionErrorAuthenticationError
}

type ConnectionErrorExceededConnectionForSameAccountError struct {
}

func NewConnectionErrorExceededConnectionForSameAccountError() *ConnectionError {
	return &ConnectionError{err: &ConnectionErrorExceededConnectionForSameAccountError{}}
}

func (e ConnectionErrorExceededConnectionForSameAccountError) destroy() {
}

func (err ConnectionErrorExceededConnectionForSameAccountError) Error() string {
	return fmt.Sprint("ExceededConnectionForSameAccountError")
}

func (self ConnectionErrorExceededConnectionForSameAccountError) Is(target error) bool {
	return target == ErrConnectionErrorExceededConnectionForSameAccountError
}

type ConnectionErrorFixAddressInUseError struct {
}

func NewConnectionErrorFixAddressInUseError() *ConnectionError {
	return &ConnectionError{err: &ConnectionErrorFixAddressInUseError{}}
}

func (e ConnectionErrorFixAddressInUseError) destroy() {
}

func (err ConnectionErrorFixAddressInUseError) Error() string {
	return fmt.Sprint("FixAddressInUseError")
}

func (self ConnectionErrorFixAddressInUseError) Is(target error) bool {
	return target == ErrConnectionErrorFixAddressInUseError
}

type ConnectionErrorIncorrectProtocolTransitionError struct {
}

func NewConnectionErrorIncorrectProtocolTransitionError() *ConnectionError {
	return &ConnectionError{err: &ConnectionErrorIncorrectProtocolTransitionError{}}
}

func (e ConnectionErrorIncorrectProtocolTransitionError) destroy() {
}

func (err ConnectionErrorIncorrectProtocolTransitionError) Error() string {
	return fmt.Sprint("IncorrectProtocolTransitionError")
}

func (self ConnectionErrorIncorrectProtocolTransitionError) Is(target error) bool {
	return target == ErrConnectionErrorIncorrectProtocolTransitionError
}

type ConnectionErrorFailedToGetAddressError struct {
}

func NewConnectionErrorFailedToGetAddressError() *ConnectionError {
	return &ConnectionError{err: &ConnectionErrorFailedToGetAddressError{}}
}

func (e ConnectionErrorFailedToGetAddressError) destroy() {
}

func (err ConnectionErrorFailedToGetAddressError) Error() string {
	return fmt.Sprint("FailedToGetAddressError")
}

func (self ConnectionErrorFailedToGetAddressError) Is(target error) bool {
	return target == ErrConnectionErrorFailedToGetAddressError
}

type ConnectionErrorInternalServerError struct {
}

func NewConnectionErrorInternalServerError() *ConnectionError {
	return &ConnectionError{err: &ConnectionErrorInternalServerError{}}
}

func (e ConnectionErrorInternalServerError) destroy() {
}

func (err ConnectionErrorInternalServerError) Error() string {
	return fmt.Sprint("InternalServerError")
}

func (self ConnectionErrorInternalServerError) Is(target error) bool {
	return target == ErrConnectionErrorInternalServerError
}

type ConnectionErrorNextRequestIsNoneError struct {
}

func NewConnectionErrorNextRequestIsNoneError() *ConnectionError {
	return &ConnectionError{err: &ConnectionErrorNextRequestIsNoneError{}}
}

func (e ConnectionErrorNextRequestIsNoneError) destroy() {
}

func (err ConnectionErrorNextRequestIsNoneError) Error() string {
	return fmt.Sprint("NextRequestIsNoneError")
}

func (self ConnectionErrorNextRequestIsNoneError) Is(target error) bool {
	return target == ErrConnectionErrorNextRequestIsNoneError
}

type ConnectionErrorSendIoError struct {
}

func NewConnectionErrorSendIoError() *ConnectionError {
	return &ConnectionError{err: &ConnectionErrorSendIoError{}}
}

func (e ConnectionErrorSendIoError) destroy() {
}

func (err ConnectionErrorSendIoError) Error() string {
	return fmt.Sprint("SendIoError")
}

func (self ConnectionErrorSendIoError) Is(target error) bool {
	return target == ErrConnectionErrorSendIoError
}

type ConnectionErrorRecvIoError struct {
}

func NewConnectionErrorRecvIoError() *ConnectionError {
	return &ConnectionError{err: &ConnectionErrorRecvIoError{}}
}

func (e ConnectionErrorRecvIoError) destroy() {
}

func (err ConnectionErrorRecvIoError) Error() string {
	return fmt.Sprint("RecvIoError")
}

func (self ConnectionErrorRecvIoError) Is(target error) bool {
	return target == ErrConnectionErrorRecvIoError
}

type ConnectionErrorTimeoutError struct {
}

func NewConnectionErrorTimeoutError() *ConnectionError {
	return &ConnectionError{err: &ConnectionErrorTimeoutError{}}
}

func (e ConnectionErrorTimeoutError) destroy() {
}

func (err ConnectionErrorTimeoutError) Error() string {
	return fmt.Sprint("TimeoutError")
}

func (self ConnectionErrorTimeoutError) Is(target error) bool {
	return target == ErrConnectionErrorTimeoutError
}

type ConnectionErrorElProtocolUnknownError struct {
}

func NewConnectionErrorElProtocolUnknownError() *ConnectionError {
	return &ConnectionError{err: &ConnectionErrorElProtocolUnknownError{}}
}

func (e ConnectionErrorElProtocolUnknownError) destroy() {
}

func (err ConnectionErrorElProtocolUnknownError) Error() string {
	return fmt.Sprint("ElProtocolUnknownError")
}

func (self ConnectionErrorElProtocolUnknownError) Is(target error) bool {
	return target == ErrConnectionErrorElProtocolUnknownError
}

type ConnectionErrorInvalidElvpFormat struct {
}

func NewConnectionErrorInvalidElvpFormat() *ConnectionError {
	return &ConnectionError{err: &ConnectionErrorInvalidElvpFormat{}}
}

func (e ConnectionErrorInvalidElvpFormat) destroy() {
}

func (err ConnectionErrorInvalidElvpFormat) Error() string {
	return fmt.Sprint("InvalidElvpFormat")
}

func (self ConnectionErrorInvalidElvpFormat) Is(target error) bool {
	return target == ErrConnectionErrorInvalidElvpFormat
}

type ConnectionErrorRecvedZero struct {
}

func NewConnectionErrorRecvedZero() *ConnectionError {
	return &ConnectionError{err: &ConnectionErrorRecvedZero{}}
}

func (e ConnectionErrorRecvedZero) destroy() {
}

func (err ConnectionErrorRecvedZero) Error() string {
	return fmt.Sprint("RecvedZero")
}

func (self ConnectionErrorRecvedZero) Is(target error) bool {
	return target == ErrConnectionErrorRecvedZero
}

type ConnectionErrorStateTransitionError struct {
}

func NewConnectionErrorStateTransitionError() *ConnectionError {
	return &ConnectionError{err: &ConnectionErrorStateTransitionError{}}
}

func (e ConnectionErrorStateTransitionError) destroy() {
}

func (err ConnectionErrorStateTransitionError) Error() string {
	return fmt.Sprint("StateTransitionError")
}

func (self ConnectionErrorStateTransitionError) Is(target error) bool {
	return target == ErrConnectionErrorStateTransitionError
}

type ConnectionErrorConvertError struct {
}

func NewConnectionErrorConvertError() *ConnectionError {
	return &ConnectionError{err: &ConnectionErrorConvertError{}}
}

func (e ConnectionErrorConvertError) destroy() {
}

func (err ConnectionErrorConvertError) Error() string {
	return fmt.Sprint("ConvertError")
}

func (self ConnectionErrorConvertError) Is(target error) bool {
	return target == ErrConnectionErrorConvertError
}

type ConnectionErrorNotInitializedError struct {
}

func NewConnectionErrorNotInitializedError() *ConnectionError {
	return &ConnectionError{err: &ConnectionErrorNotInitializedError{}}
}

func (e ConnectionErrorNotInitializedError) destroy() {
}

func (err ConnectionErrorNotInitializedError) Error() string {
	return fmt.Sprint("NotInitializedError")
}

func (self ConnectionErrorNotInitializedError) Is(target error) bool {
	return target == ErrConnectionErrorNotInitializedError
}

type FfiConverterConnectionError struct{}

var FfiConverterConnectionErrorINSTANCE = FfiConverterConnectionError{}

func (c FfiConverterConnectionError) Lift(eb RustBufferI) *ConnectionError {
	return LiftFromRustBuffer[*ConnectionError](c, eb)
}

func (c FfiConverterConnectionError) Lower(value *ConnectionError) C.RustBuffer {
	return LowerIntoRustBuffer[*ConnectionError](c, value)
}

func (c FfiConverterConnectionError) Read(reader io.Reader) *ConnectionError {
	errorID := readUint32(reader)

	switch errorID {
	case 1:
		return &ConnectionError{&ConnectionErrorNameResolvError{}}
	case 2:
		return &ConnectionError{&ConnectionErrorInvalidHostnameError{}}
	case 3:
		return &ConnectionError{&ConnectionErrorTcpConnectError{}}
	case 4:
		return &ConnectionError{&ConnectionErrorTlsHandshakeError{}}
	case 5:
		return &ConnectionError{&ConnectionErrorQuicConnectError{}}
	case 6:
		return &ConnectionError{&ConnectionErrorThereIsNoIpAddrError{}}
	case 7:
		return &ConnectionError{&ConnectionErrorInvalidIpAddrFormatError{}}
	case 8:
		return &ConnectionError{&ConnectionErrorPrepareError{}}
	case 9:
		return &ConnectionError{&ConnectionErrorFormatError{}}
	case 10:
		return &ConnectionError{&ConnectionErrorServerBusyError{}}
	case 11:
		return &ConnectionError{&ConnectionErrorMaintenanceError{}}
	case 12:
		return &ConnectionError{&ConnectionErrorRequestNotSupportedError{}}
	case 13:
		return &ConnectionError{&ConnectionErrorUnsupportedClientError{}}
	case 14:
		return &ConnectionError{&ConnectionErrorIncorrectRequestError{}}
	case 15:
		return &ConnectionError{&ConnectionErrorAuthenticationError{}}
	case 16:
		return &ConnectionError{&ConnectionErrorExceededConnectionForSameAccountError{}}
	case 17:
		return &ConnectionError{&ConnectionErrorFixAddressInUseError{}}
	case 18:
		return &ConnectionError{&ConnectionErrorIncorrectProtocolTransitionError{}}
	case 19:
		return &ConnectionError{&ConnectionErrorFailedToGetAddressError{}}
	case 20:
		return &ConnectionError{&ConnectionErrorInternalServerError{}}
	case 21:
		return &ConnectionError{&ConnectionErrorNextRequestIsNoneError{}}
	case 22:
		return &ConnectionError{&ConnectionErrorSendIoError{}}
	case 23:
		return &ConnectionError{&ConnectionErrorRecvIoError{}}
	case 24:
		return &ConnectionError{&ConnectionErrorTimeoutError{}}
	case 25:
		return &ConnectionError{&ConnectionErrorElProtocolUnknownError{}}
	case 26:
		return &ConnectionError{&ConnectionErrorInvalidElvpFormat{}}
	case 27:
		return &ConnectionError{&ConnectionErrorRecvedZero{}}
	case 28:
		return &ConnectionError{&ConnectionErrorStateTransitionError{}}
	case 29:
		return &ConnectionError{&ConnectionErrorConvertError{}}
	case 30:
		return &ConnectionError{&ConnectionErrorNotInitializedError{}}
	default:
		panic(fmt.Sprintf("Unknown error code %d in FfiConverterConnectionError.Read()", errorID))
	}
}

func (c FfiConverterConnectionError) Write(writer io.Writer, value *ConnectionError) {
	switch variantValue := value.err.(type) {
	case *ConnectionErrorNameResolvError:
		writeInt32(writer, 1)
	case *ConnectionErrorInvalidHostnameError:
		writeInt32(writer, 2)
	case *ConnectionErrorTcpConnectError:
		writeInt32(writer, 3)
	case *ConnectionErrorTlsHandshakeError:
		writeInt32(writer, 4)
	case *ConnectionErrorQuicConnectError:
		writeInt32(writer, 5)
	case *ConnectionErrorThereIsNoIpAddrError:
		writeInt32(writer, 6)
	case *ConnectionErrorInvalidIpAddrFormatError:
		writeInt32(writer, 7)
	case *ConnectionErrorPrepareError:
		writeInt32(writer, 8)
	case *ConnectionErrorFormatError:
		writeInt32(writer, 9)
	case *ConnectionErrorServerBusyError:
		writeInt32(writer, 10)
	case *ConnectionErrorMaintenanceError:
		writeInt32(writer, 11)
	case *ConnectionErrorRequestNotSupportedError:
		writeInt32(writer, 12)
	case *ConnectionErrorUnsupportedClientError:
		writeInt32(writer, 13)
	case *ConnectionErrorIncorrectRequestError:
		writeInt32(writer, 14)
	case *ConnectionErrorAuthenticationError:
		writeInt32(writer, 15)
	case *ConnectionErrorExceededConnectionForSameAccountError:
		writeInt32(writer, 16)
	case *ConnectionErrorFixAddressInUseError:
		writeInt32(writer, 17)
	case *ConnectionErrorIncorrectProtocolTransitionError:
		writeInt32(writer, 18)
	case *ConnectionErrorFailedToGetAddressError:
		writeInt32(writer, 19)
	case *ConnectionErrorInternalServerError:
		writeInt32(writer, 20)
	case *ConnectionErrorNextRequestIsNoneError:
		writeInt32(writer, 21)
	case *ConnectionErrorSendIoError:
		writeInt32(writer, 22)
	case *ConnectionErrorRecvIoError:
		writeInt32(writer, 23)
	case *ConnectionErrorTimeoutError:
		writeInt32(writer, 24)
	case *ConnectionErrorElProtocolUnknownError:
		writeInt32(writer, 25)
	case *ConnectionErrorInvalidElvpFormat:
		writeInt32(writer, 26)
	case *ConnectionErrorRecvedZero:
		writeInt32(writer, 27)
	case *ConnectionErrorStateTransitionError:
		writeInt32(writer, 28)
	case *ConnectionErrorConvertError:
		writeInt32(writer, 29)
	case *ConnectionErrorNotInitializedError:
		writeInt32(writer, 30)
	default:
		_ = variantValue
		panic(fmt.Sprintf("invalid error value `%v` in FfiConverterConnectionError.Write", value))
	}
}

type FfiDestroyerConnectionError struct{}

func (_ FfiDestroyerConnectionError) Destroy(value *ConnectionError) {
	switch variantValue := value.err.(type) {
	case ConnectionErrorNameResolvError:
		variantValue.destroy()
	case ConnectionErrorInvalidHostnameError:
		variantValue.destroy()
	case ConnectionErrorTcpConnectError:
		variantValue.destroy()
	case ConnectionErrorTlsHandshakeError:
		variantValue.destroy()
	case ConnectionErrorQuicConnectError:
		variantValue.destroy()
	case ConnectionErrorThereIsNoIpAddrError:
		variantValue.destroy()
	case ConnectionErrorInvalidIpAddrFormatError:
		variantValue.destroy()
	case ConnectionErrorPrepareError:
		variantValue.destroy()
	case ConnectionErrorFormatError:
		variantValue.destroy()
	case ConnectionErrorServerBusyError:
		variantValue.destroy()
	case ConnectionErrorMaintenanceError:
		variantValue.destroy()
	case ConnectionErrorRequestNotSupportedError:
		variantValue.destroy()
	case ConnectionErrorUnsupportedClientError:
		variantValue.destroy()
	case ConnectionErrorIncorrectRequestError:
		variantValue.destroy()
	case ConnectionErrorAuthenticationError:
		variantValue.destroy()
	case ConnectionErrorExceededConnectionForSameAccountError:
		variantValue.destroy()
	case ConnectionErrorFixAddressInUseError:
		variantValue.destroy()
	case ConnectionErrorIncorrectProtocolTransitionError:
		variantValue.destroy()
	case ConnectionErrorFailedToGetAddressError:
		variantValue.destroy()
	case ConnectionErrorInternalServerError:
		variantValue.destroy()
	case ConnectionErrorNextRequestIsNoneError:
		variantValue.destroy()
	case ConnectionErrorSendIoError:
		variantValue.destroy()
	case ConnectionErrorRecvIoError:
		variantValue.destroy()
	case ConnectionErrorTimeoutError:
		variantValue.destroy()
	case ConnectionErrorElProtocolUnknownError:
		variantValue.destroy()
	case ConnectionErrorInvalidElvpFormat:
		variantValue.destroy()
	case ConnectionErrorRecvedZero:
		variantValue.destroy()
	case ConnectionErrorStateTransitionError:
		variantValue.destroy()
	case ConnectionErrorConvertError:
		variantValue.destroy()
	case ConnectionErrorNotInitializedError:
		variantValue.destroy()
	default:
		_ = variantValue
		panic(fmt.Sprintf("invalid error value `%v` in FfiDestroyerConnectionError.Destroy", value))
	}
}

type ElStackVpnConnectionType uint

const (
	ElStackVpnConnectionTypeTls  ElStackVpnConnectionType = 1
	ElStackVpnConnectionTypeQuic ElStackVpnConnectionType = 2
)

type FfiConverterElStackVpnConnectionType struct{}

var FfiConverterElStackVpnConnectionTypeINSTANCE = FfiConverterElStackVpnConnectionType{}

func (c FfiConverterElStackVpnConnectionType) Lift(rb RustBufferI) ElStackVpnConnectionType {
	return LiftFromRustBuffer[ElStackVpnConnectionType](c, rb)
}

func (c FfiConverterElStackVpnConnectionType) Lower(value ElStackVpnConnectionType) C.RustBuffer {
	return LowerIntoRustBuffer[ElStackVpnConnectionType](c, value)
}
func (FfiConverterElStackVpnConnectionType) Read(reader io.Reader) ElStackVpnConnectionType {
	id := readInt32(reader)
	return ElStackVpnConnectionType(id)
}

func (FfiConverterElStackVpnConnectionType) Write(writer io.Writer, value ElStackVpnConnectionType) {
	writeInt32(writer, int32(value))
}

type FfiDestroyerElStackVpnConnectionType struct{}

func (_ FfiDestroyerElStackVpnConnectionType) Destroy(value ElStackVpnConnectionType) {
}

type SocketError struct {
	err error
}

// Convience method to turn *SocketError into error
// Avoiding treating nil pointer as non nil error interface
func (err *SocketError) AsError() error {
	if err == nil {
		return nil
	} else {
		return err
	}
}

func (err SocketError) Error() string {
	return fmt.Sprintf("SocketError: %s", err.err.Error())
}

func (err SocketError) Unwrap() error {
	return err.err
}

// Err* are used for checking error type with `errors.Is`
var ErrSocketErrorNameResolvError = fmt.Errorf("SocketError: NameResolvError")
var ErrSocketErrorAddressConvertError = fmt.Errorf("SocketError: AddressConvertError")
var ErrSocketErrorInvalidHostnameError = fmt.Errorf("SocketError: InvalidHostnameError")
var ErrSocketErrorTcpConnectError = fmt.Errorf("SocketError: TcpConnectError")
var ErrSocketErrorTcpConnectTimeout = fmt.Errorf("SocketError: TcpConnectTimeout")
var ErrSocketErrorTcpBindError = fmt.Errorf("SocketError: TcpBindError")
var ErrSocketErrorUdpBindError = fmt.Errorf("SocketError: UdpBindError")
var ErrSocketErrorTlsHandshakeError = fmt.Errorf("SocketError: TlsHandshakeError")
var ErrSocketErrorTlsHandshakeTimeout = fmt.Errorf("SocketError: TlsHandshakeTimeout")
var ErrSocketErrorQuicConnectError = fmt.Errorf("SocketError: QuicConnectError")
var ErrSocketErrorTcpAcceptError = fmt.Errorf("SocketError: TcpAcceptError")
var ErrSocketErrorTcpAcceptTimeout = errors.New("SocketError: TcpAcceptTimeout")
var ErrSocketErrorAddressError = fmt.Errorf("SocketError: AddressError")
var ErrSocketErrorConnectionClosed = fmt.Errorf("SocketError: ConnectionClosed")
var ErrSocketErrorInvalidCertificateError = fmt.Errorf("SocketError: InvalidCertificateError")
var ErrSocketErrorTlsError = fmt.Errorf("SocketError: TlsError")
var ErrSocketErrorTcpRecvTimeout = fmt.Errorf("SocketError: TcpRecvTimeout")
var ErrSocketErrorTcpSendTimeout = fmt.Errorf("SocketError: TcpSendTimeout")
var ErrSocketErrorUdpRecvTimeout = fmt.Errorf("SocketError: UdpRecvTimeout")
var ErrSocketErrorUdpSendTimeout = fmt.Errorf("SocketError: UdpSendTimeout")
var ErrSocketErrorOther = fmt.Errorf("SocketError: Other")
var ErrSocketErrorNotInitializedError = fmt.Errorf("SocketError: NotInitializedError")

// Variant structs
type SocketErrorNameResolvError struct {
}

func NewSocketErrorNameResolvError() *SocketError {
	return &SocketError{err: &SocketErrorNameResolvError{}}
}

func (e SocketErrorNameResolvError) destroy() {
}

func (err SocketErrorNameResolvError) Error() string {
	return fmt.Sprint("NameResolvError")
}

func (self SocketErrorNameResolvError) Is(target error) bool {
	return target == ErrSocketErrorNameResolvError
}

type SocketErrorAddressConvertError struct {
}

func NewSocketErrorAddressConvertError() *SocketError {
	return &SocketError{err: &SocketErrorAddressConvertError{}}
}

func (e SocketErrorAddressConvertError) destroy() {
}

func (err SocketErrorAddressConvertError) Error() string {
	return fmt.Sprint("AddressConvertError")
}

func (self SocketErrorAddressConvertError) Is(target error) bool {
	return target == ErrSocketErrorAddressConvertError
}

type SocketErrorInvalidHostnameError struct {
}

func NewSocketErrorInvalidHostnameError() *SocketError {
	return &SocketError{err: &SocketErrorInvalidHostnameError{}}
}

func (e SocketErrorInvalidHostnameError) destroy() {
}

func (err SocketErrorInvalidHostnameError) Error() string {
	return fmt.Sprint("InvalidHostnameError")
}

func (self SocketErrorInvalidHostnameError) Is(target error) bool {
	return target == ErrSocketErrorInvalidHostnameError
}

type SocketErrorTcpConnectError struct {
}

func NewSocketErrorTcpConnectError() *SocketError {
	return &SocketError{err: &SocketErrorTcpConnectError{}}
}

func (e SocketErrorTcpConnectError) destroy() {
}

func (err SocketErrorTcpConnectError) Error() string {
	return fmt.Sprint("TcpConnectError")
}

func (self SocketErrorTcpConnectError) Is(target error) bool {
	return target == ErrSocketErrorTcpConnectError
}

type SocketErrorTcpConnectTimeout struct {
}

func NewSocketErrorTcpConnectTimeout() *SocketError {
	return &SocketError{err: &SocketErrorTcpConnectTimeout{}}
}

func (e SocketErrorTcpConnectTimeout) destroy() {
}

func (err SocketErrorTcpConnectTimeout) Error() string {
	return fmt.Sprint("TcpConnectTimeout")
}

func (self SocketErrorTcpConnectTimeout) Is(target error) bool {
	return target == ErrSocketErrorTcpConnectTimeout
}

type SocketErrorTcpBindError struct {
}

func NewSocketErrorTcpBindError() *SocketError {
	return &SocketError{err: &SocketErrorTcpBindError{}}
}

func (e SocketErrorTcpBindError) destroy() {
}

func (err SocketErrorTcpBindError) Error() string {
	return fmt.Sprint("TcpBindError")
}

func (self SocketErrorTcpBindError) Is(target error) bool {
	return target == ErrSocketErrorTcpBindError
}

type SocketErrorUdpBindError struct {
}

func NewSocketErrorUdpBindError() *SocketError {
	return &SocketError{err: &SocketErrorUdpBindError{}}
}

func (e SocketErrorUdpBindError) destroy() {
}

func (err SocketErrorUdpBindError) Error() string {
	return fmt.Sprint("UdpBindError")
}

func (self SocketErrorUdpBindError) Is(target error) bool {
	return target == ErrSocketErrorUdpBindError
}

type SocketErrorTlsHandshakeError struct {
}

func NewSocketErrorTlsHandshakeError() *SocketError {
	return &SocketError{err: &SocketErrorTlsHandshakeError{}}
}

func (e SocketErrorTlsHandshakeError) destroy() {
}

func (err SocketErrorTlsHandshakeError) Error() string {
	return fmt.Sprint("TlsHandshakeError")
}

func (self SocketErrorTlsHandshakeError) Is(target error) bool {
	return target == ErrSocketErrorTlsHandshakeError
}

type SocketErrorTlsHandshakeTimeout struct {
}

func NewSocketErrorTlsHandshakeTimeout() *SocketError {
	return &SocketError{err: &SocketErrorTlsHandshakeTimeout{}}
}

func (e SocketErrorTlsHandshakeTimeout) destroy() {
}

func (err SocketErrorTlsHandshakeTimeout) Error() string {
	return fmt.Sprint("TlsHandshakeTimeout")
}

func (self SocketErrorTlsHandshakeTimeout) Is(target error) bool {
	return target == ErrSocketErrorTlsHandshakeTimeout
}

type SocketErrorQuicConnectError struct {
}

func NewSocketErrorQuicConnectError() *SocketError {
	return &SocketError{err: &SocketErrorQuicConnectError{}}
}

func (e SocketErrorQuicConnectError) destroy() {
}

func (err SocketErrorQuicConnectError) Error() string {
	return fmt.Sprint("QuicConnectError")
}

func (self SocketErrorQuicConnectError) Is(target error) bool {
	return target == ErrSocketErrorQuicConnectError
}

type SocketErrorTcpAcceptError struct {
}

func NewSocketErrorTcpAcceptError() *SocketError {
	return &SocketError{err: &SocketErrorTcpAcceptError{}}
}

func (e SocketErrorTcpAcceptError) destroy() {
}

func (err SocketErrorTcpAcceptError) Error() string {
	return fmt.Sprint("TcpAcceptError")
}

func (self SocketErrorTcpAcceptError) Is(target error) bool {
	return target == ErrSocketErrorTcpAcceptError
}

type SocketErrorTcpAcceptTimeout struct {
}

func NewSocketErrorTcpAcceptTimeout() *SocketError {
	return &SocketError{err: &SocketErrorTcpAcceptTimeout{}}
}

func (e SocketErrorTcpAcceptTimeout) destroy() {
}

func (err SocketErrorTcpAcceptTimeout) Error() string {
	return fmt.Sprint("TcpAcceptTimeout")
}

func (self SocketErrorTcpAcceptTimeout) Is(target error) bool {
	return target == ErrSocketErrorTcpAcceptTimeout
}

type SocketErrorAddressError struct {
}

func NewSocketErrorAddressError() *SocketError {
	return &SocketError{err: &SocketErrorAddressError{}}
}

func (e SocketErrorAddressError) destroy() {
}

func (err SocketErrorAddressError) Error() string {
	return fmt.Sprint("AddressError")
}

func (self SocketErrorAddressError) Is(target error) bool {
	return target == ErrSocketErrorAddressError
}

type SocketErrorConnectionClosed struct {
}

func NewSocketErrorConnectionClosed() *SocketError {
	return &SocketError{err: &SocketErrorConnectionClosed{}}
}

func (e SocketErrorConnectionClosed) destroy() {
}

func (err SocketErrorConnectionClosed) Error() string {
	return fmt.Sprint("ConnectionClosed")
}

func (self SocketErrorConnectionClosed) Is(target error) bool {
	return target == ErrSocketErrorConnectionClosed
}

type SocketErrorInvalidCertificateError struct {
}

func NewSocketErrorInvalidCertificateError() *SocketError {
	return &SocketError{err: &SocketErrorInvalidCertificateError{}}
}

func (e SocketErrorInvalidCertificateError) destroy() {
}

func (err SocketErrorInvalidCertificateError) Error() string {
	return fmt.Sprint("InvalidCertificateError")
}

func (self SocketErrorInvalidCertificateError) Is(target error) bool {
	return target == ErrSocketErrorInvalidCertificateError
}

type SocketErrorTlsError struct {
}

func NewSocketErrorTlsError() *SocketError {
	return &SocketError{err: &SocketErrorTlsError{}}
}

func (e SocketErrorTlsError) destroy() {
}

func (err SocketErrorTlsError) Error() string {
	return fmt.Sprint("TlsError")
}

func (self SocketErrorTlsError) Is(target error) bool {
	return target == ErrSocketErrorTlsError
}

type SocketErrorTcpRecvTimeout struct {
}

func NewSocketErrorTcpRecvTimeout() *SocketError {
	return &SocketError{err: &SocketErrorTcpRecvTimeout{}}
}

func (e SocketErrorTcpRecvTimeout) destroy() {
}

func (err SocketErrorTcpRecvTimeout) Error() string {
	return fmt.Sprint("TcpRecvTimeout")
}

func (self SocketErrorTcpRecvTimeout) Is(target error) bool {
	return target == ErrSocketErrorTcpRecvTimeout
}

type SocketErrorTcpSendTimeout struct {
}

func NewSocketErrorTcpSendTimeout() *SocketError {
	return &SocketError{err: &SocketErrorTcpSendTimeout{}}
}

func (e SocketErrorTcpSendTimeout) destroy() {
}

func (err SocketErrorTcpSendTimeout) Error() string {
	return fmt.Sprint("TcpSendTimeout")
}

func (self SocketErrorTcpSendTimeout) Is(target error) bool {
	return target == ErrSocketErrorTcpSendTimeout
}

type SocketErrorUdpRecvTimeout struct {
}

func NewSocketErrorUdpRecvTimeout() *SocketError {
	return &SocketError{err: &SocketErrorUdpRecvTimeout{}}
}

func (e SocketErrorUdpRecvTimeout) destroy() {
}

func (err SocketErrorUdpRecvTimeout) Error() string {
	return fmt.Sprint("UdpRecvTimeout")
}

func (self SocketErrorUdpRecvTimeout) Is(target error) bool {
	return target == ErrSocketErrorUdpRecvTimeout
}

type SocketErrorUdpSendTimeout struct {
}

func NewSocketErrorUdpSendTimeout() *SocketError {
	return &SocketError{err: &SocketErrorUdpSendTimeout{}}
}

func (e SocketErrorUdpSendTimeout) destroy() {
}

func (err SocketErrorUdpSendTimeout) Error() string {
	return fmt.Sprint("UdpSendTimeout")
}

func (self SocketErrorUdpSendTimeout) Is(target error) bool {
	return target == ErrSocketErrorUdpSendTimeout
}

type SocketErrorOther struct {
}

func NewSocketErrorOther() *SocketError {
	return &SocketError{err: &SocketErrorOther{}}
}

func (e SocketErrorOther) destroy() {
}

func (err SocketErrorOther) Error() string {
	return fmt.Sprint("Other")
}

func (self SocketErrorOther) Is(target error) bool {
	return target == ErrSocketErrorOther
}

type SocketErrorNotInitializedError struct {
}

func NewSocketErrorNotInitializedError() *SocketError {
	return &SocketError{err: &SocketErrorNotInitializedError{}}
}

func (e SocketErrorNotInitializedError) destroy() {
}

func (err SocketErrorNotInitializedError) Error() string {
	return fmt.Sprint("NotInitializedError")
}

func (self SocketErrorNotInitializedError) Is(target error) bool {
	return target == ErrSocketErrorNotInitializedError
}

type FfiConverterSocketError struct{}

var FfiConverterSocketErrorINSTANCE = FfiConverterSocketError{}

func (c FfiConverterSocketError) Lift(eb RustBufferI) *SocketError {
	return LiftFromRustBuffer[*SocketError](c, eb)
}

func (c FfiConverterSocketError) Lower(value *SocketError) C.RustBuffer {
	return LowerIntoRustBuffer[*SocketError](c, value)
}

func (c FfiConverterSocketError) Read(reader io.Reader) *SocketError {
	errorID := readUint32(reader)

	switch errorID {
	case 1:
		return &SocketError{&SocketErrorNameResolvError{}}
	case 2:
		return &SocketError{&SocketErrorAddressConvertError{}}
	case 3:
		return &SocketError{&SocketErrorInvalidHostnameError{}}
	case 4:
		return &SocketError{&SocketErrorTcpConnectError{}}
	case 5:
		return &SocketError{&SocketErrorTcpConnectTimeout{}}
	case 6:
		return &SocketError{&SocketErrorTcpBindError{}}
	case 7:
		return &SocketError{&SocketErrorUdpBindError{}}
	case 8:
		return &SocketError{&SocketErrorTlsHandshakeError{}}
	case 9:
		return &SocketError{&SocketErrorTlsHandshakeTimeout{}}
	case 10:
		return &SocketError{&SocketErrorQuicConnectError{}}
	case 11:
		return &SocketError{&SocketErrorTcpAcceptError{}}
	case 12:
		return &SocketError{&SocketErrorTcpAcceptTimeout{}}
	case 13:
		return &SocketError{&SocketErrorAddressError{}}
	case 14:
		return &SocketError{&SocketErrorConnectionClosed{}}
	case 15:
		return &SocketError{&SocketErrorInvalidCertificateError{}}
	case 16:
		return &SocketError{&SocketErrorTlsError{}}
	case 17:
		return &SocketError{&SocketErrorTcpRecvTimeout{}}
	case 18:
		return &SocketError{&SocketErrorTcpSendTimeout{}}
	case 19:
		return &SocketError{&SocketErrorUdpRecvTimeout{}}
	case 20:
		return &SocketError{&SocketErrorUdpSendTimeout{}}
	case 21:
		return &SocketError{&SocketErrorOther{}}
	case 22:
		return &SocketError{&SocketErrorNotInitializedError{}}
	default:
		panic(fmt.Sprintf("Unknown error code %d in FfiConverterSocketError.Read()", errorID))
	}
}

func (c FfiConverterSocketError) Write(writer io.Writer, value *SocketError) {
	switch variantValue := value.err.(type) {
	case *SocketErrorNameResolvError:
		writeInt32(writer, 1)
	case *SocketErrorAddressConvertError:
		writeInt32(writer, 2)
	case *SocketErrorInvalidHostnameError:
		writeInt32(writer, 3)
	case *SocketErrorTcpConnectError:
		writeInt32(writer, 4)
	case *SocketErrorTcpConnectTimeout:
		writeInt32(writer, 5)
	case *SocketErrorTcpBindError:
		writeInt32(writer, 6)
	case *SocketErrorUdpBindError:
		writeInt32(writer, 7)
	case *SocketErrorTlsHandshakeError:
		writeInt32(writer, 8)
	case *SocketErrorTlsHandshakeTimeout:
		writeInt32(writer, 9)
	case *SocketErrorQuicConnectError:
		writeInt32(writer, 10)
	case *SocketErrorTcpAcceptError:
		writeInt32(writer, 11)
	case *SocketErrorTcpAcceptTimeout:
		writeInt32(writer, 12)
	case *SocketErrorAddressError:
		writeInt32(writer, 13)
	case *SocketErrorConnectionClosed:
		writeInt32(writer, 14)
	case *SocketErrorInvalidCertificateError:
		writeInt32(writer, 15)
	case *SocketErrorTlsError:
		writeInt32(writer, 16)
	case *SocketErrorTcpRecvTimeout:
		writeInt32(writer, 17)
	case *SocketErrorTcpSendTimeout:
		writeInt32(writer, 18)
	case *SocketErrorUdpRecvTimeout:
		writeInt32(writer, 19)
	case *SocketErrorUdpSendTimeout:
		writeInt32(writer, 20)
	case *SocketErrorOther:
		writeInt32(writer, 21)
	case *SocketErrorNotInitializedError:
		writeInt32(writer, 22)
	default:
		_ = variantValue
		panic(fmt.Sprintf("invalid error value `%v` in FfiConverterSocketError.Write", value))
	}
}

type FfiDestroyerSocketError struct{}

func (_ FfiDestroyerSocketError) Destroy(value *SocketError) {
	switch variantValue := value.err.(type) {
	case SocketErrorNameResolvError:
		variantValue.destroy()
	case SocketErrorAddressConvertError:
		variantValue.destroy()
	case SocketErrorInvalidHostnameError:
		variantValue.destroy()
	case SocketErrorTcpConnectError:
		variantValue.destroy()
	case SocketErrorTcpConnectTimeout:
		variantValue.destroy()
	case SocketErrorTcpBindError:
		variantValue.destroy()
	case SocketErrorUdpBindError:
		variantValue.destroy()
	case SocketErrorTlsHandshakeError:
		variantValue.destroy()
	case SocketErrorTlsHandshakeTimeout:
		variantValue.destroy()
	case SocketErrorQuicConnectError:
		variantValue.destroy()
	case SocketErrorTcpAcceptError:
		variantValue.destroy()
	case SocketErrorTcpAcceptTimeout:
		variantValue.destroy()
	case SocketErrorAddressError:
		variantValue.destroy()
	case SocketErrorConnectionClosed:
		variantValue.destroy()
	case SocketErrorInvalidCertificateError:
		variantValue.destroy()
	case SocketErrorTlsError:
		variantValue.destroy()
	case SocketErrorTcpRecvTimeout:
		variantValue.destroy()
	case SocketErrorTcpSendTimeout:
		variantValue.destroy()
	case SocketErrorUdpRecvTimeout:
		variantValue.destroy()
	case SocketErrorUdpSendTimeout:
		variantValue.destroy()
	case SocketErrorOther:
		variantValue.destroy()
	case SocketErrorNotInitializedError:
		variantValue.destroy()
	default:
		_ = variantValue
		panic(fmt.Sprintf("invalid error value `%v` in FfiDestroyerSocketError.Destroy", value))
	}
}

type VpnStatus uint

const (
	VpnStatusDisconnected VpnStatus = 1
	VpnStatusConnecting   VpnStatus = 2
	VpnStatusConnected    VpnStatus = 3
)

type FfiConverterVpnStatus struct{}

var FfiConverterVpnStatusINSTANCE = FfiConverterVpnStatus{}

func (c FfiConverterVpnStatus) Lift(rb RustBufferI) VpnStatus {
	return LiftFromRustBuffer[VpnStatus](c, rb)
}

func (c FfiConverterVpnStatus) Lower(value VpnStatus) C.RustBuffer {
	return LowerIntoRustBuffer[VpnStatus](c, value)
}
func (FfiConverterVpnStatus) Read(reader io.Reader) VpnStatus {
	id := readInt32(reader)
	return VpnStatus(id)
}

func (FfiConverterVpnStatus) Write(writer io.Writer, value VpnStatus) {
	writeInt32(writer, int32(value))
}

type FfiDestroyerVpnStatus struct{}

func (_ FfiDestroyerVpnStatus) Destroy(value VpnStatus) {
}

type ElStackIssueEventDelegate interface {

	// 認証用のVCのVPを返す（追加の値はkey/valueで指定される）
	OnGenerateAuthVp(key string, value string) string

	// EL VC用の公開鍵をJWK形式の文字列で返す
	OnElPubKey() string

	// EL VCの秘密鍵で署名を行う
	OnElVpSign(data string) string
}

type FfiConverterCallbackInterfaceElStackIssueEventDelegate struct {
	handleMap *concurrentHandleMap[ElStackIssueEventDelegate]
}

var FfiConverterCallbackInterfaceElStackIssueEventDelegateINSTANCE = FfiConverterCallbackInterfaceElStackIssueEventDelegate{
	handleMap: newConcurrentHandleMap[ElStackIssueEventDelegate](),
}

func (c FfiConverterCallbackInterfaceElStackIssueEventDelegate) Lift(handle uint64) ElStackIssueEventDelegate {
	val, ok := c.handleMap.tryGet(handle)
	if !ok {
		panic(fmt.Errorf("no callback in handle map: %d", handle))
	}
	return val
}

func (c FfiConverterCallbackInterfaceElStackIssueEventDelegate) Read(reader io.Reader) ElStackIssueEventDelegate {
	return c.Lift(readUint64(reader))
}

func (c FfiConverterCallbackInterfaceElStackIssueEventDelegate) Lower(value ElStackIssueEventDelegate) C.uint64_t {
	return C.uint64_t(c.handleMap.insert(value))
}

func (c FfiConverterCallbackInterfaceElStackIssueEventDelegate) Write(writer io.Writer, value ElStackIssueEventDelegate) {
	writeUint64(writer, uint64(c.Lower(value)))
}

type FfiDestroyerCallbackInterfaceElStackIssueEventDelegate struct{}

func (FfiDestroyerCallbackInterfaceElStackIssueEventDelegate) Destroy(value ElStackIssueEventDelegate) {
}

type uniffiCallbackResult C.int8_t

const (
	uniffiIdxCallbackFree               uniffiCallbackResult = 0
	uniffiCallbackResultSuccess         uniffiCallbackResult = 0
	uniffiCallbackResultError           uniffiCallbackResult = 1
	uniffiCallbackUnexpectedResultError uniffiCallbackResult = 2
	uniffiCallbackCancelled             uniffiCallbackResult = 3
)

type concurrentHandleMap[T any] struct {
	handles       map[uint64]T
	currentHandle uint64
	lock          sync.RWMutex
}

func newConcurrentHandleMap[T any]() *concurrentHandleMap[T] {
	return &concurrentHandleMap[T]{
		handles: map[uint64]T{},
	}
}

func (cm *concurrentHandleMap[T]) insert(obj T) uint64 {
	cm.lock.Lock()
	defer cm.lock.Unlock()

	cm.currentHandle = cm.currentHandle + 1
	cm.handles[cm.currentHandle] = obj
	return cm.currentHandle
}

func (cm *concurrentHandleMap[T]) remove(handle uint64) {
	cm.lock.Lock()
	defer cm.lock.Unlock()

	delete(cm.handles, handle)
}

func (cm *concurrentHandleMap[T]) tryGet(handle uint64) (T, bool) {
	cm.lock.RLock()
	defer cm.lock.RUnlock()

	val, ok := cm.handles[handle]
	return val, ok
}

//export el_stack_cgo_dispatchCallbackInterfaceElStackIssueEventDelegateMethod0
func el_stack_cgo_dispatchCallbackInterfaceElStackIssueEventDelegateMethod0(uniffiHandle C.uint64_t, key C.RustBuffer, value C.RustBuffer, uniffiFutureCallback C.UniffiForeignFutureCompleteRustBuffer, uniffiCallbackData C.uint64_t, uniffiOutReturn *C.UniffiForeignFuture) {
	handle := uint64(uniffiHandle)
	uniffiObj, ok := FfiConverterCallbackInterfaceElStackIssueEventDelegateINSTANCE.handleMap.tryGet(handle)
	if !ok {
		panic(fmt.Errorf("no callback in handle map: %d", handle))
	}

	result := make(chan C.UniffiForeignFutureStructRustBuffer, 1)
	cancel := make(chan struct{}, 1)
	guardHandle := cgo.NewHandle(cancel)
	*uniffiOutReturn = C.UniffiForeignFuture{
		handle: C.uint64_t(guardHandle),
		free:   C.UniffiForeignFutureFree(C.el_stack_uniffiFreeGorutine),
	}

	// Wait for compleation or cancel
	go func() {
		select {
		case <-cancel:
		case res := <-result:
			C.call_UniffiForeignFutureCompleteRustBuffer(uniffiFutureCallback, uniffiCallbackData, res)
		}
	}()

	// Eval callback asynchroniously
	go func() {
		asyncResult := &C.UniffiForeignFutureStructRustBuffer{}
		uniffiOutReturn := &asyncResult.returnValue
		defer func() {
			result <- *asyncResult
		}()

		res :=
			uniffiObj.OnGenerateAuthVp(
				FfiConverterStringINSTANCE.Lift(GoRustBuffer{
					inner: key,
				}),
				FfiConverterStringINSTANCE.Lift(GoRustBuffer{
					inner: value,
				}),
			)

		*uniffiOutReturn = FfiConverterStringINSTANCE.Lower(res)
	}()
}

//export el_stack_cgo_dispatchCallbackInterfaceElStackIssueEventDelegateMethod1
func el_stack_cgo_dispatchCallbackInterfaceElStackIssueEventDelegateMethod1(uniffiHandle C.uint64_t, uniffiOutReturn *C.RustBuffer, callStatus *C.RustCallStatus) {
	handle := uint64(uniffiHandle)
	uniffiObj, ok := FfiConverterCallbackInterfaceElStackIssueEventDelegateINSTANCE.handleMap.tryGet(handle)
	if !ok {
		panic(fmt.Errorf("no callback in handle map: %d", handle))
	}

	res :=
		uniffiObj.OnElPubKey()

	*uniffiOutReturn = FfiConverterStringINSTANCE.Lower(res)
}

//export el_stack_cgo_dispatchCallbackInterfaceElStackIssueEventDelegateMethod2
func el_stack_cgo_dispatchCallbackInterfaceElStackIssueEventDelegateMethod2(uniffiHandle C.uint64_t, data C.RustBuffer, uniffiFutureCallback C.UniffiForeignFutureCompleteRustBuffer, uniffiCallbackData C.uint64_t, uniffiOutReturn *C.UniffiForeignFuture) {
	handle := uint64(uniffiHandle)
	uniffiObj, ok := FfiConverterCallbackInterfaceElStackIssueEventDelegateINSTANCE.handleMap.tryGet(handle)
	if !ok {
		panic(fmt.Errorf("no callback in handle map: %d", handle))
	}

	result := make(chan C.UniffiForeignFutureStructRustBuffer, 1)
	cancel := make(chan struct{}, 1)
	guardHandle := cgo.NewHandle(cancel)
	*uniffiOutReturn = C.UniffiForeignFuture{
		handle: C.uint64_t(guardHandle),
		free:   C.UniffiForeignFutureFree(C.el_stack_uniffiFreeGorutine),
	}

	// Wait for compleation or cancel
	go func() {
		select {
		case <-cancel:
		case res := <-result:
			C.call_UniffiForeignFutureCompleteRustBuffer(uniffiFutureCallback, uniffiCallbackData, res)
		}
	}()

	// Eval callback asynchroniously
	go func() {
		asyncResult := &C.UniffiForeignFutureStructRustBuffer{}
		uniffiOutReturn := &asyncResult.returnValue
		defer func() {
			result <- *asyncResult
		}()

		res :=
			uniffiObj.OnElVpSign(
				FfiConverterStringINSTANCE.Lift(GoRustBuffer{
					inner: data,
				}),
			)

		*uniffiOutReturn = FfiConverterStringINSTANCE.Lower(res)
	}()
}

var UniffiVTableCallbackInterfaceElStackIssueEventDelegateINSTANCE = C.UniffiVTableCallbackInterfaceElStackIssueEventDelegate{
	onGenerateAuthVp: (C.UniffiCallbackInterfaceElStackIssueEventDelegateMethod0)(C.el_stack_cgo_dispatchCallbackInterfaceElStackIssueEventDelegateMethod0),
	onElPubKey:       (C.UniffiCallbackInterfaceElStackIssueEventDelegateMethod1)(C.el_stack_cgo_dispatchCallbackInterfaceElStackIssueEventDelegateMethod1),
	onElVpSign:       (C.UniffiCallbackInterfaceElStackIssueEventDelegateMethod2)(C.el_stack_cgo_dispatchCallbackInterfaceElStackIssueEventDelegateMethod2),

	uniffiFree: (C.UniffiCallbackInterfaceFree)(C.el_stack_cgo_dispatchCallbackInterfaceElStackIssueEventDelegateFree),
}

//export el_stack_cgo_dispatchCallbackInterfaceElStackIssueEventDelegateFree
func el_stack_cgo_dispatchCallbackInterfaceElStackIssueEventDelegateFree(handle C.uint64_t) {
	FfiConverterCallbackInterfaceElStackIssueEventDelegateINSTANCE.handleMap.remove(uint64(handle))
}

func (c FfiConverterCallbackInterfaceElStackIssueEventDelegate) register() {
	C.uniffi_el_stack_fn_init_callback_vtable_elstackissueeventdelegate(&UniffiVTableCallbackInterfaceElStackIssueEventDelegateINSTANCE)
}

type ElStackVpnEventDelegate interface {

	// VPNのステータスが変更されたときに通知
	OnStatusChange(status VpnStatus)

	// VPNの接続に失敗した場合に通知
	OnConnectionError(message string)

	// VPNの接続に成功した場合にIPアドレスなどを通知
	OnLinkedParams(ipAddrs []string, dnsAddrs []string, routes []string)
}

type FfiConverterCallbackInterfaceElStackVpnEventDelegate struct {
	handleMap *concurrentHandleMap[ElStackVpnEventDelegate]
}

var FfiConverterCallbackInterfaceElStackVpnEventDelegateINSTANCE = FfiConverterCallbackInterfaceElStackVpnEventDelegate{
	handleMap: newConcurrentHandleMap[ElStackVpnEventDelegate](),
}

func (c FfiConverterCallbackInterfaceElStackVpnEventDelegate) Lift(handle uint64) ElStackVpnEventDelegate {
	val, ok := c.handleMap.tryGet(handle)
	if !ok {
		panic(fmt.Errorf("no callback in handle map: %d", handle))
	}
	return val
}

func (c FfiConverterCallbackInterfaceElStackVpnEventDelegate) Read(reader io.Reader) ElStackVpnEventDelegate {
	return c.Lift(readUint64(reader))
}

func (c FfiConverterCallbackInterfaceElStackVpnEventDelegate) Lower(value ElStackVpnEventDelegate) C.uint64_t {
	return C.uint64_t(c.handleMap.insert(value))
}

func (c FfiConverterCallbackInterfaceElStackVpnEventDelegate) Write(writer io.Writer, value ElStackVpnEventDelegate) {
	writeUint64(writer, uint64(c.Lower(value)))
}

type FfiDestroyerCallbackInterfaceElStackVpnEventDelegate struct{}

func (FfiDestroyerCallbackInterfaceElStackVpnEventDelegate) Destroy(value ElStackVpnEventDelegate) {}

//export el_stack_cgo_dispatchCallbackInterfaceElStackVpnEventDelegateMethod0
func el_stack_cgo_dispatchCallbackInterfaceElStackVpnEventDelegateMethod0(uniffiHandle C.uint64_t, status C.RustBuffer, uniffiOutReturn *C.void, callStatus *C.RustCallStatus) {
	handle := uint64(uniffiHandle)
	uniffiObj, ok := FfiConverterCallbackInterfaceElStackVpnEventDelegateINSTANCE.handleMap.tryGet(handle)
	if !ok {
		panic(fmt.Errorf("no callback in handle map: %d", handle))
	}

	uniffiObj.OnStatusChange(
		FfiConverterVpnStatusINSTANCE.Lift(GoRustBuffer{
			inner: status,
		}),
	)

}

//export el_stack_cgo_dispatchCallbackInterfaceElStackVpnEventDelegateMethod1
func el_stack_cgo_dispatchCallbackInterfaceElStackVpnEventDelegateMethod1(uniffiHandle C.uint64_t, message C.RustBuffer, uniffiOutReturn *C.void, callStatus *C.RustCallStatus) {
	handle := uint64(uniffiHandle)
	uniffiObj, ok := FfiConverterCallbackInterfaceElStackVpnEventDelegateINSTANCE.handleMap.tryGet(handle)
	if !ok {
		panic(fmt.Errorf("no callback in handle map: %d", handle))
	}

	uniffiObj.OnConnectionError(
		FfiConverterStringINSTANCE.Lift(GoRustBuffer{
			inner: message,
		}),
	)

}

//export el_stack_cgo_dispatchCallbackInterfaceElStackVpnEventDelegateMethod2
func el_stack_cgo_dispatchCallbackInterfaceElStackVpnEventDelegateMethod2(uniffiHandle C.uint64_t, ipAddrs C.RustBuffer, dnsAddrs C.RustBuffer, routes C.RustBuffer, uniffiOutReturn *C.void, callStatus *C.RustCallStatus) {
	handle := uint64(uniffiHandle)
	uniffiObj, ok := FfiConverterCallbackInterfaceElStackVpnEventDelegateINSTANCE.handleMap.tryGet(handle)
	if !ok {
		panic(fmt.Errorf("no callback in handle map: %d", handle))
	}

	uniffiObj.OnLinkedParams(
		FfiConverterSequenceStringINSTANCE.Lift(GoRustBuffer{
			inner: ipAddrs,
		}),
		FfiConverterSequenceStringINSTANCE.Lift(GoRustBuffer{
			inner: dnsAddrs,
		}),
		FfiConverterSequenceStringINSTANCE.Lift(GoRustBuffer{
			inner: routes,
		}),
	)

}

var UniffiVTableCallbackInterfaceElStackVpnEventDelegateINSTANCE = C.UniffiVTableCallbackInterfaceElStackVpnEventDelegate{
	onStatusChange:    (C.UniffiCallbackInterfaceElStackVpnEventDelegateMethod0)(C.el_stack_cgo_dispatchCallbackInterfaceElStackVpnEventDelegateMethod0),
	onConnectionError: (C.UniffiCallbackInterfaceElStackVpnEventDelegateMethod1)(C.el_stack_cgo_dispatchCallbackInterfaceElStackVpnEventDelegateMethod1),
	onLinkedParams:    (C.UniffiCallbackInterfaceElStackVpnEventDelegateMethod2)(C.el_stack_cgo_dispatchCallbackInterfaceElStackVpnEventDelegateMethod2),

	uniffiFree: (C.UniffiCallbackInterfaceFree)(C.el_stack_cgo_dispatchCallbackInterfaceElStackVpnEventDelegateFree),
}

//export el_stack_cgo_dispatchCallbackInterfaceElStackVpnEventDelegateFree
func el_stack_cgo_dispatchCallbackInterfaceElStackVpnEventDelegateFree(handle C.uint64_t) {
	FfiConverterCallbackInterfaceElStackVpnEventDelegateINSTANCE.handleMap.remove(uint64(handle))
}

func (c FfiConverterCallbackInterfaceElStackVpnEventDelegate) register() {
	C.uniffi_el_stack_fn_init_callback_vtable_elstackvpneventdelegate(&UniffiVTableCallbackInterfaceElStackVpnEventDelegateINSTANCE)
}

type FfiConverterOptionalUint64 struct{}

var FfiConverterOptionalUint64INSTANCE = FfiConverterOptionalUint64{}

func (c FfiConverterOptionalUint64) Lift(rb RustBufferI) *uint64 {
	return LiftFromRustBuffer[*uint64](c, rb)
}

func (_ FfiConverterOptionalUint64) Read(reader io.Reader) *uint64 {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterUint64INSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalUint64) Lower(value *uint64) C.RustBuffer {
	return LowerIntoRustBuffer[*uint64](c, value)
}

func (_ FfiConverterOptionalUint64) Write(writer io.Writer, value *uint64) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterUint64INSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalUint64 struct{}

func (_ FfiDestroyerOptionalUint64) Destroy(value *uint64) {
	if value != nil {
		FfiDestroyerUint64{}.Destroy(*value)
	}
}

type FfiConverterOptionalString struct{}

var FfiConverterOptionalStringINSTANCE = FfiConverterOptionalString{}

func (c FfiConverterOptionalString) Lift(rb RustBufferI) *string {
	return LiftFromRustBuffer[*string](c, rb)
}

func (_ FfiConverterOptionalString) Read(reader io.Reader) *string {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterStringINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalString) Lower(value *string) C.RustBuffer {
	return LowerIntoRustBuffer[*string](c, value)
}

func (_ FfiConverterOptionalString) Write(writer io.Writer, value *string) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterStringINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalString struct{}

func (_ FfiDestroyerOptionalString) Destroy(value *string) {
	if value != nil {
		FfiDestroyerString{}.Destroy(*value)
	}
}

type FfiConverterSequenceString struct{}

var FfiConverterSequenceStringINSTANCE = FfiConverterSequenceString{}

func (c FfiConverterSequenceString) Lift(rb RustBufferI) []string {
	return LiftFromRustBuffer[[]string](c, rb)
}

func (c FfiConverterSequenceString) Read(reader io.Reader) []string {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]string, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterStringINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceString) Lower(value []string) C.RustBuffer {
	return LowerIntoRustBuffer[[]string](c, value)
}

func (c FfiConverterSequenceString) Write(writer io.Writer, value []string) {
	if len(value) > math.MaxInt32 {
		panic("[]string is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterStringINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceString struct{}

func (FfiDestroyerSequenceString) Destroy(sequence []string) {
	for _, value := range sequence {
		FfiDestroyerString{}.Destroy(value)
	}
}

const (
	uniffiRustFuturePollReady      int8 = 0
	uniffiRustFuturePollMaybeReady int8 = 1
)

type rustFuturePollFunc func(C.uint64_t, C.UniffiRustFutureContinuationCallback, C.uint64_t)
type rustFutureCompleteFunc[T any] func(C.uint64_t, *C.RustCallStatus) T
type rustFutureFreeFunc func(C.uint64_t)

//export el_stack_uniffiFutureContinuationCallback
func el_stack_uniffiFutureContinuationCallback(data C.uint64_t, pollResult C.int8_t) {
	h := cgo.Handle(uintptr(data))
	waiter := h.Value().(chan int8)
	waiter <- int8(pollResult)
}

func uniffiRustCallAsync[E any, T any, F any](
	errConverter BufReader[*E],
	completeFunc rustFutureCompleteFunc[F],
	liftFunc func(F) T,
	rustFuture C.uint64_t,
	pollFunc rustFuturePollFunc,
	freeFunc rustFutureFreeFunc,
) (T, *E) {
	defer freeFunc(rustFuture)

	pollResult := int8(-1)
	waiter := make(chan int8, 1)

	chanHandle := cgo.NewHandle(waiter)
	defer chanHandle.Delete()

	for pollResult != uniffiRustFuturePollReady {
		pollFunc(
			rustFuture,
			(C.UniffiRustFutureContinuationCallback)(C.el_stack_uniffiFutureContinuationCallback),
			C.uint64_t(chanHandle),
		)
		pollResult = <-waiter
	}

	var goValue T
	var ffiValue F
	var err *E

	ffiValue, err = rustCallWithError(errConverter, func(status *C.RustCallStatus) F {
		return completeFunc(rustFuture, status)
	})
	if err != nil {
		return goValue, err
	}
	return liftFunc(ffiValue), nil
}

//export el_stack_uniffiFreeGorutine
func el_stack_uniffiFreeGorutine(data C.uint64_t) {
	handle := cgo.Handle(uintptr(data))
	defer handle.Delete()

	guard := handle.Value().(chan struct{})
	guard <- struct{}{}
}

func Initialize(productConfig *ElStackProductConfig, socketBufferConfig *ElStackSocketBufferConfig) {
	rustCall(func(_uniffiStatus *C.RustCallStatus) bool {
		C.uniffi_el_stack_fn_func_initialize(FfiConverterElStackProductConfigINSTANCE.Lower(productConfig), FfiConverterElStackSocketBufferConfigINSTANCE.Lower(socketBufferConfig), _uniffiStatus)
		return false
	})
}

func Restart() {
	rustCall(func(_uniffiStatus *C.RustCallStatus) bool {
		C.uniffi_el_stack_fn_func_restart(_uniffiStatus)
		return false
	})
}

func Start(vpnDelegate ElStackVpnEventDelegate, vpnConfig *ElStackVpnConfig, vcConfig *ElStackVcConfig, capturePath *string) *ConnectionError {
	_, err := uniffiRustCallAsync[ConnectionError](
		FfiConverterConnectionErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) struct{} {
			C.ffi_el_stack_rust_future_complete_void(handle, status)
			return struct{}{}
		},
		// liftFn
		func(_ struct{}) struct{} { return struct{}{} },
		C.uniffi_el_stack_fn_func_start(FfiConverterCallbackInterfaceElStackVpnEventDelegateINSTANCE.Lower(vpnDelegate), FfiConverterElStackVpnConfigINSTANCE.Lower(vpnConfig), FfiConverterElStackVcConfigINSTANCE.Lower(vcConfig), FfiConverterOptionalStringINSTANCE.Lower(capturePath)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_el_stack_rust_future_poll_void(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_el_stack_rust_future_free_void(handle)
		},
	)

	return err
}

func Stop() {
	rustCall(func(_uniffiStatus *C.RustCallStatus) bool {
		C.uniffi_el_stack_fn_func_stop(_uniffiStatus)
		return false
	})
}

// TCPのbind(for tcp server)
func TcpBind(bindAddr string) (*TcpListener, *SocketError) {
	res, err := uniffiRustCallAsync[SocketError](
		FfiConverterSocketErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) unsafe.Pointer {
			res := C.ffi_el_stack_rust_future_complete_pointer(handle, status)
			return res
		},
		// liftFn
		func(ffi unsafe.Pointer) *TcpListener {
			return FfiConverterTcpListenerINSTANCE.Lift(ffi)
		},
		C.uniffi_el_stack_fn_func_tcp_bind(FfiConverterStringINSTANCE.Lower(bindAddr)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_el_stack_rust_future_poll_pointer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_el_stack_rust_future_free_pointer(handle)
		},
	)

	return res, err
}

// TCPの接続(for tcp client)
func TcpConnect(host string, serv string, timeoutInterval uint64) (*TcpStream, *SocketError) {
	res, err := uniffiRustCallAsync[SocketError](
		FfiConverterSocketErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) unsafe.Pointer {
			res := C.ffi_el_stack_rust_future_complete_pointer(handle, status)
			return res
		},
		// liftFn
		func(ffi unsafe.Pointer) *TcpStream {
			return FfiConverterTcpStreamINSTANCE.Lift(ffi)
		},
		C.uniffi_el_stack_fn_func_tcp_connect(FfiConverterStringINSTANCE.Lower(host), FfiConverterStringINSTANCE.Lower(serv), FfiConverterUint64INSTANCE.Lower(timeoutInterval)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_el_stack_rust_future_poll_pointer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_el_stack_rust_future_free_pointer(handle)
		},
	)

	return res, err
}

// TLSの接続
func TlsConnect(host string, serv string, timeoutInterval uint64) (*TlsStream, *SocketError) {
	res, err := uniffiRustCallAsync[SocketError](
		FfiConverterSocketErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) unsafe.Pointer {
			res := C.ffi_el_stack_rust_future_complete_pointer(handle, status)
			return res
		},
		// liftFn
		func(ffi unsafe.Pointer) *TlsStream {
			return FfiConverterTlsStreamINSTANCE.Lift(ffi)
		},
		C.uniffi_el_stack_fn_func_tls_connect(FfiConverterStringINSTANCE.Lower(host), FfiConverterStringINSTANCE.Lower(serv), FfiConverterUint64INSTANCE.Lower(timeoutInterval)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_el_stack_rust_future_poll_pointer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_el_stack_rust_future_free_pointer(handle)
		},
	)

	return res, err
}

// UDPのbind(for udp server/client)
func UdpBind(bindAddr string) (*UdpSocket, *SocketError) {
	res, err := uniffiRustCallAsync[SocketError](
		FfiConverterSocketErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) unsafe.Pointer {
			res := C.ffi_el_stack_rust_future_complete_pointer(handle, status)
			return res
		},
		// liftFn
		func(ffi unsafe.Pointer) *UdpSocket {
			return FfiConverterUdpSocketINSTANCE.Lift(ffi)
		},
		C.uniffi_el_stack_fn_func_udp_bind(FfiConverterStringINSTANCE.Lower(bindAddr)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_el_stack_rust_future_poll_pointer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_el_stack_rust_future_free_pointer(handle)
		},
	)

	return res, err
}

// ElStackTcpConn は el_stack の Stream を net.Conn インターフェイスで扱うブリッジです。
// ======================= TCP =======================

type ElStackTcpConn struct {
	stream *TcpStream

	// 受信系
	recvCh    chan []byte
	recvErrCh chan error
	readBuf   []byte
	readOnce  sync.Once
	closed    atomic.Bool

	// 送信直列化
	sendMu sync.Mutex

	// 締切
	readDeadline  time.Time
	writeDeadline time.Time
	deadline      time.Time
}

func newElStackTcpConnFromStream(stream *TcpStream) *ElStackTcpConn {
	c := &ElStackTcpConn{
		stream:    stream,
		recvCh:    make(chan []byte, 128),
		recvErrCh: make(chan error, 1),
	}
	c.startReader()
	return c
}

func isSupportedTcpNetwork(network string) bool {
	switch network {
	case "tcp", "tcp4", "tcp6":
		return true
	default:
		return false
	}
}

// NewElStackTcpConn は net.Dial と同じ引数を受け取り、TcpConnect を通じて net.Conn 互換の接続を生成します。
func NewElStackTcpConn(network, address string) (net.Conn, error) {
	if !isSupportedTcpNetwork(network) {
		return nil, fmt.Errorf("unsupported network: %s", network)
	}

	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if host == "" {
		switch network {
		case "tcp6":
			host = "::1"
		case "tcp4":
			host = "127.0.0.1"
		default:
			host = "localhost"
		}
	}

	stream, serr := TcpConnect(host, port, 0)
	if serr != nil {
		return nil, mapSocketErrorToIO(serr)
	}

	return newElStackTcpConnFromStream(stream), nil
}

type ElStackTcpListener struct {
	listener *TcpListener
	network  string
	closed   atomic.Bool
}

// NewElStackTcpListener は net.Listen と同じインターフェイスで TCP リスナーを生成します。
func NewElStackTcpListener(network, address string) (net.Listener, error) {
	if !isSupportedTcpNetwork(network) {
		return nil, fmt.Errorf("unsupported network: %s", network)
	}

	listener, serr := TcpBind(address)
	if serr != nil {
		return nil, mapSocketErrorToIO(serr)
	}

	return &ElStackTcpListener{
		listener: listener,
		network:  network,
	}, nil
}

func (l *ElStackTcpListener) Accept() (net.Conn, error) {
	for {
		if l.closed.Load() {
			return nil, os.ErrClosed
		}

		stream, err := l.listener.Accept(200)
		if err != nil {
			// タイムアウトは無視して再試行
			if errors.Is(err, ErrSocketErrorTcpAcceptTimeout) {
				continue
			}
			return nil, mapSocketErrorToIO(err)
		}

		return newElStackTcpConnFromStream(stream), nil
	}
}

func (l *ElStackTcpListener) Close() error {
	if l.closed.Swap(true) {
		return os.ErrClosed
	}
	l.listener.Destroy()
	return nil
}

func (l *ElStackTcpListener) Addr() net.Addr {
	addrStr := l.listener.BindAddr()
	addr, err := net.ResolveTCPAddr(l.network, addrStr)
	if err != nil {
		return &net.TCPAddr{}
	}
	return addr
}

// -------- helpers: deadline -> seconds ----------
func ceilSeconds(d time.Duration) uint64 {
	if d <= 0 {
		return 0
	}
	// 秒に切り上げ（1nsでも残っていれば1秒）
	return uint64((d + time.Second - 1) / time.Second)
}

func (c *ElStackTcpConn) recvTimeoutSecsFromDeadline() uint64 {
	if c.readDeadline.IsZero() {
		return 0
	}
	return ceilSeconds(time.Until(c.readDeadline))
}

func (c *ElStackTcpConn) sendTimeoutSecsFromDeadline() uint64 {
	if c.writeDeadline.IsZero() {
		return 0
	}
	return ceilSeconds(time.Until(c.writeDeadline))
}

func (c *ElStackTcpConn) startReader() {
	c.readOnce.Do(func() {
		go func() {
			defer close(c.recvCh)
			for !c.closed.Load() {
				// Read 締切を毎ループ反映して Rust 側に委譲
				timeoutSecs := c.recvTimeoutSecsFromDeadline()
				data, err := c.stream.RecvSafe(timeoutSecs)
				if err != nil {
					// io.EOF などもここに流して Read 側で受け取る
					select {
					case c.recvErrCh <- err:
					default:
					}
					return
				}
				if len(data) == 0 {
					// 0バイト＝EOF扱い
					select {
					case c.recvErrCh <- io.EOF:
					default:
					}
					return
				}
				// 次段でバッファ再利用されないようコピーしておく
				p := make([]byte, len(data))
				copy(p, data)
				// バックプレッシャ：満杯時はブロックしてでも運ぶ
				c.recvCh <- p
			}
		}()
	})
}

func (c *ElStackTcpConn) Read(b []byte) (int, error) {
	if c.closed.Load() {
		return 0, os.ErrClosed
	}

	// 期限タイマー（ユーザー体感の即時性のため）
	timer := (*time.Timer)(nil)
	if !c.readDeadline.IsZero() {
		if d := time.Until(c.readDeadline); d <= 0 {
			return 0, os.ErrDeadlineExceeded
		} else {
			timer = time.NewTimer(d)
			defer timer.Stop()
		}
	}

	// 余りがあれば先に返す
	if len(c.readBuf) > 0 {
		n := copy(b, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}

	select {
	case pkt, ok := <-c.recvCh:
		if !ok {
			// 読み終わり。エラーが来ていればそちらを優先
			select {
			case err := <-c.recvErrCh:
				if err == io.EOF {
					return 0, io.EOF
				}
				return 0, mapSocketErrorToIO(err)
			default:
				return 0, io.EOF
			}
		}
		// b に入るだけ入れて、余りは readBuf へ
		if len(pkt) <= len(b) {
			n := copy(b, pkt)
			return n, nil
		} else {
			n := copy(b, pkt[:len(b)])
			c.readBuf = append(c.readBuf[:0], pkt[n:]...)
			return n, nil
		}

	case err := <-c.recvErrCh:
		if err == io.EOF {
			return 0, io.EOF
		}
		return 0, mapSocketErrorToIO(err)

	case <-timerC(timer):
		return 0, os.ErrDeadlineExceeded
	}
}

func (c *ElStackTcpConn) Write(b []byte) (int, error) {
	if c.closed.Load() {
		return 0, os.ErrClosed
	}
	c.sendMu.Lock()
	defer c.sendMu.Unlock()

	// 期限切れ即時判定
	if !c.writeDeadline.IsZero() && time.Until(c.writeDeadline) <= 0 {
		return 0, os.ErrDeadlineExceeded
	}

	// 期限から秒（切り上げ）に変換し、Rust 側に渡す
	timeoutSecs := c.sendTimeoutSecsFromDeadline()
	p := append([]byte(nil), b...) // 念のためコピー
	if err := c.stream.Send(p, timeoutSecs); isNilError(err) {
		return len(b), nil
	} else {
		return 0, mapSocketErrorToIO(err)
	}
}

func (c *ElStackTcpConn) Close() error {
	if c.closed.Swap(true) {
		return os.ErrClosed
	}
	// Rust側 close（Destroy で ARC 解放・Close 呼び出しは Rust 実装に合わせる）
	c.stream.Close()
	c.stream.Destroy()
	return nil
}

func (c *ElStackTcpConn) LocalAddr() net.Addr {
	s := c.stream.LocalAddr()
	a, err := net.ResolveTCPAddr("tcp", s)
	if err != nil {
		return &net.TCPAddr{}
	}
	return a
}

func (c *ElStackTcpConn) RemoteAddr() net.Addr {
	s := c.stream.PeerAddr()
	a, err := net.ResolveTCPAddr("tcp", s)
	if err != nil {
		return &net.TCPAddr{}
	}
	return a
}

func (c *ElStackTcpConn) SetDeadline(t time.Time) error {
	c.deadline = t
	c.readDeadline = t
	c.writeDeadline = t
	return nil
}

func (c *ElStackTcpConn) SetReadDeadline(t time.Time) error {
	c.readDeadline = t
	return nil
}

func (c *ElStackTcpConn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline = t
	return nil
}

// ======================= UDP =======================

type ElStackUdpConn struct {
	sock *UdpSocket

	network string
	closed  bool

	// 送信直列化
	sendMu sync.Mutex

	// 締切
	readDeadline  time.Time
	writeDeadline time.Time
	deadline      time.Time
}

func isSupportedUdpNetwork(network string) bool {
	switch network {
	case "udp", "udp4", "udp6":
		return true
	default:
		return false
	}
}

// NewElStackUdpConn は net.ListenUDP と同様の引数を受け取り、UdpBind を通じて UDP ソケットを生成します。
func NewElStackUdpConn(network string, laddr *net.UDPAddr) (*ElStackUdpConn, error) {
	if !isSupportedUdpNetwork(network) {
		return nil, fmt.Errorf("unsupported network: %s", network)
	}

	bindAddr := ""
	if laddr == nil {
		switch network {
		case "udp6":
			bindAddr = "[::]:0"
		default:
			bindAddr = "0.0.0.0:0"
		}
	} else {
		bindAddr = laddr.String()
	}

	sock, serr := UdpBind(bindAddr)
	if serr != nil {
		return nil, mapSocketErrorToIO(serr)
	}

	return &ElStackUdpConn{sock: sock, network: network}, nil
}

func toElStackAddr(addr *net.UDPAddr) string {
	if addr == nil {
		return ""
	}
	return addr.String()
}

func (c *ElStackUdpConn) ReadFromUDP(b []byte) (int, *net.UDPAddr, error) {
	if c.closed {
		return 0, nil, os.ErrClosed
	}
	// 期限切れ即時判定
	if !c.readDeadline.IsZero() && time.Until(c.readDeadline) <= 0 {
		return 0, nil, os.ErrDeadlineExceeded
	}
	// 期限から秒（切り上げ）に変換し、Rust 側に渡す
	timeoutSecs := ceilSeconds(time.Until(c.readDeadline))
	ret, err := c.sock.RecvFrom(timeoutSecs) // Rust 側で timeout 秒を処理
	if err != nil {
		return 0, nil, mapSocketErrorToIO(err)
	}
	n := copy(b, ret.Buf)
	udpAddr, err2 := net.ResolveUDPAddr("udp", ret.FromAddr)
	if err2 != nil {
		return 0, nil, err2
	}
	return n, udpAddr, nil
}

func (c *ElStackUdpConn) WriteToUDP(b []byte, addr *net.UDPAddr) (int, error) {
	if c.closed {
		return 0, os.ErrClosed
	}
	c.sendMu.Lock()
	defer c.sendMu.Unlock()

	// 期限切れ即時判定
	if !c.writeDeadline.IsZero() && time.Until(c.writeDeadline) <= 0 {
		return 0, os.ErrDeadlineExceeded
	}

	timeoutSecs := ceilSeconds(time.Until(c.writeDeadline))
	rawAddr := toElStackAddr(addr)
	n, err := c.sock.SendTo(b, rawAddr, timeoutSecs)
	if err != nil {
		return 0, mapSocketErrorToIO(err)
	}
	return int(n), nil
}

func (c *ElStackUdpConn) Close() error {
	if c.closed {
		return os.ErrClosed
	}
	c.closed = true
	c.sock.Destroy()
	return nil
}

func (c *ElStackUdpConn) LocalAddr() net.Addr {
	s := c.sock.LocalAddr()
	network := c.network
	if network == "" {
		network = "udp"
	}
	a, err := net.ResolveUDPAddr(network, s)
	if err != nil {
		return &net.UDPAddr{}
	}
	return a
}

func (c *ElStackUdpConn) SetDeadline(t time.Time) error {
	c.deadline = t
	c.readDeadline = t
	c.writeDeadline = t
	return nil
}

func (c *ElStackUdpConn) SetReadDeadline(t time.Time) error {
	c.readDeadline = t
	return nil
}

func (c *ElStackUdpConn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline = t
	return nil
}

// timerC は nil セーフなタイマー用チャネル取得
func timerC(t *time.Timer) <-chan time.Time {
	if t == nil {
		// nil の場合は読み出せないチャネルを返す（select の他分岐だけが有効になる）
		return make(<-chan time.Time)
	}
	return t.C
}

// 型付き nil (e.g. *SomeError(nil)) を正しく判定するためのヘルパ
func isNilError(err error) bool {
	if err == nil {
		return true
	}
	v := reflect.ValueOf(err)
	return v.Kind() == reflect.Ptr && v.IsNil()
}

// Rust側の SocketError 群を Go の一般的な I/O エラーにマップ
func mapSocketErrorToIO(err error) error {
	if isNilError(err) {
		return nil
	}
	if errors.Is(err, ErrSocketErrorConnectionClosed) {
		return io.EOF
	}
	if errors.Is(err, ErrSocketErrorTcpConnectError) ||
		errors.Is(err, ErrSocketErrorTcpAcceptError) ||
		errors.Is(err, ErrSocketErrorTcpBindError) ||
		errors.Is(err, ErrSocketErrorUdpBindError) ||
		errors.Is(err, ErrSocketErrorQuicConnectError) {
		return os.ErrClosed
	}
	if errors.Is(err, ErrSocketErrorTlsError) ||
		errors.Is(err, ErrSocketErrorTlsHandshakeError) ||
		errors.Is(err, ErrSocketErrorInvalidCertificateError) {
		return io.ErrUnexpectedEOF
	}
	if errors.Is(err, ErrSocketErrorAddressConvertError) ||
		errors.Is(err, ErrSocketErrorInvalidHostnameError) ||
		errors.Is(err, ErrSocketErrorAddressError) {
		return errors.New("invalid address")
	}
	if errors.Is(err, ErrSocketErrorNameResolvError) {
		return errors.New("name resolution failed")
	}
	// デフォルトはオリジナルを返す
	return err
}
