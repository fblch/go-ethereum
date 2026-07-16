package el_stack

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"reflect"
	"sync"
	"sync/atomic"
	"time"
)

// Compatibility aliases for earlier generated constructor names.
func NewDefaultElStackBufferPoolConfig() *ElStackBufferPoolConfig {
	return ElStackBufferPoolConfigNewDefault()
}

func NewDefaultElStackNicConfig() *ElStackNicConfig {
	return ElStackNicConfigNewDefault()
}

func NewDefaultElStackRuntimeConfig() *ElStackRuntimeConfig {
	return ElStackRuntimeConfigNewDefault()
}

func NewDefaultElStackStackConfig() *ElStackStackConfig {
	return ElStackStackConfigNewDefault()
}

// RecvSafe catches internal panics and converts EOF-like cases into io.EOF.
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
		return nil, io.EOF
	}
	return data, nil
}

// RecvSafe catches internal panics and converts EOF-like cases into io.EOF.
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
		return nil, io.EOF
	}
	return data, nil
}

// ElStackTcpConn bridges TcpStream into net.Conn.
type ElStackTcpConn struct {
	stream  *TcpStream
	network string

	localAddr  *net.TCPAddr
	remoteAddr *net.TCPAddr

	readMu  sync.Mutex
	readBuf []byte
	closed  atomic.Bool

	sendMu sync.Mutex

	readDeadline  time.Time
	writeDeadline time.Time
	deadline      time.Time
}

func resolveTCPAddrOrZero(network, addr string) *net.TCPAddr {
	if network == "" {
		network = "tcp"
	}
	tcpAddr, err := net.ResolveTCPAddr(network, addr)
	if err != nil {
		return &net.TCPAddr{}
	}
	return tcpAddr
}

func resolveUDPAddrOrZero(network, addr string) *net.UDPAddr {
	if network == "" {
		network = "udp"
	}
	udpAddr, err := net.ResolveUDPAddr(network, addr)
	if err != nil {
		return &net.UDPAddr{}
	}
	return udpAddr
}

func newElStackTcpConnFromStream(stream *TcpStream, network string) *ElStackTcpConn {
	return &ElStackTcpConn{
		stream:     stream,
		network:    network,
		localAddr:  resolveTCPAddrOrZero(network, stream.LocalAddr()),
		remoteAddr: resolveTCPAddrOrZero(network, stream.PeerAddr()),
	}
}

func isSupportedTcpNetwork(network string) bool {
	switch network {
	case "tcp", "tcp4", "tcp6":
		return true
	default:
		return false
	}
}

func NewElStackTcpConn(network, address string, timeout time.Duration) (net.Conn, error) {
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
	dialAddr := opAddr(network, net.JoinHostPort(host, port))

	stream, serr := TcpConnect(host, port, uint64(timeout.Seconds()))
	if serr != nil {
		return nil, mapSocketErrorToNetError("dial", network, nil, dialAddr, serr)
	}

	return newElStackTcpConnFromStream(stream, network), nil
}

type ElStackTcpListener struct {
	listener *TcpListener
	network  string
	addr     *net.TCPAddr
	closed   atomic.Bool
}

func NewElStackTcpListener(network, address string) (net.Listener, error) {
	if !isSupportedTcpNetwork(network) {
		return nil, fmt.Errorf("unsupported network: %s", network)
	}

	listener, serr := TcpBind(address)
	if serr != nil {
		return nil, mapSocketErrorToNetError("listen", network, nil, opAddr(network, address), serr)
	}

	return &ElStackTcpListener{
		listener: listener,
		network:  network,
		addr:     resolveTCPAddrOrZero(network, listener.BindAddr()),
	}, nil
}

func (l *ElStackTcpListener) Accept() (net.Conn, error) {
	for {
		if l.closed.Load() {
			return nil, net.ErrClosed
		}

		stream, err := l.listener.Accept(0)
		if err != nil {
			return nil, mapSocketErrorToNetError("accept", l.network, nil, l.addr, err)
		}

		return newElStackTcpConnFromStream(stream, l.network), nil
	}
}

func (l *ElStackTcpListener) Close() error {
	if l.closed.Swap(true) {
		return net.ErrClosed
	}
	l.listener.Destroy()
	return nil
}

func (l *ElStackTcpListener) Addr() net.Addr {
	return l.addr
}

func ceilSeconds(d time.Duration) uint64 {
	if d <= 0 {
		return 0
	}
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

func (c *ElStackTcpConn) Read(b []byte) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	if len(b) == 0 {
		return 0, nil
	}

	c.readMu.Lock()
	defer c.readMu.Unlock()

	if len(c.readBuf) > 0 {
		n := copy(b, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}

	if !c.readDeadline.IsZero() && time.Until(c.readDeadline) <= 0 {
		return 0, os.ErrDeadlineExceeded
	}

	timeoutSecs := c.recvTimeoutSecsFromDeadline()
	pkt, err := c.stream.RecvSafe(timeoutSecs)
	if err != nil {
		return 0, mapSocketReadErrorToNetError(c.closed.Load(), c.network, c.localAddr, c.remoteAddr, err)
	}

	if len(pkt) <= len(b) {
		n := copy(b, pkt)
		return n, nil
	}

	n := copy(b, pkt[:len(b)])
	c.readBuf = append(c.readBuf[:0], pkt[n:]...)
	return n, nil
}

func (c *ElStackTcpConn) Write(b []byte) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	c.sendMu.Lock()
	defer c.sendMu.Unlock()

	if !c.writeDeadline.IsZero() && time.Until(c.writeDeadline) <= 0 {
		return 0, os.ErrDeadlineExceeded
	}

	timeoutSecs := c.sendTimeoutSecsFromDeadline()
	p := append([]byte(nil), b...)
	serr := c.stream.Send(p, timeoutSecs)
	if isNilError(serr) {
		return len(b), nil
	}
	return 0, mapSocketErrorToNetError("write", c.network, c.localAddr, c.remoteAddr, serr)
}

func (c *ElStackTcpConn) Close() error {
	if c.closed.Swap(true) {
		return net.ErrClosed
	}
	c.stream.Close()
	c.stream.Destroy()
	return nil
}

func (c *ElStackTcpConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *ElStackTcpConn) RemoteAddr() net.Addr {
	return c.remoteAddr
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

type ElStackUdpConn struct {
	sock *UdpSocket

	network   string
	localAddr *net.UDPAddr
	closed    bool

	sendMu sync.Mutex

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
		return nil, mapSocketErrorToNetError("listen", network, nil, opAddr(network, bindAddr), serr)
	}

	return &ElStackUdpConn{
		sock:      sock,
		network:   network,
		localAddr: resolveUDPAddrOrZero(network, sock.LocalAddr()),
	}, nil
}

func toElStackAddr(addr *net.UDPAddr) string {
	if addr == nil {
		return ""
	}
	return addr.String()
}

func (c *ElStackUdpConn) ReadFromUDP(b []byte) (int, *net.UDPAddr, error) {
	if c.closed {
		return 0, nil, net.ErrClosed
	}
	if !c.readDeadline.IsZero() && time.Until(c.readDeadline) <= 0 {
		return 0, nil, os.ErrDeadlineExceeded
	}
	timeoutSecs := ceilSeconds(time.Until(c.readDeadline))
	ret, err := c.sock.RecvFrom(timeoutSecs)
	if err != nil {
		return 0, nil, mapSocketErrorToNetError("read", c.network, c.localAddr, nil, err)
	}
	n := copy(b, ret.Buf)
	udpAddr, err2 := net.ResolveUDPAddr("udp", ret.FromAddr)
	if err2 != nil {
		return 0, nil, err2
	}
	return n, udpAddr, nil
}

func (c *ElStackUdpConn) ReadFromUDPAddrPort(b []byte) (n int, addr netip.AddrPort, err error) {
	n, udpAddr, err := c.ReadFromUDP(b)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	return n, udpAddr.AddrPort(), nil
}

func (c *ElStackUdpConn) WriteToUDP(b []byte, addr *net.UDPAddr) (int, error) {
	if c.closed {
		return 0, net.ErrClosed
	}
	c.sendMu.Lock()
	defer c.sendMu.Unlock()

	if !c.writeDeadline.IsZero() && time.Until(c.writeDeadline) <= 0 {
		return 0, os.ErrDeadlineExceeded
	}

	timeoutSecs := ceilSeconds(time.Until(c.writeDeadline))
	rawAddr := toElStackAddr(addr)
	n, err := c.sock.SendTo(b, rawAddr, timeoutSecs)
	if err != nil {
		return 0, mapSocketErrorToNetError("write", c.network, c.localAddr, addr, err)
	}
	return int(n), nil
}

func (c *ElStackUdpConn) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error) {
	return c.WriteToUDP(b, net.UDPAddrFromAddrPort(addr))
}

func (c *ElStackUdpConn) Close() error {
	if c.closed {
		return net.ErrClosed
	}
	c.closed = true
	c.sock.Destroy()
	return nil
}

func (c *ElStackUdpConn) LocalAddr() net.Addr {
	return c.localAddr
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

func isNilError(err error) bool {
	if err == nil {
		return true
	}
	v := reflect.ValueOf(err)
	return v.Kind() == reflect.Ptr && v.IsNil()
}

type stringNetAddr struct {
	network string
	address string
}

func (a stringNetAddr) Network() string {
	return a.network
}

func (a stringNetAddr) String() string {
	return a.address
}

func normalizeNetAddr(addr net.Addr) net.Addr {
	if addr == nil {
		return nil
	}
	v := reflect.ValueOf(addr)
	if v.Kind() == reflect.Ptr && v.IsNil() {
		return nil
	}
	return addr
}

func netAddrString(addr net.Addr) string {
	addr = normalizeNetAddr(addr)
	if addr == nil {
		return ""
	}
	return addr.String()
}

func opAddr(network, address string) net.Addr {
	if address == "" {
		return nil
	}
	return stringNetAddr{network: network, address: address}
}

func mapSocketReadErrorToNetError(closed bool, network string, sourceAddr, addr net.Addr, err error) error {
	if isNilError(err) {
		return nil
	}
	if err == io.EOF {
		return io.EOF
	}
	if errors.Is(err, ErrSocketErrorConnectionClosed) && !closed {
		return io.EOF
	}
	return mapSocketErrorToNetError("read", network, sourceAddr, addr, err)
}

func mapSocketErrorToNetError(op, network string, sourceAddr, addr net.Addr, err error) error {
	if isNilError(err) {
		return nil
	}
	sourceAddr = normalizeNetAddr(sourceAddr)
	addr = normalizeNetAddr(addr)

	mkOpErr := func(inner error) error {
		return &net.OpError{
			Op:     op,
			Net:    network,
			Source: sourceAddr,
			Addr:   addr,
			Err:    inner,
		}
	}

	addrText := netAddrString(addr)
	if addrText == "" {
		addrText = netAddrString(sourceAddr)
	}
	dnsName := addrText
	if host, _, splitErr := net.SplitHostPort(dnsName); splitErr == nil {
		dnsName = host
	}

	switch {
	case errors.Is(err, ErrSocketErrorConnectionClosed):
		return net.ErrClosed
	case errors.Is(err, ErrSocketErrorTcpConnectTimeout),
		errors.Is(err, ErrSocketErrorTlsHandshakeTimeout),
		errors.Is(err, ErrSocketErrorTcpAcceptTimeout),
		errors.Is(err, ErrSocketErrorTcpRecvTimeout),
		errors.Is(err, ErrSocketErrorTcpSendTimeout),
		errors.Is(err, ErrSocketErrorUdpRecvTimeout),
		errors.Is(err, ErrSocketErrorUdpSendTimeout):
		return mkOpErr(os.ErrDeadlineExceeded)
	case errors.Is(err, ErrSocketErrorAddressConvertError),
		errors.Is(err, ErrSocketErrorInvalidHostnameError),
		errors.Is(err, ErrSocketErrorAddressError):
		return mkOpErr(&net.AddrError{
			Err:  "invalid address",
			Addr: addrText,
		})
	case errors.Is(err, ErrSocketErrorNameResolvError):
		return mkOpErr(&net.DNSError{
			Err:  "name resolution failed",
			Name: dnsName,
		})
	default:
		return mkOpErr(err)
	}
}
