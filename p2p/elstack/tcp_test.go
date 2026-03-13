package elstack

import (
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

type testAddr string

func (a testAddr) Network() string { return "tcp" }
func (a testAddr) String() string  { return string(a) }

type readResult struct {
	data []byte
	err  error
}

type deadlineTrackingConn struct {
	readCh    chan readResult
	closeOnce sync.Once
	closeCh   chan struct{}

	mu                 sync.Mutex
	readDeadlineCalls  int
	writeDeadlineCalls int
}

func newDeadlineTrackingConn() *deadlineTrackingConn {
	return &deadlineTrackingConn{
		readCh:  make(chan readResult, 16),
		closeCh: make(chan struct{}),
	}
}

func (c *deadlineTrackingConn) enqueueRead(data []byte, err error) {
	payload := append([]byte(nil), data...)
	c.readCh <- readResult{data: payload, err: err}
}

func (c *deadlineTrackingConn) deadlineCalls() (readCalls int, writeCalls int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.readDeadlineCalls, c.writeDeadlineCalls
}

func (c *deadlineTrackingConn) Read(b []byte) (int, error) {
	select {
	case <-c.closeCh:
		return 0, net.ErrClosed
	case res := <-c.readCh:
		n := copy(b, res.data)
		return n, res.err
	}
}

func (c *deadlineTrackingConn) Write(b []byte) (int, error) {
	select {
	case <-c.closeCh:
		return 0, net.ErrClosed
	default:
		return len(b), nil
	}
}

func (c *deadlineTrackingConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closeCh)
	})
	return nil
}

func (c *deadlineTrackingConn) LocalAddr() net.Addr           { return testAddr("127.0.0.1:1") }
func (c *deadlineTrackingConn) RemoteAddr() net.Addr          { return testAddr("127.0.0.1:2") }
func (c *deadlineTrackingConn) SetDeadline(t time.Time) error { return nil }
func (c *deadlineTrackingConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadlineCalls++
	c.mu.Unlock()
	return nil
}
func (c *deadlineTrackingConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.writeDeadlineCalls++
	c.mu.Unlock()
	return nil
}

func TestElStackTcpConnReadDeadlineCanBeShortenedWhileBlocking(t *testing.T) {
	inner := newDeadlineTrackingConn()
	conn := newElStackTcpConn(inner)
	t.Cleanup(func() { _ = conn.Close() })

	if err := conn.SetReadDeadline(time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("SetReadDeadline failed: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 1)
		_, err := conn.Read(buf)
		errCh <- err
	}()

	time.Sleep(25 * time.Millisecond)
	if err := conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline update failed: %v", err)
	}

	select {
	case err := <-errCh:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("expected deadline exceeded, got: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Read did not wake after deadline update")
	}
}

func TestElStackTcpConnReadCanResumeAfterDeadlineTimeout(t *testing.T) {
	inner := newDeadlineTrackingConn()
	conn := newElStackTcpConn(inner)
	t.Cleanup(func() { _ = conn.Close() })

	if err := conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline failed: %v", err)
	}

	buf := make([]byte, 4)
	_, err := conn.Read(buf)
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expected first read timeout, got: %v", err)
	}

	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("failed to clear read deadline: %v", err)
	}
	inner.enqueueRead([]byte("abc"), nil)

	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("second read failed: %v", err)
	}
	if n != 3 {
		t.Fatalf("expected 3 bytes, got %d", n)
	}
	if string(buf[:n]) != "abc" {
		t.Fatalf("unexpected payload: %q", string(buf[:n]))
	}
}

func TestElStackTcpConnDeadlinesAreHandledInWrapper(t *testing.T) {
	inner := newDeadlineTrackingConn()
	conn := newElStackTcpConn(inner)
	t.Cleanup(func() { _ = conn.Close() })

	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline failed: %v", err)
	}
	readCalls, writeCalls := inner.deadlineCalls()
	if readCalls != 0 || writeCalls != 0 {
		t.Fatalf("expected no inner deadline calls after SetReadDeadline, got read=%d write=%d", readCalls, writeCalls)
	}

	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetDeadline failed: %v", err)
	}
	readCalls, writeCalls = inner.deadlineCalls()
	if readCalls != 0 {
		t.Fatalf("expected inner SetReadDeadline to stay unused, got %d calls", readCalls)
	}
	if writeCalls != 1 {
		t.Fatalf("expected one inner SetWriteDeadline call, got %d", writeCalls)
	}
}
