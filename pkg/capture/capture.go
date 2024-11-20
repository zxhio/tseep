package capture

import (
	"context"
	"net"
	"syscall"
	"time"
	"unsafe"

	"tseep/pkg/poll"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

type captureOpts struct {
	timeout          time.Duration
	readZeroCopy     bool
	readErrorHandler func(error)
}

type CaptureOpt func(*captureOpts)

func WithCaptureTimeout(d time.Duration) CaptureOpt {
	return func(o *captureOpts) { o.timeout = d }
}

// Read data for memory reuse each time,
// not suitable for asynchronous scenarios.
func WithCaptureReadZeroCopy(enable bool) CaptureOpt {
	return func(o *captureOpts) { o.readZeroCopy = enable }
}

func WithCaptureReadErrorHandle(eh func(error)) CaptureOpt {
	return func(o *captureOpts) { o.readErrorHandler = eh }
}

type Capture struct {
	rawFd  int
	poller *poll.ReadPoller
	buffer []byte
	dataCh chan []byte
	opts   captureOpts
}

func NewCaptureByIfaceIndex(ifIndex int, opts ...CaptureOpt) (*Capture, error) {
	var o captureOpts
	for _, opt := range opts {
		opt(&o)
	}

	rawFd, err := OpenRawSocket(ifIndex)
	if err != nil {
		return nil, err
	}

	poller, err := poll.New()
	if err != nil {
		return nil, err
	}

	c := &Capture{
		rawFd:  rawFd,
		poller: poller,
		buffer: make([]byte, 1024*64),
		dataCh: make(chan []byte, 128),
		opts:   o,
	}

	poller.Add(rawFd, func(fd int) {
		data, err := c.recvmsg(fd)
		if err != nil {
			if c.opts.readErrorHandler != nil {
				c.opts.readErrorHandler(err)
			}
			return
		}

		if c.opts.readZeroCopy {
			c.dataCh <- data
		} else {
			ownData := make([]byte, len(data))
			copy(ownData, data)
			c.dataCh <- ownData
		}
	})
	return c, nil
}

func NewCaptureByIfaceName(name string, opts ...CaptureOpt) (*Capture, error) {
	link, err := net.InterfaceByName(name)
	if err != nil {
		return nil, errors.Wrap(err, "net.InterfaceByName")
	}
	return NewCaptureByIfaceIndex(link.Index)
}

func (c *Capture) Serve(ctx context.Context) error {
	var opts []poll.PollOpt
	if c.opts.timeout != 0 {
		opts = append(opts, poll.WithTimeout(c.opts.timeout))
	}
	return c.poller.PollWithContext(ctx, opts...)
}

// If WithCaptureReadZeroCopy(true) has been called, the read data slice will reused.
func (c *Capture) Read() <-chan []byte {
	return c.dataCh
}

func (c *Capture) Close() {
	if c.poller != nil {
		c.poller.Close()
	}
	close(c.dataCh)
}

func (c *Capture) recvmsg(fd int) ([]byte, error) {
	// ref: https://github.com/google/gopacket/blob/master/pcapgo/capture.go#L45
	// we could use unix.Recvmsg, but that does a memory allocation (for the returned sockaddr) :(
	var msg unix.Msghdr
	var sa unix.RawSockaddrLinklayer

	msg.Name = (*byte)(unsafe.Pointer(&sa))
	msg.Namelen = uint32(unsafe.Sizeof(sa))

	var iov unix.Iovec
	if len(c.buffer) > 0 {
		iov.Base = &c.buffer[0]
		iov.SetLen(len(c.buffer))
	}
	msg.Iov = &iov
	msg.Iovlen = 1

	// use msg_trunc so we know packet size without auxdata, which might be missing
	n, _, e := syscall.Syscall(unix.SYS_RECVMSG, uintptr(fd), uintptr(unsafe.Pointer(&msg)), uintptr(unix.MSG_TRUNC))
	if e != 0 {
		return nil, errors.Wrap(e, "unix.SYS_RECVMSG")
	}

	captureLen := min(int(n), len(c.buffer)-1)
	return c.buffer[:captureLen], nil
}
