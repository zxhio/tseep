package poll

import (
	"context"
	"sync"
	"syscall"
	"time"

	"github.com/pkg/errors"
)

type pollOpts struct {
	timeout time.Duration
}

type PollOpt func(*pollOpts)

func WithTimeout(d time.Duration) PollOpt {
	return func(o *pollOpts) { o.timeout = d }
}

type ReadHandler func(fd int)

type ReadPoller struct {
	handlers map[int]ReadHandler
	mu       sync.RWMutex
	efd      int
}

func New() (*ReadPoller, error) {
	efd, err := syscall.EpollCreate1(0)
	if err != nil {
		return nil, errors.Wrap(err, "syscall.EpollCreate1")
	}
	err = syscall.SetNonblock(efd, true)
	if err != nil {
		syscall.Close(efd)
		return nil, errors.Wrap(err, "syscall.SetNonblock")
	}
	return &ReadPoller{
		handlers: make(map[int]ReadHandler),
		efd:      efd,
	}, nil
}

func (p *ReadPoller) Close() {
	if p.efd != 0 {
		syscall.Close(p.efd)
	}
}

func (p *ReadPoller) Add(fd int, handler ReadHandler) error {
	err := syscall.EpollCtl(p.efd, syscall.EPOLL_CTL_ADD, fd, &syscall.EpollEvent{Fd: int32(fd), Events: syscall.EPOLLIN})
	if err != nil {
		return errors.Wrap(err, "syscall.EpollCtl")
	}

	p.mu.Lock()
	p.handlers[fd] = handler
	p.mu.Unlock()
	return nil
}

func (p *ReadPoller) Del(fd int) error {
	err := syscall.EpollCtl(p.efd, syscall.EPOLL_CTL_DEL, fd, &syscall.EpollEvent{Fd: int32(fd), Events: syscall.EPOLLIN})
	if err != nil {
		return errors.Wrap(err, "syscall.EpollCtl")
	}

	p.mu.Lock()
	delete(p.handlers, fd)
	p.mu.Unlock()
	return nil
}

func (p *ReadPoller) Len() int {
	p.mu.RLock()
	l := len(p.handlers)
	p.mu.RUnlock()
	return l
}

func (p *ReadPoller) Poll(opts ...PollOpt) error {
	return p.PollWithContext(context.Background(), opts...)
}

func (p *ReadPoller) PollWithContext(ctx context.Context, opts ...PollOpt) error {
	var o pollOpts
	for _, opt := range opts {
		opt(&o)
	}
	msec := 50
	if o.timeout > time.Millisecond*50 { // 50ms
		msec = int(o.timeout / time.Millisecond)
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		pfds := []syscall.EpollEvent{}
		p.mu.RLock()
		for fd := range p.handlers {
			pfds = append(pfds, syscall.EpollEvent{Fd: int32(fd), Events: syscall.EPOLLIN})
		}
		p.mu.RUnlock()

		n, err := syscall.EpollWait(p.efd, pfds, msec)
		if err != nil && err != syscall.EINTR {
			return errors.Wrap(err, "syscall.EpollWait")
		}

		for i := 0; i < n; i++ {
			p.mu.RLock()
			cb, ok := p.handlers[int(pfds[i].Fd)]
			p.mu.RUnlock()
			if ok {
				cb(int(pfds[i].Fd))
			}
		}
	}
}
