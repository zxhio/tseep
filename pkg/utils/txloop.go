package utils

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/pkg/errors"
)

type TxLoopOutputData struct {
	RawData []byte
	Message string
	Err     error
}

type txLoopOpts struct {
	dial     func(string, string) (net.Conn, error)
	output   func(*TxLoopOutputData)
	duration time.Duration
}

type TxLoopOpt func(*txLoopOpts)

func WithTxLoopDial(dial func(string, string) (net.Conn, error)) TxLoopOpt {
	return func(o *txLoopOpts) { o.dial = dial }
}

func WithTxLoopOutput(output func(*TxLoopOutputData)) TxLoopOpt {
	return func(o *txLoopOpts) { o.output = output }
}

func WithTxLoopHealthCheckDur(d time.Duration) TxLoopOpt {
	return func(o *txLoopOpts) { o.duration = d }
}

func txLoopEmptyOutput(*TxLoopOutputData) {}

type TxLoop struct {
	network string
	addr    string
	opts    txLoopOpts
	conn    net.Conn
	dataCh  chan []byte
	closeCh chan struct{}
}

func NewTxLoop(network, addr string, opts ...TxLoopOpt) (*TxLoop, error) {
	var o txLoopOpts
	for _, opt := range opts {
		opt(&o)
	}
	if o.dial == nil {
		o.dial = net.Dial
	}
	if o.output == nil {
		o.output = txLoopEmptyOutput
	}
	if o.duration == 0 {
		o.duration = time.Second * 10
	}

	conn, err := o.dial(network, addr)
	if err != nil {
		return nil, errors.Wrap(err, "Dial")
	}

	return &TxLoop{
		network: network,
		addr:    addr,
		opts:    o,
		conn:    conn,
		dataCh:  make(chan []byte, 128),
		closeCh: make(chan struct{}),
	}, nil
}

func (tx *TxLoop) Write(data []byte) (int, error) {
	ownData := make([]byte, len(data))
	copy(ownData, data)
	tx.dataCh <- ownData
	return len(data), nil
}

func (tx *TxLoop) Close() error {
	close(tx.closeCh)
	return nil
}

func (tx *TxLoop) Serve(ctx context.Context) error {
	healthTick := time.NewTicker(tx.opts.duration)
	for {
		select {
		case <-ctx.Done():
			if tx.conn != nil {
				tx.conn.Close()
			}
			return ctx.Err()
		case <-tx.closeCh:
			return nil
		case data := <-tx.dataCh:
			if tx.conn == nil {
				tx.opts.output(&TxLoopOutputData{RawData: data, Message: "Fail to write", Err: errors.New("closed conn")})
				continue
			}
			_, err := tx.conn.Write(data)
			if err != nil {
				tx.opts.output(&TxLoopOutputData{RawData: data, Message: "Fail to write", Err: err})
				tx.conn.Close()
				tx.conn = nil
				continue
			}
			tx.opts.output(&TxLoopOutputData{RawData: data, Message: "Write"})
		case <-healthTick.C:
			if tx.conn != nil {
				continue
			}

			conn, err := tx.opts.dial(tx.network, tx.addr)
			if err != nil {
				tx.opts.output(&TxLoopOutputData{Message: "Fail to connect", Err: err})
				continue
			}
			tx.conn = conn
			tx.opts.output(&TxLoopOutputData{Message: fmt.Sprintf("Connected %s", tx.addr)})
		}
	}
}
