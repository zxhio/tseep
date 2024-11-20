package dump

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"tseep/pkg/packet"
	"tseep/pkg/tlv"
	"tseep/pkg/utils"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/songgao/water"
)

type DumpWriter interface {
	Type() string
	io.WriteCloser
}

type FileWriter struct {
	file   *os.File
	buffer *bytes.Buffer
	pcapw  *pcapgo.Writer
}

func NewFileWriter(filename string) (*FileWriter, error) {
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY, 0644)
	if os.IsNotExist(err) {
		f, err = os.OpenFile(filename, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644)
	}
	if err != nil {
		return nil, errors.Wrap(err, "os.OpenFile")
	}

	b := bytes.NewBuffer(make([]byte, 0, 1024*64))

	info, err := os.Stat(filename)
	if err != nil {
		return nil, errors.Wrap(err, "os.Stat")
	}
	if info.Size() == 0 {
		w := pcapgo.NewWriter(b)
		w.WriteFileHeader(0, layers.LinkTypeEthernet)
		_, err = f.Write(b.Bytes())
		if err != nil {
			return nil, errors.Wrap(err, "file.Write")
		}
		b.Reset()
	}

	return &FileWriter{
		file:   f,
		buffer: b,
		pcapw:  pcapgo.NewWriter(b),
	}, nil
}

func (d *FileWriter) Type() string { return "file" }

func (d *FileWriter) Write(data []byte) (int, error) {
	d.buffer.Reset()

	err := d.pcapw.WritePacket(gopacket.CaptureInfo{
		Timestamp:      time.Now(),
		Length:         len(data),
		CaptureLength:  len(data),
		InterfaceIndex: 0, // TODO: add interface
	}, data)
	if err != nil {
		return 0, errors.Wrap(err, "pcapgo.WritePacket")
	}

	return d.file.Write(d.buffer.Bytes())
}

func (d *FileWriter) Close() error {
	if d.file != nil {
		return d.file.Close()
	}
	return nil
}

type TCPWriter struct {
	tx         *utils.TxLoop
	buffer     *bytes.Buffer
	onceTxLoop *sync.Once
}

func NewTCPWriter(addr string) (*TCPWriter, error) {
	txLoop, err := utils.NewTxLoop("tcp", addr, utils.WithTxLoopOutput(func(d *utils.TxLoopOutputData) {
		l := logrus.NewEntry(logrus.StandardLogger())
		if d.Err != nil {
			l.WithError(d.Err).Warn(d.Message)
			return
		}

		if logrus.GetLevel() >= logrus.DebugLevel {
			if d.RawData != nil {
				l = l.WithField("datalen", len(d.RawData))
			}
			l.Debug(d.Message)
		}
	}))
	if err != nil {
		return nil, err
	}
	return &TCPWriter{
		tx:         txLoop,
		buffer:     bytes.NewBuffer(make([]byte, 1024*64)),
		onceTxLoop: new(sync.Once),
	}, nil
}

func (d *TCPWriter) Type() string { return "tcp" }

func (d *TCPWriter) Write(data []byte) (int, error) {
	d.onceTxLoop.Do(func() { go d.tx.Serve(context.Background()) })

	t := tlv.TLV{Type: 1, Length: uint16(len(data))}
	d.buffer.Reset()
	_, err := t.EncodeTo(d.buffer, data)
	if err != nil {
		return 0, errors.Wrap(err, "tlv.EncodeTo")
	}
	return d.tx.Write(d.buffer.Bytes())
}

func (d *TCPWriter) Close() error {
	return d.tx.Close()
}

type StdoutWriter struct{}

func (StdoutWriter) Type() string { return "stdout" }

func (StdoutWriter) Write(data []byte) (int, error) {
	var formatErr error
	d := packet.NewLayersDecoder(packet.WithCompletedHook(func(dl []packet.DecodingLayer) {
		var d []byte
		d, formatErr = packet.Format(dl)
		if formatErr != nil {
			return
		}
		fmt.Fprintf(os.Stdout, "%s %s\n", FormatDumpTime(time.Now()), string(d))
	}))
	err := d.Decode(data, nil)
	if err != nil {
		return 0, errors.Wrap(err, "packet.Decode")
	}
	return 0, errors.Wrap(err, "packet.Format")
}

func (StdoutWriter) Close() error { return nil }

type TunWriter struct {
	tun *water.Interface
}

func NewTunWriter(tunName string) (*TunWriter, error) {
	ifaceTun, err := water.New(water.Config{
		DeviceType: water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{
			Name:    tunName,
			Persist: true,
		},
	})
	if err != nil {
		return nil, errors.Wrap(err, "water.New")
	}
	return &TunWriter{tun: ifaceTun}, nil
}

func (t *TunWriter) Type() string { return "tun" }

func (t *TunWriter) Write(data []byte) (int, error) {
	return t.tun.Write(data[14:])
}

func (t *TunWriter) Close() error {
	if t.tun != nil {
		return t.tun.Close()
	}
	return nil
}

func FormatDumpTime(t time.Time) string {
	return t.Local().Format("15:04:05.000")
}
