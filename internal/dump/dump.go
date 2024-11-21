package dump

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"tseep/pkg/packet"
	"tseep/pkg/tlv"
	"tseep/pkg/utils"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/natefinch/lumberjack"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/songgao/water"
)

type DumpWriter interface {
	Type() string
	WritePacket(gopacket.CaptureInfo, []byte) (int, error)
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

func (w *FileWriter) Type() string { return "file" }

func (w *FileWriter) WritePacket(ci gopacket.CaptureInfo, data []byte) (int, error) {
	w.buffer.Reset()
	err := w.pcapw.WritePacket(ci, data)
	if err != nil {
		return 0, errors.Wrap(err, "pcapgo.WritePacket")
	}
	return w.file.Write(w.buffer.Bytes())
}

func (w *FileWriter) Write(data []byte) (int, error) {
	ci := gopacket.CaptureInfo{
		Timestamp:      time.Now(),
		Length:         len(data),
		CaptureLength:  len(data),
		InterfaceIndex: 0,
	}
	return w.WritePacket(ci, data)
}

func (w *FileWriter) Close() error {
	if w.file != nil {
		return w.file.Close()
	}
	return nil
}

type RotateFileWriter struct {
	logger *lumberjack.Logger
	buffer *bytes.Buffer
	pcapw  *pcapgo.Writer
}

func NewRotateFileWriter(filename string, maxFileSize, maxFileBackups, maxAge int, compress bool) (*RotateFileWriter, error) {
	b := bytes.NewBuffer(make([]byte, 0, 1024*64))
	return &RotateFileWriter{
		logger: &lumberjack.Logger{
			Filename:   filename,
			MaxSize:    maxFileSize,
			MaxBackups: maxFileBackups,
			MaxAge:     maxAge,
			Compress:   compress,
			MakeFileHeaderFn: func() ([]byte, error) {
				var hb bytes.Buffer
				w := pcapgo.NewWriter(&hb)
				w.WriteFileHeader(0, layers.LinkTypeEthernet)
				return hb.Bytes(), nil
			},
		},
		buffer: b,
		pcapw:  pcapgo.NewWriter(b),
	}, nil
}

func (w *RotateFileWriter) Type() string { return "rotate-file" }

func (w *RotateFileWriter) WritePacket(ci gopacket.CaptureInfo, data []byte) (int, error) {
	w.buffer.Reset()
	err := w.pcapw.WritePacket(ci, data)
	if err != nil {
		return 0, errors.Wrap(err, "pcapgo.WritePacket")
	}
	return w.logger.Write(w.buffer.Bytes())
}

func (w *RotateFileWriter) Write(data []byte) (int, error) {
	ci := gopacket.CaptureInfo{
		Timestamp:      time.Now(),
		Length:         len(data),
		CaptureLength:  len(data),
		InterfaceIndex: 0,
	}
	return w.WritePacket(ci, data)
}

func (w *RotateFileWriter) Close() error {
	if w.logger != nil {
		return w.logger.Close()
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

func (w *TCPWriter) Type() string { return "tcp" }

func (w *TCPWriter) WritePacket(_ gopacket.CaptureInfo, data []byte) (int, error) {
	return w.Write(data)
}

func (w *TCPWriter) Write(data []byte) (int, error) {
	w.onceTxLoop.Do(func() { go w.tx.Serve(context.Background()) })

	t := tlv.TLV{Type: 1, Length: uint16(len(data))}
	w.buffer.Reset()
	_, err := t.EncodeTo(w.buffer, data)
	if err != nil {
		return 0, errors.Wrap(err, "tlv.EncodeTo")
	}
	return w.tx.Write(w.buffer.Bytes())
}

func (w *TCPWriter) Close() error {
	return w.tx.Close()
}

type StdoutWriter struct {
	opts []packet.FormatOpt
}

func NewStdoutWriter(showEthernet bool) *StdoutWriter {
	w := &StdoutWriter{}
	if showEthernet {
		w.opts = append(w.opts, packet.WithFormatEthernet())
	}
	return w
}

func (*StdoutWriter) Type() string { return "stdout" }

func (w *StdoutWriter) WritePacket(ci gopacket.CaptureInfo, data []byte) (int, error) {
	var (
		parent gopacket.Layer
		b      strings.Builder
		delim  packet.FormatDelimiter
	)

	p := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
	for _, layer := range p.Layers() {
		var (
			s string
			d packet.FormatDelimiter
		)

		f, ok := packet.GetLayerFormatter(layer.LayerType())
		if ok {
			s, d = f.Format(layer, append(w.opts, packet.WithFormatParentLayer(parent))...)
		} else if layer.LayerType() != gopacket.LayerTypePayload {
			s = layer.LayerType().String()
			d = packet.FormatDelimiterComma
		} else {
			continue
		}

		b.WriteString(string(delim))
		b.WriteString(s)
		delim = d
		parent = layer
	}

	fmt.Printf("%s %s\n", packet.FormatDumpTime(ci.Timestamp), b.String())
	return 0, nil
}

func (w *StdoutWriter) Write(data []byte) (int, error) {
	return w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Now()}, data)
}

func (*StdoutWriter) Close() error { return nil }

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

func (w *TunWriter) Type() string { return "tun" }

func (w *TunWriter) WritePacket(_ gopacket.CaptureInfo, data []byte) (int, error) {
	return w.Write(data)
}

func (w *TunWriter) Write(data []byte) (int, error) {
	var (
		ethernet gopacket.Layer
		underlay gopacket.Layer
	)

	p := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
	for _, layer := range p.Layers() {
		if layer.LayerType() == layers.LayerTypeIPv4 || layer.LayerType() == layers.LayerTypeIPv6 {
			ethernet = underlay
		}
		underlay = layer
	}
	if ethernet == nil {
		return 0, nil
	}

	return w.tun.Write(ethernet.LayerPayload())
}

func (w *TunWriter) Close() error {
	if w.tun != nil {
		return w.tun.Close()
	}
	return nil
}
