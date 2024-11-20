package dump

import (
	"context"
	"errors"

	"tseep/internal/command"
	"tseep/pkg/capture"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var cmd = &cobra.Command{
	Use:   "dump",
	Short: "Dump capture TCP/IP packet",
	RunE: func(cmd *cobra.Command, args []string) error {
		iface, _ := cmd.Flags().GetString("iface")
		tcp, _ := cmd.Flags().GetString("tcp")
		file, _ := cmd.Flags().GetString("file")
		tun, _ := cmd.Flags().GetString("tun")
		noStdout, _ := cmd.Flags().GetBool("no-stdout")
		verbose, _ := cmd.Flags().GetBool("verbose")

		if iface == "" {
			return errors.New("missing interface")
		}

		if verbose {
			logrus.SetLevel(logrus.DebugLevel)
		}

		var writerlist []DumpWriter

		if tcp != "" {
			tcpW, err := NewTCPWriter(tcp)
			if err != nil {
				return err
			}
			logrus.WithField("addr", tcp).Info("Connected")
			writerlist = append(writerlist, tcpW)
		}

		if file != "" {
			fileW, err := NewFileWriter(file)
			if err != nil {
				return err
			}
			writerlist = append(writerlist, fileW)
		}

		if tun != "" {
			tunW, err := NewTunWriter(tun)
			if err != nil {
				return err
			}
			writerlist = append(writerlist, tunW)
		}

		if !noStdout {
			writerlist = append(writerlist, StdoutWriter{})
		}

		capture, err := capture.NewCaptureByIfaceName(iface)
		if err != nil {
			return err
		}

		go func() {
			for data := range capture.Read() {
				for _, w := range writerlist {
					_, err := w.Write(data)
					if err != nil {
						logrus.WithField("type", w.Type()).WithError(err).Warn("Fail to write")
						continue
					}
				}
			}
		}()
		return capture.Serve(context.Background())
	},
}

func init() {
	cmd.Flags().StringP("iface", "i", "", "network interface to capture from")
	cmd.Flags().StringP("file", "w", "", "save captured packets to a local file")
	cmd.Flags().String("tcp", "", "send captured packets to a remote server via TCP")
	cmd.Flags().String("tun", "", "write captured packets to a TUN device")
	cmd.Flags().Bool("no-stdout", false, "disable writing to stdout")
	cmd.Flags().BoolP("verbose", "v", false, "enable verbose capture output")
	command.Register(cmd)
}
