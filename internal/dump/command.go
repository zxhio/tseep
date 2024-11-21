package dump

import (
	"tseep/internal/command"

	"github.com/gopacket/gopacket/afpacket"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var cmd = &cobra.Command{
	Use:   "dump",
	Short: "Dump capture TCP/IP packet",
	RunE: func(cmd *cobra.Command, args []string) error {
		iface, _ := cmd.Flags().GetString("iface")
		file, _ := cmd.Flags().GetString("file")
		maxFileSize, _ := cmd.Flags().GetInt("file-max-size")
		maxFileBackups, _ := cmd.Flags().GetInt("file-max-backups")
		tcp, _ := cmd.Flags().GetString("to-tcp")
		tun, _ := cmd.Flags().GetString("to-tun")
		noStdout, _ := cmd.Flags().GetBool("no-stdout")
		showEthernet, _ := cmd.Flags().GetBool("stdout-ethernet")
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
			var (
				w   DumpWriter
				err error
			)
			if maxFileSize != 0 || maxFileBackups != 0 {
				w, err = NewRotateFileWriter(file, maxFileSize, maxFileBackups, 0, false)
			} else {
				w, err = NewFileWriter(file)
			}
			if err != nil {
				return err
			}
			writerlist = append(writerlist, w)
		}

		if tun != "" {
			tunW, err := NewTunWriter(tun)
			if err != nil {
				return err
			}
			writerlist = append(writerlist, tunW)
		}

		if !noStdout {
			writerlist = append(writerlist, NewStdoutWriter(showEthernet))
		}

		tpacket, err := afpacket.NewTPacket(afpacket.OptInterface(iface), afpacket.OptAddVLANHeader(true))
		if err != nil {
			return err
		}

		for {
			data, ci, err := tpacket.ReadPacketData()
			if err != nil {
				return errors.Wrap(err, "afpacket.ReadPacketData")
			}
			if ci.Length < ci.CaptureLength {
				ci.Length = ci.CaptureLength
			}

			for _, w := range writerlist {
				_, err := w.WritePacket(ci, data)
				if err != nil {
					logrus.WithField("type", w.Type()).WithError(err).Warn("Fail to write")
					continue
				}
			}
		}
	},
}

func init() {
	cmd.Flags().StringP("iface", "i", "", "network interface to capture from")
	cmd.Flags().StringP("file", "w", "", "save captured packets to a local file")
	cmd.Flags().IntP("file-max-size", "", 0, "maximum size for pcap files (in MB)")
	cmd.Flags().IntP("file-max-backups", "", 0, "number of backup files to retain")
	cmd.Flags().String("to-tcp", "", "send captured packets to a remote server via TCP")
	cmd.Flags().String("to-tun", "", "write captured packets to a TUN device")
	cmd.Flags().Bool("no-stdout", false, "disable writing to stdout")
	cmd.Flags().BoolP("stdout-ethernet", "e", false, "stdout display ethernet info")
	cmd.Flags().BoolP("verbose", "v", false, "enable verbose capture output")
	command.Register(cmd)
}
