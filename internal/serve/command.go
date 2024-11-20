package serve

import (
	"io"
	"net"

	"tseep/internal/command"
	"tseep/pkg/tlv"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var cmd = &cobra.Command{
	Use:   "serve",
	Short: "Serve remote captured TCP/IP data",
	RunE: func(cmd *cobra.Command, args []string) error {
		addr, _ := cmd.Flags().GetString("addr")
		verbose, _ := cmd.Flags().GetBool("verbose")

		if verbose {
			logrus.SetLevel(logrus.DebugLevel)
		}

		if addr == "" {
			return errors.New("missing server address")
		}

		lis, err := net.Listen("tcp", addr)
		if err != nil {
			return errors.Wrap(err, "net.Listen")
		}
		logrus.WithField("addr", lis.Addr()).Info("Listen on")

		for {
			conn, err := lis.Accept()
			if err != nil {
				return err
			}
			go handleConn(conn)
		}
	},
}

func handleConn(conn net.Conn) {
	defer conn.Close()

	logrus.WithField("addr", conn.RemoteAddr()).Info("New conn")

	for {
		var tlv tlv.TLV
		value, err := tlv.DecodeFrom(conn)
		if err != nil {
			if err != io.EOF {
				logrus.WithError(err).Error("Fail to decode tlv")
			}
			return
		}

		// TODO: add dump command
		logrus.WithField("datalen", len(value)).Info("Recv packet")
		_ = value
	}
}

func init() {
	cmd.Flags().String("addr", "", "address to listen on")
	cmd.Flags().BoolP("verbose", "v", false, "enable verbose capture output")
	command.Register(cmd)
}
