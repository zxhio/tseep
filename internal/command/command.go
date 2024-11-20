package command

import (
	"github.com/spf13/cobra"
)

var root = cobra.Command{
	Use:   "tseep",
	Short: "TCP/IP packet capture in Go",
}

func Register(sub *cobra.Command) {
	root.AddCommand(sub)
}

func Execute() error {
	return root.Execute()
}
