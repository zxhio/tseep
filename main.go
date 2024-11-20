package main

import (
	"tseep/internal/command"
	_ "tseep/internal/dump"
	_ "tseep/internal/serve"

	"github.com/sirupsen/logrus"
)

func main() {
	err := command.Execute()
	if err != nil {
		logrus.WithError(err).Fatal("Fatal to command.Parse")
	}
}
