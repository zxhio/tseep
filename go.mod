module tseep

go 1.22.0

toolchain go1.22.9

// Fix millCh goroutine leak with pr https://github.com/natefinch/lumberjack/pull/80
replace github.com/natefinch/lumberjack => ./pkg/lumberjack-2.2.1

require (
	github.com/gopacket/gopacket v1.3.1
	github.com/natefinch/lumberjack v0.0.0-00010101000000-000000000000
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.9.3
	github.com/songgao/water v0.0.0-20200317203138-2b4b6d7c09d8
	github.com/spf13/cobra v1.8.1
	github.com/stretchr/testify v1.9.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	golang.org/x/net v0.28.0 // indirect
	golang.org/x/sys v0.27.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
