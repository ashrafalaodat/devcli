package main

import (
	"devctl.local/devctl/internal/cli"
	"errors"
	"fmt"
	"os"
)

func main() {
	if e := cli.NewCommand().Execute(); e != nil {
		fmt.Fprintln(os.Stderr, "devctl:", e)
		var exit *cli.ExitError
		if errors.As(e, &exit) {
			os.Exit(exit.Code)
		}
		os.Exit(1)
	}
}
