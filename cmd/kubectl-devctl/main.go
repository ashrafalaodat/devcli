package main

import (
	"errors"
	"fmt"
	"os"

	"devctl.local/devctl/internal/cli"
)

func main() {
	if err := cli.NewPluginCommand().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "kubectl devctl:", err)
		var exit *cli.ExitError
		if errors.As(err, &exit) {
			os.Exit(exit.Code)
		}
		os.Exit(1)
	}
}
