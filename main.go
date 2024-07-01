package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/jonhadfield/ipscout/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		if !errors.Is(err, cmd.ErrSilent) {
			fmt.Fprintln(os.Stderr, err)
		}

		os.Exit(1)
	}
}
