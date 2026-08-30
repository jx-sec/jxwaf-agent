package main

import (
	"os"

	"github.com/jx-sec/jxwaf-agent/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
