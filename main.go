package main

import (
	"os"

	"github.com/obot-platform/mcp-oauth-proxy/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
