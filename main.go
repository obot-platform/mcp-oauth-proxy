package main

import (
	"log"
	"net/http"

	"github.com/obot-platform/mcp-oauth-proxy/pkg/proxy"
)

func main() {
	// Load configuration from environment variables
	config := proxy.LoadConfigFromEnv()

	proxy, err := proxy.NewOAuthProxy(config)
	if err != nil {
		log.Fatalf("Failed to create OAuth proxy: %v", err)
	}
	defer func() {
		if err := proxy.Close(); err != nil {
			log.Printf("Error closing database: %v", err)
		}
	}()

	// Get HTTP handler
	handler := proxy.GetHandler()

	// Start server
	log.Printf("Starting OAuth proxy server on localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", handler))
}
