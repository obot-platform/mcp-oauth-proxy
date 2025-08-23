package main

import (
	"log"

	"github.com/gin-gonic/gin"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/proxy"
)

func main() {
	proxy, err := proxy.NewOAuthProxy()
	if err != nil {
		log.Fatalf("Failed to create OAuth proxy: %v", err)
	}
	defer func() {
		if err := proxy.Close(); err != nil {
			log.Printf("Error closing database: %v", err)
		}
	}()

	// Setup Gin router
	r := gin.Default()
	proxy.SetupRoutes(r)

	// Start server
	log.Printf("Starting OAuth proxy server on localhost:8080")
	log.Fatal(r.Run(":8080"))
}
