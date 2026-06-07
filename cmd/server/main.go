package main

import (
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"

	"peekport/internal/api"
)

func main() {
	var (
		domain  string
		email   string
		apiKey  string
		certDir string
		devMode bool
		port    int
	)

	root := &cobra.Command{
		Use:   "peekport-server",
		Short: "PeekPort VDS – port scan relay server",
		Long: `PeekPort server listens for authenticated WebSocket connections,
executes port scans on behalf of clients, and streams results back.

For production: set --domain and --email, open ports 80 and 443.
For development: use --dev (HTTP on :8080, no TLS).`,
		Example: `  # Production (Let's Encrypt)
  peekport-server --domain scan.example.com --email admin@example.com --api-key secret123

  # Local dev
  peekport-server --dev --api-key secret123`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !devMode && domain == "" {
				return fmt.Errorf("--domain is required in production mode (or use --dev)")
			}
			if apiKey == "" {
				log.Println("[WARN] No --api-key set. Server is open to anyone!")
			}

			log.Println("╔═══════════════════════════════════╗")
			log.Println("║       PeekPort Server v1.0        ║")
			log.Println("╚═══════════════════════════════════╝")
			log.Printf("  Domain  : %s", domain)
			log.Printf("  Dev mode: %v", devMode)
			log.Printf("  API key : %v", apiKey != "")

			return api.ListenAndServe(api.ServerConfig{
				Domain:  domain,
				Email:   email,
				APIKey:  apiKey,
				CertDir: certDir,
				DevMode: devMode,
				Port:    port,
			})
		},
	}

	root.Flags().StringVar(&domain, "domain", "", "Domain name for Let's Encrypt TLS certificate")
	root.Flags().StringVar(&email, "email", "", "Email address for Let's Encrypt account")
	root.Flags().StringVar(&apiKey, "api-key", os.Getenv("PEEKPORT_API_KEY"), "API key clients must provide (env: PEEKPORT_API_KEY)")
	root.Flags().StringVar(&certDir, "cert-dir", "/var/cache/peekport/certs", "Directory for Let's Encrypt certificate cache")
	root.Flags().BoolVar(&devMode, "dev", false, "Dev mode: HTTP on :8080 (or --port), no TLS")
	root.Flags().IntVar(&port, "port", 8080, "Port to listen on in dev mode")

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}
