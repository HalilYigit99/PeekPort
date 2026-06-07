package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"peekport/internal/api"
	"peekport/internal/proto"
)

// ─── Color helpers ─────────────────────────────────────────────────────────

var (
	bold      = color.New(color.Bold)
	green     = color.New(color.FgGreen, color.Bold)
	yellow    = color.New(color.FgYellow)
	red       = color.New(color.FgRed, color.Bold)
	cyan      = color.New(color.FgCyan)
	magenta   = color.New(color.FgMagenta)
	gray      = color.New(color.FgHiBlack)
	_ = color.New(color.FgWhite) // reserved
	bgRed     = color.New(color.BgRed, color.FgWhite, color.Bold)
	bgYellow  = color.New(color.BgYellow, color.FgBlack, color.Bold)
	bgMagenta = color.New(color.BgMagenta, color.FgWhite, color.Bold)
)

func severityColor(s string) *color.Color {
	switch strings.ToLower(s) {
	case "critical":
		return bgRed
	case "high":
		return red
	case "medium":
		return yellow
	case "low":
		return cyan
	default:
		return gray
	}
}

func main() {
	var (
		server    string
		apiKey    string
		target    string
		mode      string
		protocols []string
		timeoutMs int
		conc      int
		insecure  bool
		outputFmt string
	)

	scan := &cobra.Command{
		Use:   "scan",
		Short: "Run a port scan via the PeekPort server",
		Example: `  peekport-client scan --server wss://scan.example.com --target 10.0.0.1 --mode fast
  peekport-client scan --server ws://localhost:8080 --target 192.168.1.1 --mode full --proto tcp,udp
  peekport-client scan --server wss://scan.example.com --target 10.0.0.1 --output json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if server == "" {
				return fmt.Errorf("server is required (use --server or set PEEKPORT_SERVER)")
			}
			if target == "" {
				return fmt.Errorf("target is required (use --target)")
			}
			return runScan(server, apiKey, target, mode, protocols, timeoutMs, conc, insecure, outputFmt)
		},
	}

	scan.Flags().StringVar(&server, "server", os.Getenv("PEEKPORT_SERVER"), "Server URL (env: PEEKPORT_SERVER), e.g. wss://scan.example.com")
	scan.Flags().StringVar(&apiKey, "api-key", os.Getenv("PEEKPORT_API_KEY"), "API key (env: PEEKPORT_API_KEY)")
	scan.Flags().StringVar(&target, "target", "", "Target IP or hostname to scan (required)")
	scan.Flags().StringVar(&mode, "mode", "fast", "Scan mode: fast (well-known ports) or full (1-65535)")
	scan.Flags().StringSliceVar(&protocols, "proto", []string{"tcp"}, "Protocols: tcp, udp, or tcp,udp")
	scan.Flags().IntVar(&timeoutMs, "timeout", 1000, "Per-port timeout in milliseconds")
	scan.Flags().IntVar(&conc, "concurrency", 500, "Concurrent scanner goroutines on server")
	scan.Flags().BoolVar(&insecure, "insecure", false, "Skip TLS certificate verification")
	scan.Flags().StringVar(&outputFmt, "output", "table", "Output format: table, json")

	root := &cobra.Command{
		Use:   "peekport-client",
		Short: "PeekPort client – control a remote port scanner",
		Long: `PeekPort client connects to a PeekPort server over HTTPS/WebSocket
and instructs it to scan a target. Results stream back in real time.`,
	}
	root.AddCommand(scan)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func runScan(server, apiKey, target, mode string, protocols []string,
	timeoutMs, conc int, insecure bool, outputFmt string) error {

	protos := make([]proto.Protocol, 0, len(protocols))
	for _, p := range protocols {
		switch strings.ToLower(strings.TrimSpace(p)) {
		case "tcp":
			protos = append(protos, proto.TCP)
		case "udp":
			protos = append(protos, proto.UDP)
		}
	}
	if len(protos) == 0 {
		protos = []proto.Protocol{proto.TCP}
	}

	req := proto.ScanRequest{
		Target:      target,
		Mode:        proto.ScanMode(mode),
		Protocols:   protos,
		TimeoutMS:   timeoutMs,
		Concurrency: conc,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	printBanner(target, mode, protocols, server)

	ch, err := api.Connect(ctx, api.ClientConfig{
		ServerURL: server,
		APIKey:    apiKey,
		Insecure:  insecure,
	}, req)
	if err != nil {
		return fmt.Errorf("connection error: %w", err)
	}

	var openPorts []proto.PortResult
	var lastProgress proto.Progress
	startTime := time.Now()

	for res := range ch {
		switch {
		case res.Err != nil:
			red.Fprintf(os.Stderr, "\n[ERROR] %v\n", res.Err) //nolint:errcheck
			return res.Err

		case res.Progress != nil:
			lastProgress = *res.Progress
			if outputFmt == "table" {
				printProgress(lastProgress)
			}

		case res.Port != nil:
			openPorts = append(openPorts, *res.Port)
			if outputFmt == "table" {
				printPortResult(*res.Port)
			}

		case res.Complete != nil:
			if outputFmt == "json" {
				return printJSON(openPorts, *res.Complete)
			}
			printSummary(*res.Complete, time.Since(startTime))
		}
	}

	if ctx.Err() != nil {
		yellow.Println("\n[!] Scan cancelled.")
	}
	return nil
}

// ─── Output functions ──────────────────────────────────────────────────────

func printBanner(target, mode string, protocols []string, server string) {
	fmt.Println()
	bold.Println("╔══════════════════════════════════════════════════════════╗")
	bold.Println("║              PeekPort – Distributed Scanner              ║")
	bold.Println("╚══════════════════════════════════════════════════════════╝")
	fmt.Printf("  Target    : %s\n", cyan.Sprint(target))
	fmt.Printf("  Mode      : %s\n", yellow.Sprint(mode))
	fmt.Printf("  Protocols : %s\n", strings.Join(protocols, ", "))
	fmt.Printf("  Server    : %s\n", gray.Sprint(server))
	fmt.Println()
	bold.Printf("  %-6s  %-5s  %-20s  %-30s  %s\n", "PORT", "PROTO", "SERVICE", "BANNER", "VULNS")
	fmt.Println("  " + strings.Repeat("─", 90))
}

func printPortResult(r proto.PortResult) {
	portStr := fmt.Sprintf("%d", r.Port)
	proto_ := string(r.Protocol)
	svc := r.Service
	if svc == "" {
		svc = "unknown"
	}
	banner := r.Banner
	if len(banner) > 30 {
		banner = banner[:27] + "..."
	}
	banner = strings.ReplaceAll(banner, "\r", "")
	banner = strings.ReplaceAll(banner, "\n", " ")

	vulnStr := ""
	if len(r.Vulns) > 0 {
		parts := make([]string, 0, len(r.Vulns))
		for _, v := range r.Vulns {
			parts = append(parts, severityColor(v.Severity).Sprint(v.Severity[:1]+":"+v.ID))
		}
		vulnStr = strings.Join(parts, " ")
	}

	green.Printf("  %-6s  %-5s  %-20s  %-30s  %s\n", portStr, proto_, svc, banner, vulnStr)

	// Print vulnerability details
	for _, v := range r.Vulns {
		sc := severityColor(v.Severity)
		fmt.Printf("    %s %s", sc.Sprintf("[%s]", v.Severity), bold.Sprint(v.Name))
		if v.CVE != "" {
			fmt.Printf(" %s", gray.Sprint(v.CVE))
		}
		if v.CVSS > 0 {
			fmt.Printf(" CVSS:%.1f", v.CVSS)
		}
		fmt.Println()
		fmt.Printf("         %s\n", gray.Sprint(v.Desc))
	}
}

var lastPct float64

func printProgress(p proto.Progress) {
	// Print at most every 5% to avoid flooding stdout
	if p.Percent-lastPct < 5 && p.Percent < 99.9 {
		return
	}
	lastPct = p.Percent
	bar := progressBar(p.Percent, 30)
	fmt.Printf("\r  %s  %5.1f%%  %d/%d scanned  %d open   ",
		bar, p.Percent, p.Scanned, p.Total, p.OpenCount)
}

func progressBar(pct float64, width int) string {
	filled := int(pct / 100 * float64(width))
	if filled > width {
		filled = width
	}
	return cyan.Sprint("[") +
		green.Sprint(strings.Repeat("█", filled)) +
		gray.Sprint(strings.Repeat("░", width-filled)) +
		cyan.Sprint("]")
}

func printSummary(c proto.ScanComplete, elapsed time.Duration) {
	fmt.Println()
	fmt.Println()
	bold.Println("╔══════════════════════════════════╗")
	bold.Println("║          Scan Complete           ║")
	bold.Println("╚══════════════════════════════════╝")
	fmt.Printf("  Target       : %s\n", cyan.Sprint(c.Target))
	fmt.Printf("  Mode         : %s\n", yellow.Sprint(c.Mode))
	fmt.Printf("  Total ports  : %d\n", c.Total)
	fmt.Printf("  Open ports   : %s\n", green.Sprintf("%d", c.Open))
	fmt.Printf("  Duration     : %.2fs\n", elapsed.Seconds())
	fmt.Printf("  Started      : %s\n", c.Start.Format("2006-01-02 15:04:05"))
	fmt.Println()
}

func printJSON(ports []proto.PortResult, complete proto.ScanComplete) error {
	out := map[string]any{
		"summary":    complete,
		"open_ports": ports,
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

