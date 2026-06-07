package scanner

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"peekport/internal/proto"
	"peekport/internal/vuln"
)

// Result is a union of PortResult and Progress sent over Results channel.
type Result struct {
	Port     *proto.PortResult
	Progress *proto.Progress
	Complete *proto.ScanComplete
}

// Config holds scanner parameters.
type Config struct {
	Target      string
	Mode        proto.ScanMode
	Protocols   []proto.Protocol
	Timeout     time.Duration
	Concurrency int
}

// DefaultConcurrency is used when Config.Concurrency == 0.
const DefaultConcurrency = 500

// Run executes the scan and streams Result values to the returned channel.
// The channel is closed when the scan finishes or ctx is cancelled.
func Run(ctx context.Context, cfg Config) <-chan Result {
	out := make(chan Result, 256)

	if cfg.Concurrency <= 0 {
		cfg.Concurrency = DefaultConcurrency
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = time.Second
	}

	go func() {
		defer close(out)

		ports := buildPortList(cfg.Mode)
		total := len(ports) * len(cfg.Protocols)
		start := time.Now()

		var scanned atomic.Int64
		var openCount atomic.Int64

		sem := make(chan struct{}, cfg.Concurrency)
		var wg sync.WaitGroup

		progressTicker := time.NewTicker(500 * time.Millisecond)
		defer progressTicker.Stop()

		// Progress reporter goroutine
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case _, ok := <-progressTicker.C:
					if !ok {
						return
					}
					sc := int(scanned.Load())
					oc := int(openCount.Load())
					pct := 0.0
					if total > 0 {
						pct = float64(sc) / float64(total) * 100
					}
					select {
					case out <- Result{Progress: &proto.Progress{
						Scanned:   sc,
						Total:     total,
						Percent:   pct,
						OpenCount: oc,
					}}:
					case <-ctx.Done():
						return
					}
				}
			}
		}()

		for _, port := range ports {
			for _, pr := range cfg.Protocols {
				select {
				case <-ctx.Done():
					wg.Wait()
					return
				default:
				}

				wg.Add(1)
				sem <- struct{}{}
				go func(p int, protocol proto.Protocol) {
					defer wg.Done()
					defer func() { <-sem }()

					var r proto.PortResult
					switch protocol {
					case proto.TCP:
						r = ScanTCP(ctx, cfg.Target, p, cfg.Timeout)
					case proto.UDP:
						r = ScanUDP(ctx, cfg.Target, p, cfg.Timeout)
					}

					scanned.Add(1)

					if r.State == proto.Open {
						openCount.Add(1)
						r.Vulns = vuln.Detect(r)
						select {
						case out <- Result{Port: &r}:
						case <-ctx.Done():
						}
					}
				}(port, pr)
			}
		}

		wg.Wait()
		progressTicker.Stop()

		end := time.Now()
		out <- Result{Complete: &proto.ScanComplete{
			Target:    cfg.Target,
			Mode:      cfg.Mode,
			Total:     total,
			Open:      int(openCount.Load()),
			DurationS: end.Sub(start).Seconds(),
			Start:     start,
			End:       end,
		}}
	}()

	return out
}

func buildPortList(mode proto.ScanMode) []int {
	if mode == proto.ModeFull {
		ports := make([]int, 65535)
		for i := range ports {
			ports[i] = i + 1
		}
		return ports
	}
	return WellKnownPorts
}
