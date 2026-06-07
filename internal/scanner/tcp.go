package scanner

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"peekport/internal/proto"
)

// ScanTCP performs a TCP connect scan on target:port.
func ScanTCP(ctx context.Context, target string, port int, timeout time.Duration) proto.PortResult {
	addr := fmt.Sprintf("%s:%d", target, port)
	start := time.Now()

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	elapsed := time.Since(start).Milliseconds()

	if err != nil {
		state := proto.Filtered
		if isRefused(err) {
			state = proto.Closed
		}
		return proto.PortResult{
			Port:     port,
			Protocol: proto.TCP,
			State:    state,
			ScanMs:   elapsed,
		}
	}
	defer conn.Close()

	service := ServiceFromPort(port)
	banner := GrabBanner(conn, service)

	return proto.PortResult{
		Port:     port,
		Protocol: proto.TCP,
		State:    proto.Open,
		Service:  service,
		Banner:   banner,
		ScanMs:   elapsed,
	}
}

func isRefused(err error) bool {
	s := err.Error()
	return strings.Contains(s, "connection refused") ||
		strings.Contains(s, "refused")
}
