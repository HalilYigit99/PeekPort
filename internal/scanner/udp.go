package scanner

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"peekport/internal/proto"
)

// udpProbes maps well-known UDP ports to minimal probe payloads.
// Responses confirm the port is open; ICMP unreachable means closed.
var udpProbes = map[int][]byte{
	// DNS version query
	53: {
		0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x07, 'v', 'e', 'r', 's', 'i', 'o', 'n',
		0x04, 'b', 'i', 'n', 'd',
		0x00, 0x00, 0x10, 0x00, 0x03,
	},
	// NTP client request (v3, client mode)
	123: {
		0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	},
	// SNMP GetRequest – sysDescr.0 with community "public"
	161: {
		0x30, 0x26,
		0x02, 0x01, 0x00,
		0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c',
		0xa0, 0x19,
		0x02, 0x04, 0x01, 0x02, 0x03, 0x04,
		0x02, 0x01, 0x00,
		0x02, 0x01, 0x00,
		0x30, 0x0b, 0x30, 0x09,
		0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01,
		0x05, 0x00,
	},
	// NetBIOS Name Service – node status request
	137: {
		0x00, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x20, 0x43, 0x4b, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x00,
		0x00, 0x21, 0x00, 0x01,
	},
	// SSDP M-SEARCH
	1900: []byte("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n"),
	// SIP OPTIONS
	5060: []byte("OPTIONS sip:localhost SIP/2.0\r\nVia: SIP/2.0/UDP localhost:5060\r\n" +
		"From: <sip:peekport@localhost>\r\nTo: <sip:localhost>\r\nCall-ID: 1@localhost\r\n" +
		"CSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n"),
	// Memcached stats
	11211: []byte("stats\r\n"),
	// WSD (Windows Service Discovery)
	3702: []byte("<?xml version=\"1.0\" encoding=\"utf-8\"?><soap:Envelope " +
		"xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\"/>"),
	// mDNS query
	5353: {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x05, '_', 'h', 't', 't', 'p', 0x04, '_', 't', 'c', 'p', 0x05, 'l',
		'o', 'c', 'a', 'l', 0x00, 0x00, 0x0c, 0x00, 0x01,
	},
}

// ScanUDP performs a UDP probe on target:port.
func ScanUDP(ctx context.Context, target string, port int, timeout time.Duration) proto.PortResult {
	addr := fmt.Sprintf("%s:%d", target, port)
	start := time.Now()

	conn, err := net.DialTimeout("udp", addr, timeout)
	elapsed := time.Since(start).Milliseconds()
	if err != nil {
		return proto.PortResult{
			Port: port, Protocol: proto.UDP, State: proto.Filtered, ScanMs: elapsed,
		}
	}
	defer conn.Close()

	probe := udpProbes[port]
	if len(probe) == 0 {
		probe = []byte("\x00") // empty probe triggers ICMP unreachable on closed ports
	}

	conn.SetDeadline(time.Now().Add(timeout))
	if _, err = conn.Write(probe); err != nil {
		return proto.PortResult{
			Port: port, Protocol: proto.UDP, State: proto.Filtered, ScanMs: elapsed,
		}
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	elapsed = time.Since(start).Milliseconds()

	if err != nil {
		// ICMP port unreachable → closed
		if isICMPUnreachable(err) {
			return proto.PortResult{
				Port: port, Protocol: proto.UDP, State: proto.Closed, ScanMs: elapsed,
			}
		}
		// Timeout → open|filtered (no ICMP response, no UDP response)
		return proto.PortResult{
			Port: port, Protocol: proto.UDP, State: proto.Filtered, ScanMs: elapsed,
		}
	}

	// Got a UDP response → definitely open
	service := ServiceFromPort(port)
	banner := ""
	if n > 0 {
		raw := strings.Map(func(r rune) rune {
			if r >= 32 && r < 127 {
				return r
			}
			return -1
		}, string(buf[:n]))
		if len(raw) > 128 {
			raw = raw[:128] + "..."
		}
		banner = raw
	}

	return proto.PortResult{
		Port:     port,
		Protocol: proto.UDP,
		State:    proto.Open,
		Service:  service,
		Banner:   banner,
		ScanMs:   elapsed,
	}
}

func isICMPUnreachable(err error) bool {
	s := err.Error()
	return strings.Contains(s, "connection refused") ||
		strings.Contains(s, "port unreachable") ||
		strings.Contains(s, "no route to host")
}
