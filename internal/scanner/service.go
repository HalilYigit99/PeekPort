package scanner

import (
	"net"
	"strings"
	"time"
)

// PortServices maps well-known port numbers to service names.
var PortServices = map[int]string{
	20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet",
	25: "smtp", 26: "smtp-alt", 43: "whois", 53: "dns",
	67: "dhcp", 68: "dhcpc", 69: "tftp", 70: "gopher",
	79: "finger", 80: "http", 81: "http-alt", 88: "kerberos",
	109: "pop2", 110: "pop3", 111: "rpcbind", 119: "nntp",
	123: "ntp", 135: "msrpc", 137: "netbios-ns", 138: "netbios-dgm",
	139: "netbios-ssn", 143: "imap", 161: "snmp", 162: "snmptrap",
	179: "bgp", 194: "irc", 389: "ldap", 443: "https",
	445: "smb", 465: "smtps", 500: "ike", 502: "modbus",
	512: "rexec", 513: "rlogin", 514: "rsh", 515: "lpd",
	520: "rip", 523: "db2", 548: "afp", 554: "rtsp",
	563: "nntps", 587: "submission", 631: "cups", 636: "ldaps",
	873: "rsync", 902: "vmware", 903: "vmware-auth",
	989: "ftps-data", 990: "ftps", 993: "imaps", 995: "pop3s",
	1080: "socks", 1194: "openvpn", 1433: "mssql", 1434: "mssql-monitor",
	1521: "oracle", 1720: "h323", 1723: "pptp",
	1812: "radius", 1813: "radius-acct", 1883: "mqtt",
	1900: "upnp", 2049: "nfs", 2181: "zookeeper",
	2222: "ssh-alt", 2375: "docker", 2376: "docker-tls",
	2379: "etcd-client", 2380: "etcd-peer",
	3000: "grafana", 3128: "squid", 3268: "globalcat",
	3306: "mysql", 3389: "rdp", 3690: "svn",
	4444: "backdoor", 4505: "saltstack-pub", 4506: "saltstack-ret",
	4848: "glassfish", 4899: "radmin",
	5000: "upnp-alt", 5060: "sip", 5061: "sips",
	5222: "xmpp-client", 5269: "xmpp-server",
	5432: "postgresql", 5601: "kibana",
	5672: "amqp", 5900: "vnc", 5901: "vnc-1", 5902: "vnc-2",
	5984: "couchdb", 6000: "x11", 6379: "redis",
	6443: "kubernetes-api", 6667: "irc", 6697: "ircs",
	7474: "neo4j", 8000: "http-alt", 8001: "k8s-proxy",
	8009: "ajp", 8069: "odoo", 8080: "http-proxy",
	8088: "hadoop", 8090: "confluence", 8118: "privoxy",
	8140: "puppet", 8161: "activemq-admin", 8200: "vault",
	8443: "https-alt", 8500: "consul", 8600: "consul-dns",
	8888: "jupyter", 9000: "sonarqube",
	9042: "cassandra", 9090: "prometheus", 9092: "kafka",
	9100: "node-exporter", 9200: "elasticsearch", 9300: "elasticsearch-cluster",
	9418: "git", 10000: "webmin", 11211: "memcached",
	15672: "rabbitmq-mgmt", 27017: "mongodb", 27018: "mongodb-shard",
	28017: "mongodb-web", 31337: "backdoor", 33060: "mysqlx",
	47808: "bacnet", 50000: "sap", 51820: "wireguard",
}

// ServiceProbes maps service names to probes we send to elicit a banner.
var ServiceProbes = map[string][]byte{
	"http":         []byte("GET / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: PeekPort/1.0\r\n\r\n"),
	"http-alt":     []byte("GET / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: PeekPort/1.0\r\n\r\n"),
	"http-proxy":   []byte("GET / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: PeekPort/1.0\r\n\r\n"),
	"https-alt":    []byte("GET / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: PeekPort/1.0\r\n\r\n"),
	"smtp":         []byte("EHLO peekport.local\r\n"),
	"submission":   []byte("EHLO peekport.local\r\n"),
	"redis":        []byte("PING\r\n"),
	"memcached":    []byte("version\r\n"),
	"mongodb":      nil, // sends wire protocol greeting
	"postgresql":   nil, // sends startup packet
	"mysql":        nil, // sends handshake
	"vnc":          nil, // sends protocol version
	"ftp":          nil, // server sends 220 banner
	"ssh":          nil, // server sends SSH banner
	"telnet":       nil, // server sends IAC
	"smb":          nil, // binary protocol
	"imap":         nil, // server sends * OK
	"pop3":         nil, // server sends +OK
}

// GrabBanner connects (already done) and tries to read a service banner.
func GrabBanner(conn net.Conn, service string) string {
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	// Some services need a probe before they respond.
	if probe, ok := ServiceProbes[service]; ok && len(probe) > 0 {
		conn.Write(probe) //nolint:errcheck
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return ""
	}
	banner := strings.TrimSpace(string(buf[:n]))
	// Remove non-printable except newline
	var clean strings.Builder
	for _, r := range banner {
		if r >= 32 || r == '\n' || r == '\r' {
			clean.WriteRune(r)
		}
	}
	result := strings.TrimSpace(clean.String())
	if len(result) > 256 {
		result = result[:256] + "..."
	}
	return result
}

// ServiceFromPort returns the service name for a port.
func ServiceFromPort(port int) string {
	if svc, ok := PortServices[port]; ok {
		return svc
	}
	return ""
}
