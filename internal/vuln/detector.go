package vuln

import (
	"regexp"
	"strings"

	"peekport/internal/proto"
)

type rule struct {
	id       string
	name     string
	severity string
	cve      string
	cvss     float64
	desc     string
	ports    []int
	services []string
	banner   *regexp.Regexp
}

// severity levels used throughout the project
const (
	Critical = "Critical"
	High     = "High"
	Medium   = "Medium"
	Low      = "Low"
	Info     = "Info"
)

var rules = []rule{
	// ── Critical ────────────────────────────────────────────────────
	{
		id: "telnet-cleartext", name: "Telnet Exposed", severity: Critical,
		desc:  "Telnet transmits credentials and data in cleartext. Replace with SSH.",
		ports: []int{23},
	},
	{
		id: "docker-api-exposed", name: "Docker API Exposed (No TLS)", severity: Critical,
		cve: "CVE-2019-5736", cvss: 8.6,
		desc:  "Unauthenticated Docker API allows full host compromise via container escape.",
		ports: []int{2375},
	},
	{
		id: "redis-no-auth", name: "Redis Exposed", severity: Critical,
		desc:    "Redis commonly runs without authentication. Allows data theft and RCE via SLAVEOF.",
		ports:   []int{6379},
		services: []string{"redis"},
	},
	{
		id: "mongodb-no-auth", name: "MongoDB Exposed", severity: Critical,
		desc:  "MongoDB default config has no authentication. All databases accessible.",
		ports: []int{27017, 27018},
	},
	{
		id: "jupyter-no-auth", name: "Jupyter Notebook Exposed", severity: Critical,
		desc:  "Jupyter Notebook without a token allows arbitrary code execution on the host.",
		ports: []int{8888},
	},
	{
		id: "k8s-api-exposed", name: "Kubernetes API Server Exposed", severity: Critical,
		desc:  "Kubernetes API server exposed to internet. May allow full cluster takeover.",
		ports: []int{6443, 8001},
	},
	{
		id: "metasploit-port", name: "Common Backdoor/Exploit Port", severity: Critical,
		desc:  "Port associated with Metasploit handlers, netcat listeners, or malware.",
		ports: []int{4444, 31337, 12345, 23456, 54321},
	},
	{
		id: "rsh-rlogin", name: "RSH/Rlogin Cleartext Remote Shell", severity: Critical,
		desc:  "rsh/rlogin use .rhosts trust-based auth (no password). Trivially exploitable.",
		ports: []int{512, 513, 514},
	},
	{
		id: "vault-exposed", name: "HashiCorp Vault API Exposed", severity: Critical,
		desc:  "Vault HTTP API exposed. May allow secret extraction without auth if misconfigured.",
		ports: []int{8200},
	},
	// ── High ────────────────────────────────────────────────────────
	{
		id: "ftp-cleartext", name: "FTP Cleartext Protocol", severity: High,
		desc:  "FTP transmits credentials in cleartext. Use SFTP or FTPS instead.",
		ports: []int{20, 21},
	},
	{
		id: "smb-exposed", name: "SMB/CIFS Exposed", severity: High,
		cve: "CVE-2017-0144", cvss: 9.3,
		desc:  "SMB exposed to internet. High risk of EternalBlue/WannaCry exploitation.",
		ports: []int{445, 139},
	},
	{
		id: "rdp-exposed", name: "RDP Exposed to Internet", severity: High,
		cve: "CVE-2019-0708", cvss: 9.8,
		desc:  "RDP exposed to internet. BlueKeep and brute-force attacks are common.",
		ports: []int{3389, 33389},
	},
	{
		id: "vnc-exposed", name: "VNC Exposed", severity: High,
		desc:  "VNC often uses weak/no authentication. Remote desktop access may be trivial.",
		ports: []int{5900, 5901, 5902},
	},
	{
		id: "elasticsearch-exposed", name: "Elasticsearch Exposed (No Auth)", severity: High,
		desc:  "Elasticsearch has no auth by default (< 8.x). All indices readable/deletable.",
		ports: []int{9200, 9300},
	},
	{
		id: "memcached-exposed", name: "Memcached Exposed (UDP Amplification)", severity: High,
		cve: "CVE-2018-1000115", cvss: 7.5,
		desc:  "Memcached with UDP open can be abused for >50,000x DDoS amplification.",
		ports: []int{11211},
	},
	{
		id: "mssql-exposed", name: "MS SQL Server Exposed", severity: High,
		desc:  "MS SQL exposed to internet. Brute force and xp_cmdshell attacks are common.",
		ports: []int{1433, 1434},
	},
	{
		id: "oracle-exposed", name: "Oracle DB Exposed", severity: High,
		desc:  "Oracle DB listener exposed. TNS Poison and SID enumeration attacks apply.",
		ports: []int{1521, 1522},
	},
	{
		id: "mysql-exposed", name: "MySQL Exposed", severity: High,
		desc:  "MySQL/MariaDB exposed to internet. Brute force and CVE exploits are common.",
		ports: []int{3306, 33060},
	},
	{
		id: "rsync-exposed", name: "rsync Exposed", severity: High,
		desc:  "rsync daemon without auth allows arbitrary file read/write on the server.",
		ports: []int{873},
	},
	{
		id: "nfs-exposed", name: "NFS Exposed", severity: High,
		desc:  "NFS export accessible. May allow mounting and reading sensitive filesystems.",
		ports: []int{2049, 111},
	},
	{
		id: "activemq-admin", name: "ActiveMQ Admin Console Exposed", severity: High,
		cve: "CVE-2023-46604", cvss: 10.0,
		desc:  "ActiveMQ admin UI exposed. CVE-2023-46604 allows unauthenticated RCE.",
		ports: []int{8161},
	},
	{
		id: "radmin-exposed", name: "Radmin Remote Admin Exposed", severity: High,
		desc:  "Radmin exposed to internet. Legacy protocol with known auth bypass issues.",
		ports: []int{4899},
	},
	{
		id: "couchdb-exposed", name: "CouchDB Admin Exposed", severity: High,
		cve: "CVE-2017-12636", cvss: 9.8,
		desc:  "CouchDB Futon/Fauxton admin with no auth enables RCE via server-side functions.",
		ports: []int{5984},
	},
	{
		id: "neo4j-exposed", name: "Neo4j Exposed", severity: High,
		desc:  "Neo4j browser/REST API exposed. Default credentials admin:neo4j are common.",
		ports: []int{7474},
	},
	{
		id: "saltstack-exposed", name: "SaltStack ZMQ Exposed", severity: High,
		cve: "CVE-2020-11651", cvss: 9.8,
		desc:  "SaltStack ZMQ ports exposed. Authentication bypass allows RCE on all minions.",
		ports: []int{4505, 4506},
	},
	{
		id: "kafka-exposed", name: "Apache Kafka Exposed", severity: High,
		desc:  "Kafka broker exposed without auth. Topics readable/writable by anyone.",
		ports: []int{9092},
	},
	{
		id: "cassandra-exposed", name: "Cassandra CQL Exposed", severity: High,
		desc:  "Cassandra CQL port exposed. No auth by default – all keyspaces accessible.",
		ports: []int{9042},
	},
	{
		id: "glassfish-admin", name: "GlassFish Admin Console Exposed", severity: High,
		desc:  "GlassFish admin on 4848. Default credentials admin:adminadmin are common.",
		ports: []int{4848},
	},
	// ── Medium ──────────────────────────────────────────────────────
	{
		id: "snmp-public", name: "SNMP Community String 'public'", severity: Medium,
		cve: "CVE-2002-0012", cvss: 7.5,
		desc:  "SNMP with default community 'public' leaks device config and system info.",
		ports: []int{161, 162},
	},
	{
		id: "ntp-amplification", name: "NTP Amplification Risk", severity: Medium,
		cve: "CVE-2013-5211", cvss: 7.8,
		desc:  "NTP monlist command can be abused for DDoS amplification (600x factor).",
		ports: []int{123},
	},
	{
		id: "smtp-exposed", name: "SMTP Relay Potential", severity: Medium,
		desc:  "SMTP exposed. Test for open relay which enables spam/phishing abuse.",
		ports: []int{25, 26},
	},
	{
		id: "dns-exposed", name: "DNS Open Resolver", severity: Medium,
		desc:  "DNS resolver exposed. Open resolvers enable cache poisoning and amplification.",
		ports: []int{53},
	},
	{
		id: "ldap-exposed", name: "LDAP Exposed", severity: Medium,
		desc:  "LDAP (unencrypted) exposed. Directory information may be browsable anonymously.",
		ports: []int{389},
	},
	{
		id: "pptp-exposed", name: "PPTP VPN Exposed", severity: Medium,
		desc:  "PPTP VPN uses MS-CHAPv2 which is cryptographically broken (100% offline crack).",
		ports: []int{1723},
	},
	{
		id: "finger-exposed", name: "Finger Protocol Exposed", severity: Medium,
		desc:  "Finger daemon leaks user account information to anonymous queriers.",
		ports: []int{79},
	},
	{
		id: "modbus-exposed", name: "Modbus ICS Protocol Exposed", severity: Medium,
		desc:  "Modbus (ICS/SCADA) exposed to internet. No authentication; direct device control.",
		ports: []int{502},
	},
	{
		id: "zookeeper-exposed", name: "ZooKeeper Exposed", severity: Medium,
		desc:  "ZooKeeper exposed. No auth by default – Kafka/HBase/cluster config accessible.",
		ports: []int{2181},
	},
	{
		id: "consul-exposed", name: "HashiCorp Consul Exposed", severity: Medium,
		desc:  "Consul API exposed without ACL. Service catalog and KV store may be readable.",
		ports: []int{8500, 8600},
	},
	{
		id: "prometheus-exposed", name: "Prometheus Metrics Exposed", severity: Medium,
		desc:  "Prometheus /metrics endpoint leaks internal infra details, hostnames, paths.",
		ports: []int{9090, 9091, 9100},
	},
	{
		id: "webmin-exposed", name: "Webmin Exposed", severity: Medium,
		cve: "CVE-2019-15107", cvss: 10.0,
		desc:  "Webmin admin panel exposed. CVE-2019-15107 allows unauthenticated RCE.",
		ports: []int{10000},
	},
	{
		id: "socks-proxy", name: "SOCKS Proxy Exposed", severity: Medium,
		desc:  "Open SOCKS proxy allows traffic pivoting through this host.",
		ports: []int{1080},
	},
	{
		id: "squid-proxy", name: "Squid Proxy Exposed", severity: Medium,
		desc:  "Squid proxy may be open – allowing others to proxy traffic through this host.",
		ports: []int{3128},
	},
	{
		id: "rabbitmq-mgmt", name: "RabbitMQ Management UI Exposed", severity: Medium,
		desc:  "RabbitMQ management UI exposed. Default guest:guest credentials common.",
		ports: []int{15672},
	},
	{
		id: "bacnet-exposed", name: "BACnet Building Automation Exposed", severity: Medium,
		desc:  "BACnet (building automation) exposed. Controls HVAC, lighting, access systems.",
		ports: []int{47808},
	},
	// ── Info / Low ──────────────────────────────────────────────────
	{
		id: "wireguard-detected", name: "WireGuard VPN Detected", severity: Info,
		desc:  "WireGuard VPN endpoint detected. Ensure only authorised peers can connect.",
		ports: []int{51820},
	},
	{
		id: "git-daemon", name: "Git Daemon Exposed", severity: Low,
		desc:  "Git daemon may expose repository contents to anonymous git clone.",
		ports: []int{9418},
	},
	// ── Banner-based (version-specific CVEs) ────────────────────────
	{
		id: "openssh-old", name: "Outdated OpenSSH Version", severity: High,
		cve: "CVE-2023-38408", cvss: 9.8,
		desc:   "OpenSSH < 9.3p2 is vulnerable to remote code execution via ssh-agent forwarding.",
		banner: regexp.MustCompile(`(?i)OpenSSH_([1-8]\.|9\.[0-2])`),
	},
	{
		id: "apache-old", name: "Potentially Outdated Apache httpd", severity: Medium,
		desc:   "Apache version exposed. Verify against latest security advisories.",
		banner: regexp.MustCompile(`(?i)Apache/([01]\.|2\.[0-3]\.)`),
	},
	{
		id: "nginx-version-exposed", name: "nginx Version Disclosed", severity: Info,
		desc:   "nginx version exposed in banner. Mask with 'server_tokens off'.",
		banner: regexp.MustCompile(`(?i)nginx/`),
	},
	{
		id: "proftpd-rce", name: "ProFTPD RCE Vulnerability", severity: Critical,
		cve: "CVE-2015-3306", cvss: 10.0,
		desc:   "ProFTPD 1.3.5 (mod_copy) allows unauthenticated file copy → RCE.",
		banner: regexp.MustCompile(`ProFTPD 1\.3\.5\b`),
	},
	{
		id: "vsftpd-backdoor", name: "vsftpd Backdoor", severity: Critical,
		cve: "CVE-2011-2523", cvss: 10.0,
		desc:   "vsftpd 2.3.4 contains a backdoor triggered by ':)' in username.",
		banner: regexp.MustCompile(`vsftpd 2\.3\.4`),
	},
	{
		id: "ms-smb-eternalblue", name: "EternalBlue Candidate (SMBv1)", severity: Critical,
		cve: "CVE-2017-0144", cvss: 9.3,
		desc:   "Windows SMBv1 banner detected. Likely vulnerable to EternalBlue/WannaCry.",
		banner: regexp.MustCompile(`(?i)Windows.*SMB|SMB.*Windows`),
	},
	{
		id: "heartbleed-candidate", name: "OpenSSL Heartbleed Candidate", severity: Critical,
		cve: "CVE-2014-0160", cvss: 7.5,
		desc:   "OpenSSL 1.0.1a–1.0.1f detected. May be vulnerable to Heartbleed.",
		banner: regexp.MustCompile(`OpenSSL 1\.0\.1[a-f]\b`),
	},
}

// Detect returns all vulnerabilities that apply to the given port result.
func Detect(r proto.PortResult) []proto.Vulnerability {
	var found []proto.Vulnerability
	seen := make(map[string]struct{})

	add := func(rule rule) {
		if _, ok := seen[rule.id]; ok {
			return
		}
		seen[rule.id] = struct{}{}
		found = append(found, proto.Vulnerability{
			ID:       rule.id,
			Name:     rule.name,
			Severity: rule.severity,
			CVE:      rule.cve,
			CVSS:     rule.cvss,
			Desc:     rule.desc,
		})
	}

	for _, rl := range rules {
		// Port match
		for _, p := range rl.ports {
			if p == r.Port {
				add(rl)
			}
		}
		// Service match
		for _, svc := range rl.services {
			if strings.EqualFold(svc, r.Service) {
				add(rl)
			}
		}
		// Banner regex match
		if rl.banner != nil && r.Banner != "" && rl.banner.MatchString(r.Banner) {
			add(rl)
		}
	}
	return found
}
