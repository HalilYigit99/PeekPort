package scanner

// WellKnownPorts is the curated list used in "fast" mode scan.
// Covers most commonly attacked / monitored ports.
var WellKnownPorts = dedup([]int{
	// ── System / IANA (0-1023) ──────────────────────────────────────
	20, 21,             // FTP data/ctrl
	22,                 // SSH / SFTP
	23,                 // Telnet
	25, 26, 465, 587,   // SMTP variants
	43,                 // WHOIS
	53,                 // DNS
	67, 68,             // DHCP
	69,                 // TFTP
	70,                 // Gopher
	79,                 // Finger
	80, 81, 82, 83,     // HTTP
	88,                 // Kerberos
	109, 110, 995,      // POP2/3
	111,                // RPCbind / Portmapper
	119, 563,           // NNTP
	123,                // NTP
	135,                // MS RPC
	137, 138, 139,      // NetBIOS
	143, 993,           // IMAP
	161, 162,           // SNMP
	179,                // BGP
	194,                // IRC
	389, 636,           // LDAP / LDAPS
	443,                // HTTPS
	445,                // SMB / CIFS
	500, 4500,          // IKE / IPsec NAT-T
	502,                // Modbus (ICS)
	512, 513, 514,      // rexec / rlogin / rsh
	515,                // LPD / LPR
	520,                // RIP
	523,                // IBM DB2
	524,                // Novell NCP
	548,                // AFP (Apple)
	554,                // RTSP
	631,                // CUPS
	873,                // rsync
	902, 903,           // VMware
	989, 990,           // FTP over TLS
	// ── Registered (1024-49151) ─────────────────────────────────────
	1080,               // SOCKS proxy
	1194,               // OpenVPN
	1433, 1434,         // MS SQL Server
	1521, 1522,         // Oracle DB
	1720,               // H.323
	1723,               // PPTP
	1812, 1813,         // RADIUS
	1883, 8883,         // MQTT
	1900,               // SSDP / UPnP
	2049,               // NFS
	2082, 2083,         // cPanel HTTP/S
	2086, 2087,         // WHM HTTP/S
	2095, 2096,         // cPanel webmail
	2121,               // FTP alt
	2181,               // ZooKeeper
	2222,               // SSH alt / DirectAdmin
	2375, 2376,         // Docker HTTP / TLS
	2379, 2380,         // etcd
	2525,               // SMTP alt
	3000,               // Grafana / Node dev
	3128,               // Squid proxy
	3268, 3269,         // Global Catalog
	3306,               // MySQL / MariaDB
	3389,               // RDP
	3690,               // SVN
	4000,               // generic dev
	4443,               // HTTPS alt
	4444,               // Metasploit / netcat backdoor
	4505, 4506,         // SaltStack
	4848,               // GlassFish admin
	4899,               // Radmin
	5000, 5001,         // UPnP / generic dev
	5060, 5061,         // SIP
	5222, 5269,         // XMPP client/server
	5432,               // PostgreSQL
	5601,               // Kibana
	5672, 15672,        // RabbitMQ AMQP / management
	5900, 5901, 5902,   // VNC
	5984,               // CouchDB
	6000, 6001,         // X11
	6379,               // Redis
	6443,               // Kubernetes API
	6667, 6697,         // IRC / IRC SSL
	7070, 7443,         // WebLogic / alt HTTPS
	7474,               // Neo4j
	7777,               // various
	8000, 8001,         // HTTP alt / K8s proxy
	8008, 8009,         // HTTP alt / Tomcat AJP
	8069,               // Odoo / OpenERP
	8080, 8081, 8082,   // HTTP proxy / apps
	8088, 8090,         // Hadoop / Confluence
	8118,               // Privoxy
	8140,               // Puppet
	8161,               // ActiveMQ admin
	8200,               // HashiCorp Vault
	8443,               // HTTPS alt / Tomcat
	8500,               // Consul HTTP
	8600,               // Consul DNS
	8880,               // Plesk HTTP
	8888,               // Jupyter Notebook
	9000,               // SonarQube / PHP-FPM
	9001,               // Tor ORPort / Supervisord
	9042,               // Cassandra CQL
	9090,               // Prometheus / Cockpit
	9091,               // Prometheus push
	9092,               // Apache Kafka
	9100,               // Node exporter / raw print
	9200, 9300,         // Elasticsearch
	9418,               // Git daemon
	9987,               // TeamSpeak 3 voice
	10000,              // Webmin
	10011,              // TeamSpeak query
	11211,              // Memcached
	27017, 27018,       // MongoDB
	28017,              // MongoDB web UI
	30033,              // TeamSpeak file transfer
	33060,              // MySQL X Protocol
	47808,              // BACnet (BMS)
	50000,              // SAP / IBM DB2
	51820,              // WireGuard
	// ── High / unusual ──────────────────────────────────────────────
	31337,              // classic backdoor port
	12345, 23456, 54321, // common trojan ports
	65535,              // max port (often scanned)
})

func dedup(ports []int) []int {
	seen := make(map[int]struct{}, len(ports))
	out := make([]int, 0, len(ports))
	for _, p := range ports {
		if _, ok := seen[p]; !ok {
			seen[p] = struct{}{}
			out = append(out, p)
		}
	}
	return out
}
