# Zafiyet Veritabanı

PeekPort'un gömülü zafiyet kuralları. Tüm kurallar `internal/vuln/detector.go` dosyasındadır.

## Critical

| ID | Port(lar) | CVE | CVSS | Açıklama |
|----|-----------|-----|------|----------|
| `telnet-cleartext` | 23 | — | — | Telnet kimlik bilgilerini ve veriyi şifresiz iletir |
| `docker-api-exposed` | 2375 | CVE-2019-5736 | 8.6 | Kimlik doğrulamasız Docker API → tam host kontrolü |
| `redis-no-auth` | 6379 | — | — | Redis varsayılan olarak kimlik doğrulamasız çalışır |
| `mongodb-no-auth` | 27017, 27018 | — | — | MongoDB varsayılan config'de kimlik doğrulaması yok |
| `jupyter-no-auth` | 8888 | — | — | Token olmayan Jupyter Notebook → keyfi kod çalıştırma |
| `k8s-api-exposed` | 6443, 8001 | — | — | Kubernetes API server internete açık → cluster ele geçirme |
| `metasploit-port` | 4444, 31337, 12345, 23456, 54321 | — | — | Backdoor/exploit handler portları |
| `rsh-rlogin` | 512, 513, 514 | — | — | .rhosts tabanlı kimlik doğrulama → şifresiz uzaktan shell |
| `vault-exposed` | 8200 | — | — | HashiCorp Vault API açık; yanlış config'de secret sızdırır |
| `proftpd-rce` | Banner | CVE-2015-3306 | 10.0 | ProFTPD 1.3.5 mod_copy → kimlik doğrulamasız RCE |
| `vsftpd-backdoor` | Banner | CVE-2011-2523 | 10.0 | vsftpd 2.3.4 ':)' kullanıcı adıyla backdoor |
| `ms-smb-eternalblue` | Banner | CVE-2017-0144 | 9.3 | Windows SMBv1 → EternalBlue/WannaCry |
| `heartbleed-candidate` | Banner | CVE-2014-0160 | 7.5 | OpenSSL 1.0.1a–f → Heartbleed |

## High

| ID | Port(lar) | CVE | CVSS | Açıklama |
|----|-----------|-----|------|----------|
| `ftp-cleartext` | 20, 21 | — | — | FTP kimlik bilgileri şifresiz |
| `smb-exposed` | 445, 139 | CVE-2017-0144 | 9.3 | SMB internete açık → EternalBlue riski |
| `rdp-exposed` | 3389, 33389 | CVE-2019-0708 | 9.8 | RDP internete açık → BlueKeep / brute force |
| `vnc-exposed` | 5900–5902 | — | — | VNC genellikle zayıf/kimlik doğrulamasız |
| `elasticsearch-exposed` | 9200, 9300 | — | — | Elasticsearch < 8.x varsayılan olarak kimlik doğrulamasız |
| `memcached-exposed` | 11211 | CVE-2018-1000115 | 7.5 | UDP açık → 50.000× DDoS amplifikasyonu |
| `mssql-exposed` | 1433, 1434 | — | — | MS SQL internete açık → brute force / xp_cmdshell |
| `oracle-exposed` | 1521, 1522 | — | — | Oracle listener açık → TNS Poison, SID enum |
| `mysql-exposed` | 3306, 33060 | — | — | MySQL internete açık |
| `rsync-exposed` | 873 | — | — | rsync daemon kimlik doğrulamasız → dosya okuma/yazma |
| `nfs-exposed` | 2049, 111 | — | — | NFS export erişilebilir → filesystem mount |
| `activemq-admin` | 8161 | CVE-2023-46604 | 10.0 | ActiveMQ admin UI → kimlik doğrulamasız RCE |
| `radmin-exposed` | 4899 | — | — | Radmin internete açık |
| `couchdb-exposed` | 5984 | CVE-2017-12636 | 9.8 | CouchDB Futon/Fauxton admin → RCE |
| `neo4j-exposed` | 7474 | — | — | Neo4j browser açık; varsayılan admin:neo4j |
| `saltstack-exposed` | 4505, 4506 | CVE-2020-11651 | 9.8 | SaltStack ZMQ → kimlik doğrulama bypass / RCE |
| `kafka-exposed` | 9092 | — | — | Kafka broker kimlik doğrulamasız açık |
| `cassandra-exposed` | 9042 | — | — | Cassandra CQL kimlik doğrulamasız |
| `glassfish-admin` | 4848 | — | — | GlassFish admin; varsayılan admin:adminadmin |
| `openssh-old` | Banner | CVE-2023-38408 | 9.8 | OpenSSH < 9.3p2 → ssh-agent RCE |
| `apache-old` | Banner | — | — | Eski Apache httpd sürümü |

## Medium

| ID | Port(lar) | CVE | CVSS | Açıklama |
|----|-----------|-----|------|----------|
| `snmp-public` | 161, 162 | CVE-2002-0012 | 7.5 | SNMP community "public" → cihaz bilgisi sızıntısı |
| `ntp-amplification` | 123 | CVE-2013-5211 | 7.8 | NTP monlist → 600× DDoS amplifikasyonu |
| `smtp-exposed` | 25, 26 | — | — | SMTP açık → open relay testi önerilir |
| `dns-exposed` | 53 | — | — | DNS açık resolver → cache poisoning / amplifikasyon |
| `ldap-exposed` | 389 | — | — | LDAP şifresiz; anonim taramaya açık olabilir |
| `pptp-exposed` | 1723 | — | — | PPTP VPN MS-CHAPv2 kriptografik olarak kırık |
| `finger-exposed` | 79 | — | — | Finger daemon kullanıcı hesabı bilgisi sızdırır |
| `modbus-exposed` | 502 | — | — | Modbus (ICS/SCADA) internete açık → cihaz kontrolü |
| `zookeeper-exposed` | 2181 | — | — | ZooKeeper kimlik doğrulamasız; cluster config erişilebilir |
| `consul-exposed` | 8500, 8600 | — | — | Consul ACL yok → servis kataloğu okunabilir |
| `prometheus-exposed` | 9090, 9091, 9100 | — | — | Metrics endpoint altyapı detayı sızdırır |
| `webmin-exposed` | 10000 | CVE-2019-15107 | 10.0 | Webmin panel açık → kimlik doğrulamasız RCE |
| `socks-proxy` | 1080 | — | — | Açık SOCKS proxy → trafik pivotlama |
| `squid-proxy` | 3128 | — | — | Squid proxy açık |
| `rabbitmq-mgmt` | 15672 | — | — | RabbitMQ management UI; varsayılan guest:guest |
| `bacnet-exposed` | 47808 | — | — | BACnet bina otomasyonu internete açık |

## Low / Info

| ID | Port(lar) | Açıklama |
|----|-----------|----------|
| `wireguard-detected` | 51820 | WireGuard VPN endpoint tespit edildi |
| `git-daemon` | 9418 | Git daemon anonim clone'a izin verebilir |
| `nginx-version-exposed` | Banner | nginx sürüm bilgisi açıklanmış |

---

## Yeni Kural Ekleme

`internal/vuln/detector.go` dosyasındaki `rules` slice'ına ekleyin:

```go
{
    id:       "yeni-kural-id",
    name:     "İnsan Okunabilir İsim",
    severity: High, // Critical | High | Medium | Low | Info
    cve:      "CVE-2024-XXXX",       // opsiyonel
    cvss:     9.8,                   // opsiyonel
    desc:     "Açıklama metni.",
    ports:    []int{1234},           // port bazlı eşleşme
    services: []string{"servisad"}, // servis adı eşleşmesi
    banner:   regexp.MustCompile(`Regex İfadesi`), // banner eşleşmesi
},
```

En az bir eşleşme stratejisi (`ports`, `services` veya `banner`) zorunludur.
