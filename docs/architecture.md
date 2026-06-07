# Mimari

## Genel Bakış

PeekPort iki bileşenden oluşur:

```
┌─────────────────────────────────────────────────────────────────┐
│  Kısıtlı Ağ                                                     │
│  ┌──────────────────┐                                           │
│  │  peekport-client │──── HTTPS/WSS :443 ──→  ┌─────────────┐  │
│  │  (CLI)           │                          │  VDS Server │  │
│  └──────────────────┘  ←── Sonuç akışı ──────  │  :443/:80   │  │
│                                                └──────┬──────┘  │
└───────────────────────────────────────────────────────┼─────────┘
                                                        │ TCP/UDP
                                                        ▼
                                               [ Hedef Sistem ]
```

**Neden bu yapı?**
Kurumsal ağların çoğu giden bağlantılarda yalnızca 80/443'e izin verir. Client bu sınır içinde çalışırken VDS kısıtlanmamış internetten hedefi tarar.

---

## Paket Yapısı

```
PeekPort/
├── cmd/
│   ├── server/main.go      → Server CLI (cobra, flag parsing, api.ListenAndServe)
│   └── client/main.go      → Client CLI (cobra, renkli çıktı, progress bar)
│
├── internal/
│   ├── proto/types.go      → Paylaşılan JSON mesaj tipleri
│   │
│   ├── scanner/
│   │   ├── scanner.go      → Orkestrasyон: goroutine pool, progress, complete
│   │   ├── tcp.go          → TCP connect scan + banner grab
│   │   ├── udp.go          → UDP probe (protokole özgü payloadlar)
│   │   ├── service.go      → Port→servis haritası, probe payloadları, banner temizleme
│   │   └── ports.go        → Fast mod için ~200 bilinen port listesi
│   │
│   ├── vuln/
│   │   └── detector.go     → 40+ zafiyet kuralı (port/servis/banner regex bazlı)
│   │
│   └── api/
│       ├── server.go       → HTTP/WebSocket sunucusu, TLS (Let's Encrypt / dev)
│       ├── client.go       → WebSocket istemcisi, mesaj decode
│       └── tls.go          → TLS helper (insecure skip için)
│
├── docs/                   → Bu belgeler
├── go.mod / go.sum
└── Makefile
```

---

## İletişim Protokolü

Client ile server arası WebSocket üzerinden JSON mesajlaşması:

### Client → Server

**`scan_request`** — Tarama başlatma:
```json
{
  "type": "scan_request",
  "payload": {
    "target": "10.0.0.1",
    "mode": "fast",
    "protocols": ["tcp", "udp"],
    "timeout_ms": 1000,
    "concurrency": 500
  }
}
```

**`cancel`** — Taramayı iptal et:
```json
{ "type": "cancel", "payload": null }
```

### Server → Client

**`port_result`** — Açık port bulunduğunda anlık:
```json
{
  "type": "port_result",
  "payload": {
    "port": 6379,
    "protocol": "tcp",
    "state": "open",
    "service": "redis",
    "banner": "+PONG",
    "vulns": [{
      "id": "redis-no-auth",
      "name": "Redis Exposed",
      "severity": "Critical",
      "description": "..."
    }],
    "scan_ms": 12
  }
}
```

**`progress`** — Her 500ms'de bir:
```json
{
  "type": "progress",
  "payload": {
    "scanned": 850,
    "total": 171,
    "percent": 49.7,
    "open_count": 3
  }
}
```

**`scan_complete`** — Tarama tamamlandığında:
```json
{
  "type": "scan_complete",
  "payload": {
    "target": "10.0.0.1",
    "mode": "fast",
    "total_ports": 171,
    "open_ports": 5,
    "duration_s": 2.04,
    "start_time": "...",
    "end_time": "..."
  }
}
```

**`error`** — Hata durumunda:
```json
{
  "type": "error",
  "payload": { "code": "invalid_request", "message": "target is required" }
}
```

---

## Tarama Motoru

### TCP Tarama (`scanner/tcp.go`)

`net.DialContext` ile TCP connect scan. Bağlantı açılırsa:
1. Servis adı port haritasından alınır
2. Banner grab: önce sunucunun gönderdiği veri okunur; servis probe gerektiriyorsa (HTTP, Redis vb.) probe gönderilir
3. Banner 256 karakterle sınırlanır, kontrol karakterleri temizlenir

Durum kararı:
- `open` → bağlantı başarılı
- `closed` → "connection refused" ICMP
- `filtered` → timeout veya başka hata

### UDP Tarama (`scanner/udp.go`)

`net.DialTimeout("udp", ...)` ile socket açılır, port'a özgü probe gönderilir:

| Port | Protokol | Payload |
|------|----------|---------|
| 53 | DNS | version.bind TXT CHAOS sorgusu |
| 123 | NTP | NTP v3 client request (48 byte) |
| 161 | SNMP | GetRequest sysDescr.0 community=public |
| 137 | NetBIOS | Node status request |
| 1900 | SSDP | M-SEARCH * HTTP/1.1 |
| 5060 | SIP | OPTIONS request |
| 11211 | Memcached | `stats\r\n` |
| Diğer | — | `\x00` (ICMP unreachable tetikler) |

Durum kararı:
- `open` → UDP cevabı alındı
- `closed` → "connection refused" / "port unreachable" (ICMP)
- `filtered` → timeout (açık veya filtrelenmiş)

### Concurrency Modeli (`scanner/scanner.go`)

```
portlar × protokoller
      │
      ▼
  semaphore (chan struct{}, concurrency)
      │
      ├── goroutine 1: ScanTCP(port1)
      ├── goroutine 2: ScanUDP(port1)
      ├── goroutine 3: ScanTCP(port2)
      └── ...
            │
            ▼ (open only)
        results channel → WebSocket → Client
```

Progress goroutine'i `time.Ticker(500ms)` ile ayrı çalışır, atomic counter'lardan okur — scanner goroutine'lerine dokunmaz.

---

## Kimlik Doğrulama

API key şu iki kanaldan kabul edilir (öncelik sırası):

1. `X-API-Key` HTTP header
2. `?key=...` URL query parametresi (WebSocket handshake'te)

`--api-key` boş bırakılırsa sunucu herkese açık çalışır (yalnızca dev ortamı için).

---

## TLS

| Mod | Davranış |
|-----|----------|
| Üretim (`--domain`) | Let's Encrypt ACME (`golang.org/x/crypto/acme/autocert`); :80 challenge + redirect, :443 HTTPS |
| Geliştirme (`--dev`) | TLS yok; belirlenen port üzerinde düz HTTP |
| Client `--insecure` | `InsecureSkipVerify: true`; self-signed sertifikalı dev serverlar için |

---

## Zafiyet Dedektörü

`internal/vuln/detector.go` üç eşleşme stratejisi uygular:

1. **Port bazlı** — Belirli port açıksa kural tetiklenir (örn. 6379 → redis-no-auth)
2. **Servis bazlı** — Tespit edilen servis adıyla eşleşme
3. **Banner regex** — Düzenli ifadeyle banner'dan versiyon/imza tespiti (örn. `ProFTPD 1\.3\.5` → CVE-2015-3306)

Kural eklemek için `rules` slice'ına yeni bir `rule{}` struct'ı eklemek yeterlidir.
