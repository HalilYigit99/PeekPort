# PeekPort

Kısıtlı ağlarda çalışan dağıtık port tarayıcısı. Yalnızca 80/443 açık olan ağlardaki makinelerden bile tam kapsamlı TCP/UDP port taraması ve zafiyet tespiti yapabilirsiniz.

```
[Client · kısıtlı ağ]  ←─ HTTPS/WSS ─→  [VDS Server]  ←─ TCP/UDP ─→  [Hedef]
```

## Özellikler

- **İki tarama modu** — `fast`: ~200 bilinen port | `full`: tüm 1–65535 port
- **TCP + UDP** — TCP connect scan, UDP probe (DNS/NTP/SNMP/SSDP/SIP özel payloadlar)
- **Gerçek zamanlı akış** — Sonuçlar WebSocket üzerinden anlık gelir
- **Otomatik zafiyet tespiti** — 40+ kural: port/servis/banner bazlı (CVE dahil)
- **Let's Encrypt TLS** — Prod ortamda otomatik HTTPS sertifikası
- **API key koruması** — Yetkisiz kullanıma karşı paylaşımlı gizli anahtar
- **JSON çıktısı** — Raporlama / pipeline entegrasyonu için `--output json`

## Hızlı Başlangıç

### Gereksinimler

- Go 1.22+
- VDS için: public domain adı + 80/443 açık portlar

### Kurulum

```bash
git clone https://github.com/kullanici/peekport.git
cd peekport
make build
# bin/peekport-server ve bin/peekport-client hazır
```

### Server (VDS)

```bash
# Üretim – Let's Encrypt otomatik sertifika
./bin/peekport-server \
  --domain scan.example.com \
  --email admin@example.com \
  --api-key GIZLI_ANAHTAR

# Geliştirme – TLS yok, özel port
./bin/peekport-server --dev --port 9000 --api-key test
```

### Client (CLI)

```bash
# Hızlı tarama (TCP, bilinen portlar)
./bin/peekport-client scan \
  --server wss://scan.example.com \
  --target 10.0.0.1 \
  --api-key GIZLI_ANAHTAR

# Tam tarama (TCP + UDP, 1-65535)
./bin/peekport-client scan \
  --server wss://scan.example.com \
  --target 192.168.1.0 \
  --mode full \
  --proto tcp,udp \
  --timeout 800 \
  --concurrency 1000

# JSON raporu
./bin/peekport-client scan \
  --server wss://scan.example.com \
  --target 10.0.0.1 \
  --output json > rapor.json
```

Çevre değişkenleriyle da kullanılabilir:

```bash
export PEEKPORT_SERVER=wss://scan.example.com
export PEEKPORT_API_KEY=GIZLI_ANAHTAR
./bin/peekport-client scan --target 10.0.0.1
```

## Mimari

Ayrıntılar için → [docs/architecture.md](docs/architecture.md)

## Tarama Modları

| Mod | Port Sayısı | Kullanım Durumu |
|-----|-------------|-----------------|
| `fast` | ~200 | Hızlı keşif, günlük kontrol |
| `full` | 65535 | Kapsamlı güvenlik denetimi |

## Tespit Edilen Zafiyetler

Ayrıntılar için → [docs/vulnerabilities.md](docs/vulnerabilities.md)

| Seviye | Örnekler |
|--------|----------|
| Critical | Redis/MongoDB açık, Docker API, Telnet, rsh/rlogin, Jupyter Notebook |
| High | SMB/EternalBlue, RDP/BlueKeep, VNC, Elasticsearch, Memcached UDP amplification |
| Medium | SNMP community public, NTP amplification, SMTP open relay, Modbus/ICS |
| Low/Info | Git daemon, WireGuard, nginx sürüm ifşası |

## Derleme Seçenekleri

```bash
make build          # Yerel platform (server + client)
make server-linux   # VDS için Linux amd64 server
make client-linux   # Linux amd64 client
make clean          # bin/ temizle
```

## Etik Kullanım

Bu araç yalnızca **yetkili** güvenlik testleri, penetrasyon testleri ve IT altyapı denetimi için tasarlanmıştır. İzinsiz sistemlerde kullanmak yasadışıdır. Kullanıcı, hedef sistemler üzerinde gerekli yetkiye sahip olduğunu kabul etmiş sayılır.

## Lisans

MIT
