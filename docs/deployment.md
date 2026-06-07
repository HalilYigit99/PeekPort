# VDS Kurulum Rehberi

## Gereksinimler

- Ubuntu 22.04+ / Debian 12+ (veya benzeri Linux dağıtımı)
- Public IP adresi
- Bir alan adı (Let's Encrypt için)
- Go 1.22+ veya önceden derlenmiş binary

## 1. Firewall Ayarları

```bash
# UFW ile
ufw allow 22/tcp    # SSH
ufw allow 80/tcp    # ACME HTTP challenge
ufw allow 443/tcp   # HTTPS / WebSocket
ufw enable
```

## 2. DNS Kaydı

```
scan.example.com  A  <VDS_IP>
```

DNS propagasyonunun tamamlanmasını bekleyin (`dig scan.example.com` ile kontrol edin).

## 3. Binary Kopyalama

```bash
# Geliştirme makinenizde Linux binary derleyin
make server-linux

# VDS'e kopyalayın
scp bin/peekport-server-linux-amd64 user@vds:/usr/local/bin/peekport-server
chmod +x /usr/local/bin/peekport-server
```

## 4. systemd Servisi

```ini
# /etc/systemd/system/peekport.service
[Unit]
Description=PeekPort Scan Server
After=network.target

[Service]
Type=simple
User=nobody
ExecStart=/usr/local/bin/peekport-server \
    --domain scan.example.com \
    --email admin@example.com \
    --api-key BURAYA_GIZLI_ANAHTAR \
    --cert-dir /var/cache/peekport/certs
Restart=on-failure
RestartSec=5s
# Sertifika cache dizini
RuntimeDirectory=peekport
StateDirectory=peekport

[Install]
WantedBy=multi-user.target
```

```bash
# Sertifika dizini oluştur
mkdir -p /var/cache/peekport/certs
chown nobody:nobody /var/cache/peekport/certs

# Servisi etkinleştir ve başlat
systemctl daemon-reload
systemctl enable peekport
systemctl start peekport

# Logları izle
journalctl -u peekport -f
```

## 5. Bağlantı Testi

```bash
# Server sağlık kontrolü
curl https://scan.example.com/health

# Client ile test taraması
./peekport-client scan \
    --server wss://scan.example.com \
    --target 127.0.0.1 \
    --mode fast \
    --api-key BURAYA_GIZLI_ANAHTAR
```

## API Key Güvenliği

- En az 32 karakter, rastgele üretin: `openssl rand -hex 32`
- Çevre değişkeniyle geçirin: `Environment=PEEKPORT_API_KEY=...` (systemd unit'e ekleyin)
- Client tarafında da çevre değişkeni kullanın: `export PEEKPORT_API_KEY=...`
- API key'i asla kaynak koda ya da git'e commit etmeyin

## Sorun Giderme

| Sorun | Çözüm |
|-------|-------|
| Let's Encrypt başarısız | 80. port açık mı? DNS kaydı doğru mu? |
| WebSocket bağlanamıyor | Firewall 443'e izin veriyor mu? |
| `unauthorized` hatası | Client ve server aynı `--api-key` kullanıyor mu? |
| UDP taramaları hep `filtered` | VDS'de UDP giden izinleri var mı? Root yetkisi gerekebilir |
