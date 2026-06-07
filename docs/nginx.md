# NGINX Arkasında Kurulum

NGINX zaten 80 ve 443'ü tutuyorsa PeekPort'u `--dev` moduyla iç portta (örn. `9000`) çalıştırırsınız. TLS'i NGINX üstlenir; PeekPort sadece düz HTTP üzerinden dinler.

```
İstemci ──── HTTPS/WSS :443 ──→  NGINX  ──── HTTP/WS :9000 ──→  PeekPort
```

---

## 1. PeekPort'u İç Portta Çalıştırın

`--dev --port 9000` ile başlatırsanız PeekPort ne TLS ne ACME ile uğraşır:

```bash
peekport-server --dev --port 9000 --api-key GIZLI_ANAHTAR
```

systemd servisinde (`/etc/systemd/system/peekport.service`):

```ini
[Unit]
Description=PeekPort Scan Server
After=network.target

[Service]
Type=simple
User=nobody
ExecStart=/usr/local/bin/peekport-server \
    --dev \
    --port 9000 \
    --api-key GIZLI_ANAHTAR
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now peekport
```

---

## 2. NGINX Konfigürasyonu

`/etc/nginx/sites-available/peekport` dosyasını oluşturun:

```nginx
# HTTP → HTTPS yönlendirme (zaten varsa bu bloğu atla)
server {
    listen 80;
    server_name scan.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name scan.example.com;

    # Sertifika — Certbot kullanıyorsanız bu yollar otomatik doldurulur
    ssl_certificate     /etc/letsencrypt/live/scan.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/scan.example.com/privkey.pem;

    # Önerilen SSL ayarları
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;

    # ── WebSocket proxy (/ws) ──────────────────────────────────────
    location /ws {
        proxy_pass         http://127.0.0.1:9000;
        proxy_http_version 1.1;

        # WebSocket handshake için zorunlu
        proxy_set_header Upgrade    $http_upgrade;
        proxy_set_header Connection "upgrade";

        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Uzun taramalar için timeout'ları artırın
        # full mod 65535 port × 1 s ≈ birkaç dakika olabilir
        proxy_read_timeout  3600s;
        proxy_send_timeout  3600s;
        proxy_connect_timeout 10s;

        # Büyük binary payload yok; buffer'ı küçük tutun
        proxy_buffering off;
    }

    # ── Health check ──────────────────────────────────────────────
    location /health {
        proxy_pass http://127.0.0.1:9000;
    }

    # Diğer path'lere erişimi kapat
    location / {
        return 404;
    }
}
```

Etkinleştirin ve test edin:

```bash
ln -s /etc/nginx/sites-available/peekport /etc/nginx/sites-enabled/
nginx -t                  # konfigürasyon hata kontrolü
systemctl reload nginx
```

---

## 3. Certbot ile Sertifika (zaten yoksa)

NGINX eklentisiyle otomatik konfigürasyon:

```bash
apt install certbot python3-certbot-nginx
certbot --nginx -d scan.example.com --email admin@example.com --agree-tos
```

Certbot `ssl_certificate` satırlarını otomatik doldurur ve yenilemeyi cron'a ekler.

---

## 4. Client Bağlantısı

Client aynı şekilde `wss://` kullanır; NGINX şeffaf proxy olduğundan değişiklik gerekmez:

```bash
peekport-client scan \
    --server  wss://scan.example.com \
    --target  10.0.0.1 \
    --api-key GIZLI_ANAHTAR
```

---

## Sorun Giderme

| Belirti | Olası neden | Çözüm |
|---------|-------------|-------|
| `502 Bad Gateway` | PeekPort çalışmıyor | `systemctl status peekport` |
| WebSocket bağlanamıyor | `Upgrade` header eksik | `proxy_set_header Upgrade` satırını ekleyin |
| Uzun taramalar kopuyor | NGINX timeout çok kısa | `proxy_read_timeout 3600s` olduğunu doğrulayın |
| `403 Forbidden` | NGINX başka bir location engelledi | `/ws` ve `/health` location bloklarının sırasını kontrol edin |
| Sertifika hatası | Certbot çalışmamış | `certbot renew --dry-run` ile test edin |

---

## Özet: Ne Nereye Bakıyor?

```
İstemci
  │  wss://scan.example.com/ws
  ▼
NGINX :443 (TLS sonlandırma)
  │  proxy_pass http://127.0.0.1:9000/ws
  │  Upgrade: websocket
  ▼
PeekPort --dev --port 9000
  │  TCP/UDP scan
  ▼
Hedef sistem
```
