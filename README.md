# fwatcher

File Integrity Monitor sederhana berbasis Go. Mencatat **siapa**, **apa**, dan **kapan**
sebuah file dibuat / diubah / dihapus, lengkap dengan **hash SHA256** dan **unified diff**
isi perubahannya. Output berupa JSON-lines yang siap diserap oleh
[Wazuh](https://wazuh.com/) (atau SIEM lain yang bisa membaca file log).

## Fitur

- Watch banyak path (file atau folder), rekursif opsional
- Deteksi event: `created`, `modified`, `deleted`, `renamed_from`, `permission_changed`, `dir_created`
- Catat **pemilik file** (Windows: `DOMAIN\user` via SID, Linux: username via uid)
- **SHA256 sebelum/sesudah** untuk verifikasi perubahan isi
- **Unified diff** untuk file teks (mirip `diff -u`), dengan deteksi binary otomatis
- Debounce burst event dari editor & installer
- Ignore pattern (glob basename atau substring path)
- Output JSON per baris → langsung dimakan Wazuh `<localfile log_format="json">`
- Single binary, no CGO, cross-platform (Windows / Linux / macOS)

## Instalasi cepat

### Build dari source

```bash
git clone https://github.com/<USER>/fwatcher.git
cd fwatcher
go build -o fwatcher .
```

Cross-compile ke Linux dari Windows / macOS:

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o fwatcher-linux-amd64 .
```

### Jalankan

```bash
# Edit config dulu (lihat config.yaml / config.linux.yaml)
./fwatcher -config config.yaml
```

## Konfigurasi

`config.yaml` — semua kolom + defaultnya:

```yaml
paths:                        # WAJIB: path absolut, file atau folder
  - "/etc"
  - "/var/www"

recursive: true               # ikut subfolder
log_path: "/var/log/fwatcher/fwatcher.json"

hash_files: true              # hitung SHA256 sebelum/sesudah
max_hash_size_mb: 100         # file > N MB di-skip hashing-nya

debounce_ms: 300              # gabung burst event dalam jendela ms ini

# Unified diff isi perubahan
max_diff_size_kb: 512         # 0 = matikan diff (hanya hash)
diff_context_lines: 3
max_diff_output_kb: 16        # cap diff per event (Wazuh ~64KB max)

ignore_patterns:
  - "*.tmp"
  - "*.tmp.*"                 # atomic-write tempfiles
  - "*.swp"
  - ".git"
  - "node_modules"
```

### Trade-off `max_diff_size_kb`

Setiap file ≤ batas ini di-cache isinya di RAM agar bisa di-diff. Untuk 10 ribu file
kecil rata-rata 10 KB ≈ ~100 MB RAM. Set `0` untuk mematikan jika tidak butuh diff.

## Format event JSON

Satu baris = satu event. Contoh `modified`:

```json
{
  "timestamp": "2026-05-17T12:05:04.744Z",
  "source": "fwatcher",
  "host": "web-01",
  "event_type": "modified",
  "path": "/etc/nginx/nginx.conf",
  "user": "root",
  "size_before": 1432,
  "size_after": 1488,
  "hash_before": "sha256:abc123...",
  "hash_after": "sha256:def456...",
  "diff": "--- before\n+++ after\n@@ -10,3 +10,3 @@\n-    worker_processes 4;\n+    worker_processes 8;\n",
  "diff_truncated": false,
  "is_binary": false
}
```

| Field            | Tipe   | Catatan                                                    |
|------------------|--------|------------------------------------------------------------|
| `timestamp`      | string | RFC3339 nanosekon, UTC                                     |
| `source`         | string | Selalu `"fwatcher"` — pakai ini untuk filter di Wazuh      |
| `host`           | string | Hostname mesin                                             |
| `event_type`     | string | `created` / `modified` / `deleted` / `renamed_from` / `permission_changed` / `dir_created` / `watcher_error` / `service_started` / `service_stopped` |
| `path`           | string | Path absolut                                               |
| `user`           | string | Pemilik file saat event (lihat catatan di bawah)           |
| `size_before/after` | int | Bytes                                                      |
| `hash_before/after` | string | `sha256:<hex>` atau `skipped:too_large`                  |
| `diff`           | string | Unified diff isi (kosong untuk binary / oversize)          |
| `diff_truncated` | bool   | `true` jika diff dipotong sampai `max_diff_output_kb`      |
| `is_binary`      | bool   | `true` jika file terdeteksi binary (NUL byte di 8 KB awal) |

## Integrasi Wazuh

### Wazuh agent

Tambahkan ke `ossec.conf`:

```xml
<localfile>
  <location>/var/log/fwatcher/fwatcher.json</location>
  <log_format>json</log_format>
  <label key="@source">fwatcher</label>
</localfile>
```

Restart:

```bash
sudo systemctl restart wazuh-agent
```

### Wazuh manager (rules)

Lihat [`wazuh/local_rules.xml`](wazuh/local_rules.xml). Tambahkan ke
`/var/ossec/etc/rules/local_rules.xml` di server manager, lalu:

```bash
sudo systemctl restart wazuh-manager
```

Rule ID 100200–100205 dipakai sebagai contoh — sesuaikan supaya tidak bentrok.

## Jalankan sebagai service (Linux / systemd)

```bash
sudo bash systemd/install.sh
sudo nano /etc/fwatcher/config.yaml
sudo systemctl start fwatcher
sudo tail -f /var/log/fwatcher/fwatcher.json
```

Unit file: [`systemd/fwatcher.service`](systemd/fwatcher.service) — sudah disertai
hardening dasar (`ProtectSystem=strict`, `NoNewPrivileges`, dll).

## Tuning inotify (Linux)

Untuk path besar (`/home` rekursif, dll), naikkan limit watch:

```bash
echo fs.inotify.max_user_watches=524288 | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

## Catatan: "siapa yang edit"

Field `user` di event berisi **pemilik file** (file owner SID di Windows, uid di Linux),
**bukan** orang yang sebenarnya mengetik perubahan. fsnotify / inotify tidak menyediakan
identitas penulis. Untuk audit yang akurat:

- **Linux:** aktifkan `auditd` dengan rule pada path yang sama → Wazuh mengkorelasikan via field `path`.
- **Windows:** aktifkan audit policy untuk object access (Event 4663) → Wazuh agent membaca event log.

fwatcher tetap berguna sebagai **layer kedua** karena memberi hash + diff yang tidak
disediakan auditd / Event Log.

## Lisensi

MIT
