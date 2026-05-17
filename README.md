# fwatcher

File Integrity Monitor sederhana berbasis Go. Mencatat **siapa**, **apa**, dan **kapan**
sebuah file dibuat / diubah / dihapus, lengkap dengan **hash SHA256** dan **unified diff**
isi perubahannya. Output berupa JSON-lines yang siap diserap oleh
[Wazuh](https://wazuh.com/) (atau SIEM lain yang bisa membaca file log).

## Fitur

- Watch banyak path (file atau folder), rekursif opsional
- Deteksi event: `created`, `modified`, `deleted`, `renamed_from`, `permission_changed`, `dir_created`
- Catat **pemilik file** (Windows: `DOMAIN\user` via SID, Linux: username via uid)
- Catat **proses yang sedang membuka file** saat event terjadi (best-effort):
  - Linux: scan `/proc/*/fd/*`
  - Windows: Restart Manager API (`rstrtmgr.dll`)
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
  "timestamp": "2026-05-17T12:50:03.522Z",
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
  "is_binary": false,
  "editor_pid": 14236,
  "editor_user": "ops-deploy",
  "editor_proc": "ansible-playbook",
  "editor_exe": "/usr/bin/python3"
}
```

| Field               | Tipe   | Catatan                                                    |
|---------------------|--------|------------------------------------------------------------|
| `timestamp`         | string | RFC3339 nanosekon, UTC                                     |
| `source`            | string | Selalu `"fwatcher"` — pakai ini untuk filter di Wazuh      |
| `host`              | string | Hostname mesin                                             |
| `event_type`        | string | `created` / `modified` / `deleted` / `renamed_from` / `permission_changed` / `dir_created` / `watcher_error` / `service_started` / `service_stopped` |
| `path`              | string | Path absolut                                               |
| `user`              | string | **Pemilik** file saat event                                |
| `size_before/after` | int    | Bytes                                                      |
| `hash_before/after` | string | `sha256:<hex>` atau `skipped:too_large`                    |
| `diff`              | string | Unified diff isi (kosong untuk binary / oversize)          |
| `diff_truncated`    | bool   | `true` jika diff dipotong sampai `max_diff_output_kb`      |
| `is_binary`         | bool   | `true` jika file terdeteksi binary (NUL byte di 8 KB awal) |
| `editor_pid`        | int    | PID proses yang sedang membuka file saat event (best-effort) |
| `editor_user`       | string | User dari proses tsb (Linux: username, Windows: `DOMAIN\user`) |
| `editor_proc`       | string | Nama proses / image (`/proc/PID/comm` atau `RM_PROCESS_INFO.strAppName`) |
| `editor_exe`        | string | Path lengkap executable saat tersedia                      |

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

Ada dua field yang menjawab pertanyaan ini, dengan reliabilitas berbeda:

### `user` — pemilik file (selalu ada)

File owner SID di Windows, uid di Linux. **Bukan** orang yang mengetik perubahan,
melainkan pemilik permanen file. Selalu tersedia.

### `editor_*` — proses yang sedang membuka file (best-effort)

Saat event terjadi, fwatcher scan proses-proses yang sedang memegang handle ke file
tersebut:

- **Linux:** baca `/proc/*/fd/*`. Tanpa root cuma lihat proses milik sendiri; jalankan
  via systemd (`User=root`) untuk visibility penuh.
- **Windows:** Restart Manager API. Tidak butuh admin.

**Kapan ini berhasil:**
- Editor menahan file selama proses edit (`vim` mode-w-O_TRUNC sebentar, `nano` saat save,
  `notepad`, IDE yang menahan handle, deployment script yang tulis-perlahan)

**Kapan ini gagal (field kosong):**
- Atomic-write (VSCode, modern vim, `cp`, package installer) — tulis ke tmp lalu rename,
  saat scan dilakukan tmp sudah ditutup
- Write super cepat (millidetik) yang selesai sebelum debounce + scan
- Edit dari proses milik user lain saat fwatcher tidak running sebagai root

**Untuk audit kuat (100% reliable identitas penulis):**

- **Linux:** aktifkan `auditd` dengan rule pada path yang sama, misal:
  ```bash
  sudo auditctl -w /etc/passwd -p wa -k fim
  ```
  Wazuh ingest `/var/log/audit/audit.log` otomatis dan korelasikan via field `path`.
- **Windows:** aktifkan Audit Policy (Group Policy → Local Policies → Audit Policy →
  Audit object access) + SACL di file. Event 4663 muncul di Security log dan Wazuh
  agent membacanya.

fwatcher tetap berguna sebagai **layer kedua** — auditd / Event 4663 memberi identitas
tapi tidak memberi **isi perubahan**. fwatcher melengkapi dengan hash + diff.

## Lisensi

MIT
