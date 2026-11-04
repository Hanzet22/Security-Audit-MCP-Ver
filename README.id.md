# Security-Audit-MCP-Ver

[English (EU)](./README.md) · [English (US)](./README.en-US.md) · [Bahasa Indonesia](./README.id.md) · [Malay (Singapore)](./README.ms-SG.md)

Perangkat audit keamanan kode sumber berbasis bukti yang bersifat **read-only** dan tersedia melalui Model Context Protocol (MCP).

Implementasi independen yang terinspirasi oleh alur kerja [Cloudflare Security Audit Skill](https://github.com/cloudflare/security-audit-skill). Proyek ini tidak berafiliasi dengan atau didukung secara resmi oleh Cloudflare. Materi upstream Cloudflare tetap menggunakan lisensi MIT aslinya; kode proyek ini menggunakan AGPL-3.0-or-later. Lihat [ATTRIBUTIONS.md](./ATTRIBUTIONS.md).

## Status

**Status publikasi versi 0.3.0: masih menunggu.** Tag rilis dan GitHub Release resmi harus tersedia sebelum versi ini dinyatakan telah diterbitkan. Lihat [RELEASE_CHECKLIST.md](./RELEASE_CHECKLIST.md).

Server menyediakan 18 MCP tools untuk reconnaissance repositori, perencanaan cakupan, peninjauan kode sumber, validasi temuan, verifikasi independen, kontrak orkestrasi, dan pembuatan laporan. Ini adalah kumpulan primitive alur kerja, bukan agen audit otonom.

## Persyaratan

- Node.js 22 atau lebih baru (gunakan versi LTS yang masih didukung).
- Klien yang kompatibel dengan MCP.
- Token GitHub fine-grained opsional untuk repositori privat atau batas API yang lebih tinggi. Berikan izin **Contents: read-only** dan **Metadata: read-only** saja.

## Instalasi dari source

```bash
git clone https://github.com/Hanzet22/Security-Audit-MCP-Ver.git
cd Security-Audit-MCP-Ver
npm ci
npm run build
```

Untuk menjalankan rangkaian validasi lokal:

```bash
npm run typecheck
npm test
npm run build
```

Entry point STDIO untuk produksi adalah `dist/stdio.js`. Saat ini server hanya mendukung **transport STDIO lokal**; belum menyediakan endpoint HTTP, URL MCP jarak jauh, OAuth, atau layanan hosted.

## Konfigurasi klien MCP

Ganti `/absolute/path/to/Security-Audit-MCP-Ver` dengan lokasi folder repositori hasil clone di perangkat Anda. Build proyek sebelum menghubungkan klien.

### Claude Code

Tambahkan server untuk seluruh proyek pengguna:

```bash
claude mcp add --transport stdio --scope user security-audit-mcp-ver -- node /absolute/path/to/Security-Audit-MCP-Ver/dist/stdio.js
claude mcp list
```

Jalankan `/mcp` di Claude Code untuk memeriksa koneksi. Untuk konfigurasi khusus proyek, gunakan `--scope project`.

### OpenAI Codex CLI

```bash
codex mcp add security-audit-mcp-ver -- node /absolute/path/to/Security-Audit-MCP-Ver/dist/stdio.js
codex mcp list
```

Codex menyimpan konfigurasi di `~/.codex/config.toml`. Konfigurasi manual:

```toml
[mcp_servers.security-audit-mcp-ver]
command = "node"
args = ["/absolute/path/to/Security-Audit-MCP-Ver/dist/stdio.js"]
```

### Cursor

Buat file `.cursor/mcp.json` di proyek, atau gunakan konfigurasi MCP global Cursor:

```json
{
  "mcpServers": {
    "security-audit-mcp-ver": {
      "command": "node",
      "args": ["/absolute/path/to/Security-Audit-MCP-Ver/dist/stdio.js"]
    }
  }
}
```

### Visual Studio Code

Untuk klien yang menggunakan format konfigurasi MCP VS Code, buat file `.vscode/mcp.json`:

```json
{
  "servers": {
    "security-audit-mcp-ver": {
      "type": "stdio",
      "command": "node",
      "args": ["/absolute/path/to/Security-Audit-MCP-Ver/dist/stdio.js"]
    }
  }
}
```

Format konfigurasi dapat berbeda antar klien. Periksa dokumentasi MCP resmi klien jika formatnya berubah.

## Token GitHub opsional

Repositori publik dapat dibaca tanpa token, dengan mengikuti batas API GitHub untuk permintaan tanpa autentikasi. Jika diperlukan, atur `GITHUB_TOKEN` pada environment server di konfigurasi klien MCP. Gunakan token fine-grained yang dibatasi pada repositori yang diperlukan, dengan izin **Contents: read-only** dan **Metadata: read-only**. Jangan pernah commit token atau memasukkannya ke argumen tool.

Contoh konfigurasi klien yang mendukung environment variable:

```json
{
  "mcpServers": {
    "security-audit-mcp-ver": {
      "command": "node",
      "args": ["/absolute/path/to/Security-Audit-MCP-Ver/dist/stdio.js"],
      "env": {
        "GITHUB_TOKEN": "YOUR_READ_ONLY_TOKEN"
      }
    }
  }
}
```

Utamakan secret manager sistem operasi atau mekanisme environment variable aman milik klien daripada menyimpan token di file proyek bersama.

## Fungsi server

- Membaca metadata repositori GitHub, tree terbatas, dan file teks.
- Menyiapkan laporan reconnaissance dan coverage ledger kanonis.
- Merencanakan hunting wave terbatas serta memvalidasi hasil yang diberikan caller.
- Memvalidasi temuan, struktur bukti, dan fingerprint unik.
- Memeriksa catatan reviewer terpisah.
- Menghasilkan laporan audit JSON dan Markdown.

## Model keamanan dan batasan

- Akses GitHub bersifat read-only.
- Server tidak meng-clone atau mengeksekusi kode repositori target.
- Server tidak memindai endpoint produksi atau infrastruktur pihak ketiga.
- Hasil pencocokan heuristik hanyalah kandidat, bukan bukti kerentanan.
- Ref, rentang baris, hasil worker, dan state orkestrasi dari caller tidak memiliki attestasi kriptografis.
- Gate alur kerja memeriksa konsistensi data; bukan membuktikan bahwa pekerjaan independen benar-benar dilakukan.
- Server tidak membuat agent, background job, antrean persisten, atau autentikasi bukti independen.
- Laporan tetap berstatus incomplete jika gate coverage dan verification belum terpenuhi.

Batas sumber daya penting: timeout GitHub API 15 detik, batas respons 5 MB, maksimal 500 entri tree, batas file individual 300 KB, dan 100.000 karakter source text per operasi review. Input yang terpotong atau ditolak tidak boleh dianggap telah diperiksa sepenuhnya.

## Pengembangan dan kontribusi

```bash
npm ci
npm run typecheck
npm test
npm run build
```

Lihat [CONTRIBUTING.md](./CONTRIBUTING.md), [SECURITY.md](./SECURITY.md), [CHANGELOG.md](./CHANGELOG.md), dan [RELEASE_CHECKLIST.md](./RELEASE_CHECKLIST.md).

## Lisensi

Kode proyek: **GNU Affero General Public License v3.0 atau lebih baru**. Lihat [LICENSE](./LICENSE).

Materi upstream pihak ketiga: lihat [ATTRIBUTIONS.md](./ATTRIBUTIONS.md) dan pemberitahuan lisensi yang dipertahankan di `vendor/cloudflare-security-audit-skill/`.
