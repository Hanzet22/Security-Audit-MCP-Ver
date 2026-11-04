# Security-Audit-MCP-Ver

[English (EU)](./README.md) · [English (US)](./README.en-US.md) · [Bahasa Indonesia](./README.id.md) · [Malay (Singapore)](./README.ms-SG.md)

**Setup guide:** [SETUP.md](./SETUP.md)

Alat audit keselamatan kod sumber berasaskan bukti yang bersifat **read-only** dan disediakan melalui Model Context Protocol (MCP).

Pelaksanaan bebas yang diilhamkan oleh aliran kerja [Cloudflare Security Audit Skill](https://github.com/cloudflare/security-audit-skill). Projek ini tidak bersekutu dengan atau disokong secara rasmi oleh Cloudflare. Bahan upstream Cloudflare kekal di bawah lesen MIT asal; kod projek ini dilesenkan di bawah AGPL-3.0-or-later. Rujuk [ATTRIBUTIONS.md](./ATTRIBUTIONS.md).

## Status

**Versi 0.3.1 — RELEASED.** Rujuk [CHANGELOG.md](./CHANGELOG.md) untuk nota keluaran dan [SETUP.md](./SETUP.md) bagi panduan pemasangan serta konfigurasi klien MCP.

Pelayan ini menyediakan 18 MCP tools untuk reconnaissance repositori, perancangan liputan, semakan kod sumber, pengesahan dapatan, verifikasi bebas, kontrak orkestrasi dan penjanaan laporan. Ia menyediakan komponen aliran kerja, bukannya ejen audit autonomi.

## Keperluan

- Node.js 22 atau lebih baharu (gunakan keluaran LTS yang masih disokong).
- Klien yang serasi dengan MCP.
- Token GitHub fine-grained pilihan untuk repositori persendirian atau had API yang lebih tinggi. Berikan kebenaran **Contents: read-only** dan **Metadata: read-only** sahaja.

## Pemasangan daripada source

```bash
git clone https://github.com/Hanzet22/Security-Audit-MCP-Ver.git
cd Security-Audit-MCP-Ver
npm ci
npm run build
```

Untuk menjalankan keseluruhan suite pengesahan setempat:

```bash
npm run typecheck
npm test
npm run build
```

Entry point STDIO untuk penggunaan produksi ialah `dist/stdio.js`. Buat masa ini, pelayan hanya menyokong **transport STDIO setempat**; ia belum menyediakan endpoint HTTP, URL MCP jauh, aliran OAuth atau perkhidmatan hosted.

## Konfigurasi klien MCP

Gantikan `/absolute/path/to/Security-Audit-MCP-Ver` dengan laluan sebenar folder repositori yang telah di-clone. Bina projek sebelum menyambungkan klien.

### Claude Code

Daftarkan pelayan pada skop pengguna:

```bash
claude mcp add --transport stdio --scope user security-audit-mcp-ver -- node /absolute/path/to/Security-Audit-MCP-Ver/dist/stdio.js
claude mcp list
```

Jalankan `/mcp` dalam Claude Code untuk menyemak sambungan. Untuk konfigurasi bagi projek semasa sahaja, gunakan `--scope project`.

### OpenAI Codex CLI

```bash
codex mcp add security-audit-mcp-ver -- node /absolute/path/to/Security-Audit-MCP-Ver/dist/stdio.js
codex mcp list
```

Codex menyimpan konfigurasi di `~/.codex/config.toml`. Anda juga boleh menetapkannya secara manual:

```toml
[mcp_servers.security-audit-mcp-ver]
command = "node"
args = ["/absolute/path/to/Security-Audit-MCP-Ver/dist/stdio.js"]
```

### Cursor

Cipta fail `.cursor/mcp.json` dalam projek, atau gunakan konfigurasi MCP global Cursor:

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

Bagi klien yang menggunakan format konfigurasi MCP VS Code, cipta fail `.vscode/mcp.json`:

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

Format konfigurasi mungkin berbeza mengikut klien. Semak dokumentasi MCP rasmi klien sekiranya skemanya berubah.

## Token GitHub pilihan

Repositori awam boleh dibaca tanpa token, tertakluk pada had API GitHub tanpa pengesahan. Jika perlu, tetapkan `GITHUB_TOKEN` dalam persekitaran pelayan pada konfigurasi klien MCP. Gunakan token fine-grained yang dihadkan kepada repositori yang diperlukan, dengan kebenaran **Contents: read-only** dan **Metadata: read-only**. Jangan sekali-kali commit token atau meletakkannya dalam argumen tool.

Contoh konfigurasi klien yang menyokong environment variable:

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

Utamakan secret manager sistem operasi atau mekanisme environment variable selamat milik klien berbanding menyimpan token dalam fail projek yang dikongsi.

## Fungsi pelayan

- Membaca metadata repositori GitHub, tree terhad dan fail teks.
- Menyediakan laporan reconnaissance dan coverage ledger kanonik.
- Merancang hunting wave terhad serta mengesahkan hasil yang dibekalkan oleh caller.
- Mengesahkan dapatan, struktur bukti dan fingerprint unik.
- Menyemak rekod reviewer yang dibekalkan secara berasingan.
- Menjana laporan audit JSON dan Markdown.

## Model keselamatan dan batasan

- Akses GitHub adalah read-only.
- Pelayan tidak meng-clone atau melaksanakan kod repositori sasaran.
- Ia tidak menguji endpoint produksi atau infrastruktur pihak ketiga.
- Padanan heuristik hanyalah petunjuk calon, bukannya bukti kerentanan.
- Ref, julat baris, hasil worker dan state orkestrasi yang dibekalkan caller tidak disahkan secara kriptografi.
- Gate aliran kerja menyemak konsistensi rekod; ia tidak membuktikan bahawa kerja bebas benar-benar dilakukan.
- Pelayan tidak melancarkan agent, menjalankan background job, menyimpan queue atau mengesahkan bukti secara bebas.
- Laporan kekal incomplete sehingga gate coverage dan verification yang diperlukan diluluskan.

Had sumber penting termasuk timeout GitHub API 15 saat, had badan respons 5 MB, maksimum 500 entri tree, had fail individu 300 KB dan 100,000 aksara teks sumber bagi setiap operasi semakan. Input yang dipotong atau ditolak tidak boleh dianggap telah disemak sepenuhnya.

## Pembangunan dan sumbangan

```bash
npm ci
npm run typecheck
npm test
npm run build
```

Rujuk [CONTRIBUTING.md](./CONTRIBUTING.md), [SECURITY.md](./SECURITY.md), [CHANGELOG.md](./CHANGELOG.md) dan [RELEASE_CHECKLIST.md](./RELEASE_CHECKLIST.md).

## Lesen

Kod projek: **GNU Affero General Public License v3.0 atau lebih baharu**. Rujuk [LICENSE](./LICENSE).

Bahan upstream pihak ketiga: rujuk [ATTRIBUTIONS.md](./ATTRIBUTIONS.md) dan notis asal yang dikekalkan di `vendor/cloudflare-security-audit-skill/`.
