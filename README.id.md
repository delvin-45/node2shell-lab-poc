# Node2Shell Lab

**Lab riset loopback untuk CVE-2026-111497, out-of-bounds write pada decoder
Brotli yang dibundel Node.js.** Repo ini berisi tiga aplikasi kecil, PoC Python
tanpa dependensi eksternal, dan log mentah dari setiap eksekusi.

Dua profil exact-binary menghasilkan output `id` baru di 2/2 container segar.
Profil ketiga membuktikan denial of service di 2/2 container. Klaim RCE hanya
berlaku untuk profil yang tercatat, bukan untuk semua deployment Node.js.

[English](README.md)

## Lab

| Lab | Runtime | Status | Bukti |
| --- | --- | --- | --- |
| [WordPress-style CMS](lab/wp-cms/) | Node.js v24.22.0 | RCE 2/2, DoS 2/2 | [RCE](docs/evidence/wp-cms-rce-run1.txt) · [DoS](docs/evidence/wp-cms-dos-run1.txt) |
| [Link Unfurl API](lab/unfurl-api/) | Node.js v24.22.0, undici 8.12.3 | DoS 2/2, RCE tidak diklaim | [DoS](docs/evidence/unfurl-api-dos-run1.txt) |
| [Reference Express](lab/reference-express/) | Node.js v24.22.0 | RCE 2/2, DoS 2/2 | [RCE](docs/evidence/ref-express-rce-run1.txt) · [DoS](docs/evidence/ref-express-dos-run1.txt) |

Kontrol patched memakai Node.js v24.22.1 dan source yang sama. Ketiganya gagal
tertutup dengan `ERR__ERROR_FORMAT_BLOCK_SWITCH`; `/health` tetap `PONG`.
Lihat [matriks klaim](docs/evidence/MATRIX.md) dan
[checksum](docs/evidence/SHA256SUMS).

## Akar masalah

Decoder Brotli memilih tipe block melalui sebuah switch. Stream cacat dapat
membuat cabang switch menulis melewati batas buffer. Write itu merusak state
decoder dan heap di sekitarnya. Dampak pertama biasanya crash; pada layout
tertentu, state yang rusak dapat memengaruhi control flow.

Permintaan dengan `Content-Encoding: br` mengalami inflasi sebelum JSON
divalidasi. Response yang di-fetch juga masuk ke decoder saat body dibaca
sampai habis. Karena itu, membatasi ukuran body saja bukan perbaikan decoder.

Trigger tidak boleh berubah:

```text
sha256=b7a6508eb39ef57ae5e3fdf9aa85540071a06eff5d5b5a2d359fc8e1768e4df4
```

## Jalankan

Tiga perintah untuk uji DoS CMS yang deterministik:

```bash
make lab-a
make poc-a
make clean
```

Hasil yang diharapkan berakhir dengan:

```text
PASS: DoS verified through the declared network interface
postcondition=service unavailable
healthchecks_failed=4/4
```

Untuk RCE exact-profile:

```bash
make lab-ref
make poc-ref
make clean
```

RCE memakai supervisor untuk mendapatkan proses baru setelah tebakan ASLR
gagal. Keberhasilan bersifat probabilistik. Kegagalan tidak membuktikan target
aman.

## Versi

| Lini | Terdampak | Diperbaiki | Diuji ulang di sini |
| --- | --- | --- | --- |
| 22.x | 22.23.3 dan sebelumnya | 22.23.4 | Tidak |
| 24.x | 24.22.0 dan sebelumnya | 24.22.1 | Ya |
| 26.x | 26.12.0 dan sebelumnya | 26.12.1 | Tidak |

Image yang diuji:
`node@sha256:925de64a85319052d6971ae81ef2417da956e8a3a2c4a0fac732327970f017f5`
(affected) dan
`node@sha256:6449e19d8184d84062525b6a7524def03146c2cb04a7f08b076680d0e8e4240a`
(patched).

## Mitigasi

- Upgrade ke Node.js 24.22.1, 22.23.4, atau 26.12.1 sesuai lini.
- Jika Brotli dibangun terpisah, pakai rilis 1.2.1 atau lebih baru.
- Turunkan batas body dan tolak encoding yang tidak dibutuhkan sebagai lapisan
  tambahan, bukan pengganti patch.
- Jalankan worker dengan resource limit dan supervisor.
- Batasi URL outbound dan ukuran response.
- Jangan menganggap crash sebagai satu-satunya dampak.

## Batasan

- RCE hanya untuk profil exact-binary: image, package lock, satu libuv worker,
  file descriptor 19, dan supervisor yang tercatat.
- Posisi ASLR ditebak; 2/2 PASS bukan jaminan untuk mesin lain.
- Unfurl API hanya diklaim DoS.
- Hanya v24.22.0 dan v24.22.1 yang diuji ulang.
- `scan.py` hanya triage pasif, bukan bukti exploitability.
- Bukti dibuat di Docker Desktop Windows dengan container Linux `amd64`.

## Dokumentasi

- [README utama](README.md)
- [Arsitektur](docs/architecture.md)
- [Walkthrough exploit](docs/exploit-walkthrough.md)
- [Troubleshooting](docs/troubleshooting.md)
- [FAQ](docs/faq.md)
- [Landing page](docs/index.html)
- [Demo terminal](docs/demo/)
- [Screenshot asli](docs/media/)

## Lisensi

MIT, Copyright (c) 2026 Delvin Alvazri. Gunakan hanya pada sistem milik Anda
atau yang Anda punya izin tertulis untuk mengujinya. Baca
[AUTHORIZED_USE.md](AUTHORIZED_USE.md).
