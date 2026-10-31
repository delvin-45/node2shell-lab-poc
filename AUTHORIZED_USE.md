# Authorized use

This repository is a restricted local cyber range for security research,
remediation validation, and education.

Run the reproducer only against the included Docker labs on loopback. The tool
accepts only `127.0.0.1`, `::1`, and `localhost`, requires the exact port from
the selected profile, uses fixed request paths, and never accepts a
caller-supplied command. The RCE proof executes only `/usr/bin/id`; it requires
fresh `uid=` and `gid=` output.

The outbound test path binds an attacker origin on the host. On Docker Desktop
the container reaches it through `host.docker.internal`. Keep that listener
local, do not forward the port, and stop the container when the test ends.

Do not use this material to access, disrupt, or exfiltrate data from a
third-party system; to establish persistence; to evade controls; or to perform
any activity without prior written authorization. A profile entry is a
reproduction recipe, not authorization for another host.

If you are validating a production system, use the vendor advisory and the
fixed release. Do not send the malformed stream outside the included lab.

## Penggunaan berizin

Repositori ini adalah laboratorium siber lokal terbatas untuk riset keamanan,
validasi perbaikan, dan pendidikan.

Jalankan reproducer hanya terhadap lab Docker loopback yang disertakan. Alat
ini hanya menerima `127.0.0.1`, `::1`, dan `localhost`, mewajibkan port yang
sama dengan profil, memakai path tetap, dan tidak menerima perintah dari
pengguna. Bukti RCE hanya menjalankan `/usr/bin/id` dan mewajibkan keluaran
`uid=` serta `gid=` yang baru.

Jangan gunakan materi ini untuk mengakses, mengganggu, atau mengambil data
sistem pihak ketiga; membuat persistensi; menghindari kontrol; atau melakukan
aktivitas apa pun tanpa izin tertulis. Entri profil bukan izin untuk menguji
host lain.
