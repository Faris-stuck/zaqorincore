# UU PDP Compliance Rules

Kumpulan Sigma rules untuk deteksi kepatuhan terhadap
**Undang-Undang No. 27 Tahun 2022 tentang Pelindungan Data Pribadi
(UU PDP)** beserta regulasi sektoral terkait
(POJK No. 13/POJK.02/2020 dan Peraturan Bank Indonesia).

## Pemetaan Pasal → Rule

| Pasal / Regulasi | Topik                                            | File Rule                                  | Level    |
|------------------|--------------------------------------------------|--------------------------------------------|----------|
| Pasal 35         | Akses data pribadi tanpa otorisasi               | `pasal35_akses_tidak_sah.yml`              | critical |
| Pasal 36         | Pengumpulan data tanpa persetujuan               | `pasal36_pengumpulan_tanpa_konsen.yml`     | high     |
| Pasal 37         | Pemrosesan di luar tujuan                       | `pasal37_pemrosesan_melanggar.yml`         | high     |
| Pasal 38         | Ketidakakuratan data (update massal identitas)  | `pasal38_ketidakakuratan_data.yml`         | high     |
| Pasal 39         | Permintaan hapus data tidak ditindaklanjuti     | `pasal39_penghapusan_tidak_dilakukan.yml`  | critical |
| Pasal 40         | Kegagalan perlindungan data pribadi             | `pasal40_kegagalan_keamanan.yml`           | critical |
| Pasal 41         | Deteksi dini pelanggaran (ekspor di luar jam)   | `pasal41_notifikasi_breach.yml`            | critical |
| Pasal 46         | Transfer lintas batas yurisdiksi                 | `pasal46_transfer_lintas_batas.yml`        | critical |
| Pasal 48         | Operasi admin di luar change window             | `pasal48_izin_pengontrol.yml`              | high     |
| POJK 13/2020     | Pembagian data nasabah tanpa kontrak            | `pojk13_data_nasabah_eksternal.yml`        | high     |
| Regulasi BI      | Data keuangan konsumen keluar perimeter         | `bi_pdp_data_konsumen_eksternal.yml`       | critical |
| Pasal 25-26      | Perlindungan data anak                          | `uu_pdp_data_anak_dilindungi.yml`          | critical |
| Pasal 16         | Hak hapus data (right to be forgotten)          | `uu_pdp_kuasa_data_hapus.yml`              | critical |

## Skema

Setiap file mengikuti schema Sigma pada `sigma.py` loader dan
menambahkan metadata tambahan:

- `title` — judul rule
- `id` — identifier unik lowercase
- `description` — deskripsi dalam Bahasa Indonesia
- `author`, `date`, `modified` — metadata authorship
- `references` — daftar URL rujukan regulasi
- `tags` — termasuk taksonomi `compliance.uu_pdp`
- `level` — `low` | `medium` | `high` | `critical`
- `detection` — blok deteksi Sigma (wajib)
- `cooldown_sec`, `dedup_key` — tuning engine

## Verifikasi

```python
import yaml, glob
files = sorted(glob.glob('rules/builtin/uu_pdp/*.yml'))
for f in files:
    with open(f) as fh:
        data = yaml.safe_load(fh)
    assert 'detection' in data
print(f"All {len(files)} rules parse OK")
```
