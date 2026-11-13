# Roadmap: Agentic yang Mengembangkan Tool/Skrip untuk Dirinya Sendiri

> Status: **rencana tersimpan, belum diimplementasi.**
> Roadmap evolusi dari agent core deterministik (v1) menuju agent yang
> mampu *mengembangkan diri*: meningkatkan tool miliknya, menyintesis
> payload/skrip pentest baru, dan (di tahap akhir) menulis draf exploit
> melalui gerbang review manusia. Fondasi arsitekturnya dianalisa di
> `docs/AGENTIC_HARNESS_ANALYSIS.md`; jalur reasoner LLM ada di
> `docs/AGENTIC_PLAN.md` (menjadi v4 di roadmap ini).

## 0. Prinsip tunggal: yang berkembang adalah DATA, bukan KODE

Hasil "kreativitas" agent disiplinkan lewat pemisahan tegas:

```
src/securebank_lab/agent/     # KODE — teruji, tidak pernah berubah sendiri
├── (core v1: models, tools, planner, loop, report, cli)
├── forge.py                  # validator & loader tool generasi (v3)
├── sandbox.py                # eksekusi tool generasi: budget + polisi (v3)
└── learning.py               # statistik hasil → bobot & pengetahuan (v2)

data/agent/                   # HASIL GENERASI — data, divalidasi, bukan kode
├── knowledge.json            # v2: statistik lintas-run, payload sukses, sinyal
└── tools/                    # v3: tool generasi (DSL JSON, bukan .py mentah)
    └── pt12_sqli_variant.json
```

Kenapa struktur ini penting (bukan kebetulan):

1. **Kontrak sumber memindai `src/`** — setiap callable publik di `src/`
   wajib teruji (`test_source_contract.py`). Kalau agent menulis `.py` ke
   `src/`, kontrak bocor. Dengan loader + DSL, yang diuji hanya *loader &
   sandbox* (kode tetap); hasil generasi = data yang divalidasi.
2. **Invariant keamanan terjaga struktural** — tool generasi tidak membangun
   HTTP sendiri; sandbox hanya memberi satu handle `LabClient`
   (loopback-only diwariskan) dan budget. Tool generasi *secara fisik tidak
   punya cara* keluar dari loopback.
3. **Sifat tool generasi berasal dari template terbukti** — mutasi payload
   dari grammar yang sudah non-destruktif, bukan karangan bebas.

## 1. Tangga kemampuan (levels of self-development)

| Level | Yang ditingkatkan | Contoh konkret di proyek ini | Risiko |
|---|---|---|---|
| **L1 — Tuning** | Bobot scoring dari statistik hasil | PT-05 sering `INCONCLUSIVE` → bobot turun; PT-04 sukses selalu → urutan naik | Rendah |
| **L2 — Pengetahuan** | Memori lintas-run | "CSRF kosong ⇒ mode vuln ⇒ PT-02 prioritas 1" tersimpan sebagai fakta yang dipakai run berikutnya | Rendah |
| **L3 — Sintesis payload/script** | Agent menulis varian probe baru | Dari `_SEARCH_SQLI_PAYLOAD` terbukti, mutasi: `ORDER BY`, kutip ganda, encoding — diuji aman dulu sebelum dipakai | Sedang |
| **L4 — Penulisan exploit** | Agent menyusun draf alur serangan multi-langkah baru | Rantai: kredensial default → IDOR → ekstraksi; hasilnya **draf untuk review manusia**, bukan eksekusi langsung | Tinggi |

L1–L3 deterministik dan teruji penuh. L4 memerlukan reasoner LLM sebagai
*penulis draf* — jalurnya sudah dianalisa di `AGENTIC_PLAN.md`.

## 2. Roadmap per fase

### v1 — Agent core (fondasi / konstitusi)

* Isi: `state`, `tools`, `planner`, `loop`, `report`, CLI — sesuai checklist
  §8 `AGENTIC_HARNESS_ANALYSIS.md`.
* Penerimaan: 11 temuan di mode vulnerable, 0 di secure, urutan eksekusi
  berbeda dari run statis, audit trail lengkap, budget lockout keras.
* Kenapa harus selesai dulu: harness adalah **konstitusi** — executor,
  budget, dan audit trail yang solid membuat L1–L3 hanya menambah otak dan
  tangan tanpa menyentuh polisi.

### v2 — Learning: L1 + L2 (`agent/learning.py`, `data/agent/knowledge.json`)

* **Statistik per tool**: jumlah run, hit/miss/inconclusive, biaya aktual
  (request terukur), korelasi sinyal (mis. "CSRF kosong → PT-02 hit 100%").
* **Pembaruan bobot**: score multiplier per tool dari data, dibatasi
  (clamped, mis. 0.5–2.0) supaya tidak pernah melumpuhkan probe.
* **Persistensi**: `knowledge.json` append/merge dengan timestamp + versi
  skema; dibaca saat planner mulai, ditulis setelah run (opsi
  `--no-learn` untuk run tanpa efek samping pengetahuan).
* **Reprodusibilitas**: run dengan pengetahuan = run baru; hasil tetap
  deterministik *terhadap* pengetahuan yang sama (sort + tie-break).
* Penerimaan: dua run beruntun — run kedua mencapai 11 temuan dengan
  **biaya request lebih rendah** atau sama; mode secure tetap 0 temuan.

### v3 — Tool Forge: L3 (`agent/forge.py`, `agent/sandbox.py`, `data/agent/tools/`)

Pipeline: **OBSERVE → THINK (menimbang gain vs cost) → FORGE → VALIDASI →
EKSEKUSI terbatas → PROMOSI/BUANG.**

Contoh pemicu: "PT-05 vulnerable tetapi payload tak ter-refleks; XSS mungkin
di konteks refleksi lain" → gain tool baru layak vs cost.

DSL tool generasi (sketsa field JSON):

```json
{
  "id": "gen-0001",
  "provenance": "generated",
  "derived_from": "PT-05",
  "template": "reflected_marker_probe",
  "phase": "INJECTION",
  "preconditions": ["AUTH_SESSION"],
  "budget": {"max_requests": 5},
  "payload": {"path": "/search", "query": {"q": "<var>"}},
  "grammar": "xss_marker_v1",
  "verdict": {"vulnerable_when": "marker_reflected", "not_vulnerable_when": "marker_escaped"}
}
```

**Validation gates** (semua wajib lolos sebelum eksekusi):

| Gate | Aturan |
|---|---|
| G1 Statis | Pindai DSL: tolak endpoint di luar allowlist, method di luar GET/POST-form, payload di luar grammar yang didefinisikan di `forge.py` |
| G2 Biaya | `max_requests` tool generasi kecil (default 5), dihitung ke budget global run |
| G3 Sifat | Hanya mutasi dari template terbukti non-destruktif; tidak ada aksi state-changing (aturan `NOT_COVERED` tetap berlaku) |
| G4 Audit | Setiap eksekusi tool generasi tercatat penuh di Decision trail (dibuat kapan, dari template apa, hasilnya) |

**Promotion gate** (mencegah menumpuk tool sampah):

* Tool generasi bersifat **ephemeral** — hanya hidup di run yang membuatnya.
* Reproducible N kali lintas run → dipromosikan ke tool permanen di
  `knowledge.json`; tidak → dibuang otomatis.
* Tool yang menghasilkan temuan pada mode secure (false positive) = alarm
  dan langsung dibuang.

### v4 — LLM author + gerbang manusia: L4

* Menyatukan rencana `AGENTIC_PLAN.md`: reasoner LLM lokal (Ollama,
  JSON-prompting, judge terstruktur dengan verifikasi kutipan) sebagai
  lapisan *di atas* harness deterministik — bukan penggantinya.
* Peran LLM di tahap ini: **menulis draf** tool/rantai serangan baru
  (penulis), yang lolos G1–G4 lalu masuk **antrean review manusia**.
* Eksekusi exploit state-changing (mis. membuktikan Insecure Design) tetap
  diluar agent: hasil review diubah menjadi *test case* di `tests/lab/`
  atau dijalankan manual di sandbox terisolasi — pola yang sama dengan
  CI-gate `--fail-on-vulnerable` yang sudah ada.
* Keamanan: guardrail tetap di layer eksekusi (`actions.py` → `LabClient`),
  bukan pada nalar model (prinsip §9 `AGENTIC_PLAN.md`).

## 3. Metrik "lebih cerdas" (syarat sebelum self-improvement)

Self-improvement tanpa metrik adalah ilusi. Repo ini memberi *ground truth*
gratis:

| Metrik | Sumber kebenaran | Arti |
|---|---|---|
| **Recall** | Mode vulnerable → harus 11/11 | Seberapa banyak flaw yang ditemukan |
| **Precision** | Mode secure → harus 0 temuan | Temuan di secure = false positive = alarm |
| **Cost** | Jumlah request + waktu per run | Efisiensi; harus turun seiring v2+ |

Evolusi agent diukur: `recall naik, precision dipertahankan, cost turun` —
dievaluasi ulang tiap iterasi seperti regression suite. Tool generasi yang
menaikkan recall tanpa false positive = peningkatan cerdas yang terukur.

## 4. Ringkasan fase

| Fase | Deliverable | Gate penerimaan |
|---|---|---|
| v1 | Agent core deterministik + harness | 11/0, urutan adaptif, audit trail, budget lockout |
| v2 | `learning.py` + `knowledge.json` | Run kedua lebih murah, tetap 11/0 |
| v3 | `forge.py` + `sandbox.py` + DSL + promotion gate | Tool generasi lolos G1–G4; recall naik tanpa false positive; tidak ada tool sampah menumpuk |
| v4 | LLM author (AGENTIC_PLAN.md) + human review gate | Draf exploit hanya dijalankan setelah review; guardrail layer eksekusi terbukti lewat test kontrak |

## 5. Prinsip keamanan yang tidak berubah

> Vulnerable mode tetap menolak bind selain loopback; tool hanya menerima
> target loopback yang mengidentifikasi diri sebagai SecureBank Lab; hanya
> uji sistem milik sendiri atau yang ada izin tertulisnya. Tool yang
> mengubah data tidak pernah menjadi bagian dari agent — hasilnya selalu
> berupa test case yang direview manusia.
