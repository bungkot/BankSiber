# Analisa: Kesiapan Codebase untuk Agentic Harness (Deterministik)

> Status: **analisa tersimpan, belum diimplementasi.**
> Dokumen ini menyimpan hasil analisa arsitektur untuk lapisan *agentic
> harness* deterministik — agent yang **memilih, menimbang, dan mengeksekusi**
> probe pentest secara adaptif terhadap sandbox lab. Roadmap evolusinya
> (termasuk kemampuan mengembangkan tool/skrip untuk dirinya sendiri) ada di
> `docs/AGENTIC_SELF_DEV_ROADMAP.md`; jalur LLM ada di
> `docs/AGENTIC_PLAN.md`.

## 1. Keputusan desain (disepakati)

| Topik | Keputusan |
|---|---|
| Otak agent | **Deterministik + heuristic** — planner berbasis scoring & state machine; fully testable, tanpa API key, konsisten dengan mypy strict |
| Cakupan | **Probe yang ada saja** (11 probe + 1 tool recon) — tidak ada tool destruktif baru |
| Prioritas | **Agent core dulu** — scoring model, agentic loop, audit trail, CLI, tests; tool baru menyusul |
| Posisi vs `pentest/` | **Additif murni** — modul `pentest/` tidak diubah; agent membungkus `CHECKS` tanpa refactor |
| Posisi vs jalur LLM | Core deterministik = **konstitusi**; reasoner LLM (AGENTIC_PLAN.md) menjadi lapisan di atas harness (roadmap v4) |

## 2. Inventaris — apa yang bisa direuse langsung (tanpa refactor)

| Aset | Status | Peran untuk agent |
|---|---|---|
| `CHECKS` (11 probe) di `pentest/checks.py` | Siap | Tiap `Check` sudah berupa `(Spec, Callable[[Target], Outcome])` — bentuknya persis tool registry; agent cukup membungkus |
| `Spec` + `Outcome` + `Status` di `pentest/models.py` | Siap | Frozen dataclasses — cocok dengan `State` immutabel |
| `LabClient` di `pentest/client.py` | Siap | Guard loopback (`core.netutil.is_loopback`, proteksi DNS-rebinding) di konstruktor — agent mewarisi polisi keamanan otomatis |
| `LabClient.verify_is_lab()` | Siap | Gerbang fingerprint — recon agent wajib memanggilnya dulu; kegagalan = hard abort |
| Pola `run_checks()` (normalisasi error → `INCONCLUSIVE`) | Pola siap | ToolExecutor meniru pola ini |
| Fixture test (`make_server` di thread loopback, `tests/tool/test_pentest.py`) | Siap | Test integrasi agent memakai pola sama (server Flask di port acak) |
| Dispatcher CLI (`cli/main.py`) + `[project.scripts]` | Perlu ditambah | Subcommand `agent` + entry point `securebank-agent` |

## 3. Peta aliran informasi antar-probe (fondasi planner)

```
TANPA SESSI (gratis, jalankan dulu):          BUTUH SESSI (7 probe):
├─ PT-01 login SQLi        (CRITICAL)         ┌─ PT-02 search SQLi   (CRITICAL)
├─ PT-06 security headers  (MEDIUM)           ├─ PT-03 IDOR          (HIGH)
├─ PT-09 /about disclosure (MEDIUM)           ├─ PT-05 reflected XSS (MEDIUM)
└─ PT-04 default creds     (HIGH) ────────────┤─ PT-07 cookie flags   (LOW)
        │                                     ├─ PT-08 error leak    (MEDIUM)
        └── SUCCESS = fakta AUTH_SESSION ────►├─ PT-10 integrity stamp(HIGH)
              (membuka seluruh kolom kanan)   └─ PT-11 SSRF          (HIGH)
```

Sinyal "mode" yang bisa dipakai fingerprint agent:

* **CSRF token kosong** di halaman login → hanya mode vulnerable
  (`LabClient.csrf_token()` mengembalikan `""`).
* **Server banner Werkzeug** di evidence PT-06.

Keduanya gratis dari request yang memang harus dilakukan.

## 4. Temuan kritis

### 4.1 Lockout adalah sumber daya nyata yang wajib di-budget

Mode secure punya proteksi brute-force (`banking/secure.py:23-24`):

* `MAX_FAILED_ATTEMPTS = 5`, `LOCKOUT_SECONDS = 900` (15 menit) per akun.
* `known_lab_passwords()` mengembalikan 2 password untuk `jsmith`
  (`demo1234` untuk mode vulnerable, `Cx7!mango-orbit` untuk mode secure).

Tool statis saat ini *aman kebetulan*: tiap probe login
`fail(satu kali) → sukses → counter reset ke 0`, jadi hanya ada 1 attempt
menunggu di antara probe. Agent yang justru didesain mencoba hal baru saat
gagal berisiko membakar counter:

> Skenario bahaya: planner yang melakukan "credential discovery" dengan
> dictionary kecil membuat 5+ login gagal beruntun → akun `jsmith` terkunci
> 15 menit → seluruh 7 probe terautentikasi menjadi `INCONCLUSIVE` →
> laporan agent cacat.

Aturan keras yang harus hidup di harness (bukan heuristik planner):

1. **Login-attempt budget per akun: maksimal 4 gagal** (selalu sisakan 1),
   dihitung kumulatif per run, dilacak di `State`.
2. Setiap attempt gagal harus diikuti sukses atau berhenti — tanpa retry cepat.
3. Biaya tool bukan hanya jumlah HTTP request, tapi juga **sumber daya yang
   tidak bisa diperbarui** (lockout counter).

### 4.2 Kontrak sumber memaksa pekerjaan tersembunyi

`tests/test_source_contract.py` punya tiga pancing yang fail saat package
`agent/` ditambahkan:

1. `_PACKAGES` (baris 101): `assert package in _PACKAGES` → AssertionError
   untuk package yang tidak terdaftar. `agent` wajib masuk tuple ini.
2. `test_bank_never_imports_tool_packages`: `tool_packages =
   {"pentest", "research", "cli"}` → `agent` wajib ditambahkan, sehingga
   dependency-direction otomatis berlaku juga untuk agent.
3. `test_every_public_callable_is_tested_or_excluded`: semua callable publik
   baru di `agent/` harus direferensikan di test atau masuk `_EXCLUDED`
   dengan alasan terdokumentasi. Test agent bukan opsional — ia dipaksa CI.

### 4.3 Model biaya request (dasar field `cost`)

Perkiraan jumlah request HTTP per jalur (dari kode):

| Probe | Request | Catatan |
|---|---|---|
| `verify_is_lab` (recon) | 1 | GET /login |
| PT-06, PT-09 | 1 masing-masing | Tanpa sessi |
| PT-01 | 4 | 2× login; tiap login = GET csrf + POST |
| PT-04 | 2 | 1 login |
| 7 probe terautentikasi | 3–6 masing-masing | login (2–4, tergantung password) + 1–2 request probe |
| **Total run statis** | **≈ 35–45** | |

Implikasi: `--max-requests 200` longgar; yang benar-benar membatasi adalah
budget lockout (4.1). Login berulang antar probe (~2–4 req × 7 probe) buang
~20 request — untuk v1 biarkan (probe tidak disentuh); optimasi session-cache
jadi backlog v2.

## 5. Temuan minor yang berdampak desain

* `pentest/report.py` hardcode nama tool `"securebank-pentest"` dan
  disclaimer → agent perlu renderer sendiri dengan bagian **Decision trail**
  (audit trail) sebagai pembeda dari laporan statis.
* **Tie-breaking determinisme**: skor sama dipecah dengan `tool id` — run
  agent harus reprodusibel (test & audit).
* `Target` frozen: agent tidak bisa menyuntik password hasil discovery ke
  `Target` yang sama — harus membuat `Target` baru saat kredensial baru
  ditemukan (cocok dengan model fakta append-only).
* Entry point baru di `pyproject.toml` butuh `pip install -e .` ulang.
* PT-11 (SSRF) satu-satunya tool yang memicu permintaan *server-side* —
  dicatat di deskripsi ToolSpec, tetap non-destruktif.

## 6. Arsitektur v1

```
src/securebank_lab/agent/
├── models.py   Fact, State, DecisionRecord (append-only, immutabel)
├── tools.py    ToolSpec: id, phase, preconditions, produces, cost,
│               base_severity; registry = 11 probe + recon_fingerprint
├── planner.py  score = severity × applicability × information_gain ÷ cost
│               + aturan branching sebagai DATA (bukan if tersebar)
├── loop.py     PLAN → ACT → OBSERVE → REPLAN; max_steps, max_requests
├── report.py   renderer agent + bagian Decision trail
└── cli.py      securebank-agent <target> [--explain] [--max-steps] ...
```

**Inti harness: agent tidak pernah memanggil HTTP langsung.** Ia hanya boleh
*meminta* harness menjalankan tool. Semua polisi (budget, loopback,
non-destruktif) hidup di harness — reasoning yang salah tetap aman
(*fail-safe by construction*).

Aturan branching v1 (didefinisikan sebagai data):

| ID | Kondisi (fakta di State) | Efek prioritas |
|---|---|---|
| BR-01 | `AUTH_SESSION` belum ada | PT-04 + PT-01 di atas probe terautentikasi |
| BR-02 | `BLOCKED_AUTH` (semua password gagal) | Skip 7 probe terautentikasi; minta `--password`; catat di laporan |
| BR-03 | Temuan `VULNERABLE` kategori Injection | Sibling injection dipertahankan tinggi; sebaliknya turun |
| BR-04 | `INCONCLUSIVE` + retry tersedia | Jalur alternatif; setelah retry gagal → tool dicoret dengan alasan tercatat |
| BR-05 | Lockout budget habis (≥4 gagal) | Semua tool yang login dicoret permanen per run |

## 7. Risk register

| # | Risiko | Dampak | Mitigasi |
|---|---|---|---|
| R1 | Lockout jsmith (5 gagal) | 7 probe INCONCLUSIVE, laporan cacat | Budget lockout keras di harness (§4.1) |
| R2 | Lupa update `_PACKAGES` / `tool_packages` | CI fail atau dependency-rule tak berlaku | Checklist integrasi (§8 langkah 7) |
| R3 | Planner loop (tool gagal dicoba terus) | Budget habis tanpa hasil | `max_steps` + fakta `BLOCKED_*` coret tool per run |
| R4 | Determinisme pecah (dict ordering) | Test flaky, audit tak reprodusibel | Sort deterministik, State append-only |
| R5 | INCONCLUSIVE ditafsirkan VULNERABLE | Temuan palsu | Aturan `checks.py` dipertahankan: hanya positive evidence |

## 8. Checklist integrasi v1 (urutan kerja)

1. `agent/models.py` — `Fact`, `State`, `DecisionRecord` (+ entri `_EXCLUDED` untuk dataclass kontainer)
2. `agent/tools.py` — bungkus `CHECKS` jadi `ToolSpec` + tool recon `verify_is_lab`
3. `agent/planner.py` — scoring + 5 aturan branching + budget lockout (§4.1)
4. `agent/loop.py` — PLAN→ACT→OBSERVE→REPLAN dengan `max_steps`/`max_requests`
5. `agent/report.py` — renderer + Decision trail
6. `agent/cli.py` + `cli/main.py` subcommand `agent` + `pyproject.toml` script `securebank-agent`
7. `tests/test_source_contract.py` — tambah `agent` ke `_PACKAGES` dan `tool_packages` (§4.2)
8. `tests/agent/` — planner, loop (client palsu, offline), integrasi kedua mode, CLI
9. Verifikasi manual: **11 temuan di mode vulnerable / 0 di secure** + urutan eksekusi **berbeda** dari run statis (bukti agent benar-benar memilih)

## 9. Prinsip keamanan yang tidak berubah

> Vulnerable mode tetap menolak bind selain loopback; tool hanya menerima
> target loopback yang mengidentifikasi diri sebagai SecureBank Lab; hanya
> uji sistem milik sendiri atau yang ada izin tertulisnya.
