# Rencana Integrasi: LLM Agentic Assessor (OWASP Top 10 + WSTG)

> Status: **rencana tersimpan, belum diimplementasi.**
> Dokumen ini menyimpan hasil analisis dan diskusi desain untuk pengembangan
> tahap berikutnya dari BankSiber: menggandeng LLM lokal sebagai *agentic
> tester* yang menguji lab mengikuti metodologi OWASP.

## 1. Keputusan desain (disepakati)

| Topik | Keputusan |
|---|---|
| Peran LLM | **Agentic tester** — LLM membaca hasil enumerasi, menyusun rencana uji dari katalog WSTG, mengeksekusi lewat tool-calls, menilai bukti, dan menulis laporan |
| Tempat LLM | **Lokal** (Ollama / LM Studio, antarmuka OpenAI-compatible) — jalan offline, data tidak keluar mesin |
| Cakupan metodologi | **OWASP Top 10 (2021) + OWASP WSTG** (test case WSTG-ATHN, WSTG-INPV, dst.) |
| Guardrail | **Tetap loopback-only ketat** — semua HTTP LLM melewati `LabClient`; LLM tidak punya akses jaringan langsung |

## 2. Arsitektur yang diusulkan

Paket baru `src/securebank_lab/agentic/`, terpisah dari `pentest/` yang ada:

```
src/securebank_lab/agentic/
├── models.py        TestPlan, TestStep, Observation, AgentFinding
│                    (reuse Status/Outcome dari pentest.models)
├── knowledge.py     Katalog test case OWASP WSTG → Top 10
│                    (WSTG-INPV-02, WSTG-ATHN-02, ...)
├── llm.py           Klien chat OpenAI-compatible
│                    (default http://127.0.0.1:11434/v1 = Ollama)
├── actions.py       Tool-call surface yang BOLEH dipakai LLM
├── planner.py       Enumerasi → LLM menyusun TestPlan per kategori WSTG
├── executor.py      Loop agentic: act → observe → reason
│                    (budget langkah & request)
├── judge.py         LLM menilai bukti → vulnerable/not_vulnerable/
│                    inconclusive + kutipan bukti yang diverifikasi
├── report.py        Gabungan hasil agent + probe deterministik
└── cli.py           Entry point baru: securebank-agent
```

## 3. Keputusan desain teknis penting

1. **Prompting JSON, bukan native tool-calling** — model lokal kecil tidak semua
   andal untuk function calling. Agent meminta model mengembalikan JSON:
   `{"action": "request", "method": "GET", "path": "/search", "query": {"q": "..."}}`,
   divalidasi ketat sebelum dieksekusi. Kompatibel dengan model apa pun.
2. **Guardrail tetap di `LabClient`** — LLM tidak pernah menyentuh `urllib`
   langsung. Semua aksi lewat `LabClient` (loopback-check + fingerprint lab
   sudah di konstruktor). Lapisan tambahan:
   - **Allowlist aksi**: `enumerate`, `request` (GET/POST form saja, tanpa
     PUT/DELETE), `login_as`, `finish`.
   - **Path di-escape**: LLM hanya memberi *path relatif*; `//evil.com`, URL
     absolut, dan `..` ditolak sebelum sampai ke client.
   - **Denylist destruktif**: payload transfer/lockout/brute-force ditolak
     (filosofi non-destructive yang sudah ada).
   - **Budget**: `--max-steps` (default ±40), `--max-requests` (default ±60),
     timeout per langkah; semua keputusan LLM dicatat ke log terstruktur.
3. **Knowledge base WSTG** — daftar Python murni (tanpa dependensi baru), tiap
   entri: ID WSTG, kategori Top-10, tujuan, sinyal rentan/aman, contoh payload
   aman. Dikirim ke LLM per kategori agar muat di context model lokal.
4. **Judge terstruktur** — penilaian bukti dipaksa JSON:
   `{"status": "...", "evidence_quote": "...", "wstg_ids": [...], "reasoning": "..."}`.
   Kutipan bukti diverifikasi benar-benar ada di respons HTTP (anti-halusinasi).
   `VULNERABLE` tanpa bukti terverifikasi → dipaksa `INCONCLUSIVE`.
5. **Tanpa dependensi baru** — HTTP ke LLM pakai `urllib` (konsisten dengan gaya
   proyek), validasi JSON manual dengan dataclass; model lokal jalan offline.

## 4. CLI yang direncanakan

```bash
securebank-agent http://127.0.0.1:5000 --mode vulnerable   # agentic penuh
securebank-pentest ... --with-agent                         # hybrid: probe + agent
# opsi: --llm-base-url, --llm-model, --max-steps, --max-requests,
#       --categories INPV,ATHN
```

## 5. Tahapan implementasi

| Fase | Isi | Hasil uji |
|---|---|---|
| 1 | `models.py`, `knowledge.py` (katalog WSTG), `llm.py` | Unit test katalog + klien LLM (mock) |
| 2 | `actions.py` + guardrail, `executor.py`, `judge.py` dengan **fake LLM scripted** | Test kontrak: LLM "jahat" (`path="//evil.com"`, aksi DELETE, payload transfer) semuanya ditolak |
| 3 | `planner.py`, `report.py` gabungan, CLI | Loop end-to-end: vulnerable → temuan terkonfirmasi; secure → bersih |
| 4 | Integrasi CI, `docs/AGENTIC.md`, update `METHODOLOGY.md`, `test_source_contract.py` | Gate lulus: pytest, ruff, mypy strict |

## 6. Riset model LLM uncensored di Ollama (hasil cek ollama.com, Nov 2026)

Kebutuhan: patuh format JSON, kuat coding/payload, dukungan tools sebagai bonus.
Karena desain pakai JSON prompting (bukan native function calling), semua model
di bawah aman dipakai.

| Model | Ukuran | VRAM | Tools | Catatan |
|---|---|---|---|---|
| `orcarouter/OrcaSAQ-2-Cyber-27B-Uncensored` ⭐ | 16 GB | 16–24 GB | ✅ | Post-train khusus cybersecurity (vuln analysis, red team). Base Qwen3.8-27B, context 262K, thinking+MTP. Ollama ≥ v0.40.16 |
| `abliterant/qwen3.5-rana:9b` ⭐ default | 6.5 GB | ~8 GB / CPU | ✅ | Abliterated Qwen3.5-9B terdokumentasi baik (KLD 0.0184, hard refusal 0%, kemampuan nyaris tak turun). Tools+thinking+vision |
| `eriktonon/qwen3-coder-uncensored:30b-a3b` | 19 GB | ~21 GB | ❌ | MoE 30.5B/3B aktif — tercepat (±272 tok/s decode). Klaim refusal 0%. Tanpa tools |
| `dolphin-mistral` (fallback) | ~4.1 GB | CPU | ❌ | Klasik Eric Hartford, terbukti, bagus coding, model lama |
| `dolphin-mixtral:8x7b` (fallback) | ~26 GB | besar | ❌ | Lebih pintar dari dolphin-mistral |

Perintah pull:

```bash
ollama pull orcarouter/OrcaSAQ-2-Cyber-27B-Uncensored   # kualitas terbaik (GPU 16–24 GB)
ollama pull abliterant/qwen3.5-rana:9b                  # default (GPU kecil / CPU)
ollama pull eriktonon/qwen3-coder-uncensored            # tercepat
```

**Saran**: default CLI `--llm-model` = `abliterant/qwen3.5-rana:9b` (jalan di
banyak mesin), user dengan GPU 16–24 GB ganti ke `OrcaSAQ-2-Cyber-27B-Uncensored`.

## 7. Catatan implementasi `llm.py`

- `num_ctx` ≥ 32768 (prompt agent + katalog WSTG panjang).
- Jika model thinking ON (`rano`, Orca): matikan per-request
  (`"think": false`) atau strip blok `olygon`/` Polygon` sebelum parse JSON.
- Timeout + retry dengan pesan error validator (model lokal kadang JSON-nya
  rusak; kirim balik error agar memperbaiki sendiri).

## 8. Risiko yang sudah diantisipasi

| Risiko | Mitigasi |
|---|---|
| Model lokal lemah | JSON mode + retry dengan error validator + kutipan bukti wajib |
| Halusinasi temuan | Verifikasi kutipan + cross-check probe deterministik yang sudah terbukti |
| Context kecil | Katalog dikirim per kategori, bukan sekaligus |
| Model tanpa refusal | Guardrail ada di layer eksekusi (`actions.py`), bukan pada nalar model |

## 9. Prinsip keamanan yang tidak berubah

> Vulnerable mode tetap menolak bind selain loopback; tool hanya menerima target
> loopback yang mengidentifikasi diri sebagai SecureBank Lab; hanya uji sistem
> milik sendiri atau yang ada izin tertulisnya.
