"""
compare.py — PQ-VPN vs Klasik VPN Karşılaştırma Raporu
────────────────────────────────────────────────────────
Her iki testi tamamladıktan sonra çalıştırın:
  python3 compare.py

Okuyacağı CSV dosyaları:
  server_cpu_log.csv         ← PQ-VPN (Kyber512) testi
  classic_server_cpu_log.csv ← Klasik VPN (RSA-2048) testi
"""

import os, csv, statistics, time

BASE = os.path.dirname(__file__)

def load_csv(filename: str) -> list[float]:
    path = os.path.join(BASE, filename)
    if not os.path.exists(path):
        return []
    data = []
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            try: data.append(float(row["cpu_percent"]))
            except: pass
    return data


def stats(data: list[float]) -> dict:
    if not data:
        return {"avg": 0, "max": 0, "min": 0, "median": 0, "n": 0}
    return {
        "avg"   : round(statistics.mean(data),   2),
        "max"   : round(max(data),               2),
        "min"   : round(min(data),               2),
        "median": round(statistics.median(data), 2),
        "n"     : len(data),
    }


def bar(value: float, max_val: float = 100, width: int = 30) -> str:
    filled = int((value / max_val) * width)
    return "█" * filled + "░" * (width - filled)


if __name__ == "__main__":
    pq  = stats(load_csv("server_cpu_log.csv"))
    cls = stats(load_csv("classic_server_cpu_log.csv"))

    sep  = "═" * 70
    sep2 = "─" * 70

    lines = []
    lines.append(sep)
    lines.append("  PQ-VPN vs KLASİK VPN — KARŞILAŞTIRMA RAPORU")
    lines.append(f"  Tarih: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(sep)

    # ── 1. El Sıkışma Algoritması Karşılaştırması ─────────────────────────────
    lines.append("\n  [1] EL SIKIŞMA (HANDSHAKE) ALGORİTMASI FARKI")
    lines.append(sep2)
    lines.append(f"  {'Özellik':<35} {'Klasik (RSA-2048)':>16} {'PQ-VPN (Kyber512)':>17}")
    lines.append(sep2)
    rows = [
        ("Algoritma türü",              "Klasik (RSA)",   "Post-Kuantum"),
        ("Matematiksel problem",         "Büyük asal × ", "Module LWE"),
        ("Kuantum saldırısına dayanıklı","❌ HAYIR",      "✅ EVET"),
        ("Public Key boyutu",            "294 byte",      "800 byte"),
        ("Private Key boyutu",           "1218 byte",     "1632 byte"),
        ("Ciphertext/şifreli veri",      "256 byte",      "768 byte"),
        ("Tahmini keygen süresi",        "~50-200 ms",    "~1-3 ms"),
        ("Tahmini encrypt/encaps",       "~1-5 ms",       "~1-3 ms"),
    ]
    for r in rows:
        lines.append(f"  {r[0]:<35} {r[1]:>16} {r[2]:>17}")
    lines.append(sep2)
    lines.append("  ► Shor algoritması RSA-2048'i kırar → Klasik VPN SAVUNMASIZ!")
    lines.append("  ► Kyber512, MLWE problemine dayanır → Kuantum dirençli!")

    # ── 2. CPU Yük Karşılaştırması ────────────────────────────────────────────
    lines.append(f"\n\n  [2] CPU YÜK KARŞILAŞTIRMASI (Veri Transfer Sırasında)")
    lines.append(sep2)

    max_cpu = max(pq["avg"], cls["avg"], 1)

    if pq["n"] > 0 and cls["n"] > 0:
        lines.append(f"\n  PQ-VPN  (Kyber512) — Ort: {pq['avg']:5.1f}%  "
                     f"Maks: {pq['max']:5.1f}%  Min: {pq['min']:5.1f}%")
        lines.append(f"  [{bar(pq['avg'], max(pq['max'],cls['max'],1))}] {pq['avg']:.1f}%")
        lines.append("")
        lines.append(f"  Klasik  (RSA-2048) — Ort: {cls['avg']:5.1f}%  "
                     f"Maks: {cls['max']:5.1f}%  Min: {cls['min']:5.1f}%")
        lines.append(f"  [{bar(cls['avg'], max(pq['max'],cls['max'],1))}] {cls['avg']:.1f}%")

        diff = pq["avg"] - cls["avg"]
        lines.append(f"\n  ► PQ-VPN'in ek CPU maliyeti: {diff:+.1f}%")
        if diff > 0:
            lines.append(f"  ► Bu fark Kyber512'nin büyük anahtarlarından kaynaklanır.")
            lines.append(f"  ► Ancak bu maliyet kuantum güvenliğinin 'sigorta primi'dir.")
        else:
            lines.append(f"  ► PQ-VPN, Klasik VPN'e göre DAHA AZ CPU kullandı!")
            lines.append(f"  ► AES-GCM veri şifrelemesi her iki tarafta da aynı!")
    else:
        lines.append("\n  ⚠️  CSV log dosyaları bulunamadı!")
        lines.append("  Her iki testi de tamamlayıp Ctrl+C ile durdurun.")
        lines.append("  PQ-VPN  → server_cpu_log.csv")
        lines.append("  Klasik  → classic_server_cpu_log.csv")

    # ── 3. Paket Overhead ─────────────────────────────────────────────────────
    lines.append(f"\n\n  [3] PAKET OVERHEAD — İKİ VPN DE AYNI")
    lines.append(sep2)
    lines.append(f"  Her iki VPN de AES-256-GCM kullandığından overhead EŞİT:")
    lines.append(f"  12 byte (Nonce) + 16 byte (GCM Tag) = 28 byte / paket")
    lines.append(f"\n  Örnek: 84 byte ICMP ping → 112 byte şifreli payload")
    lines.append(f"  Fark: Sadece EL SIKIŞMA algoritması!")

    # ── 4. Güvenlik Karşılaştırması ───────────────────────────────────────────
    lines.append(f"\n\n  [4] GÜVENLİK DEĞERLENDİRMESİ")
    lines.append(sep2)
    lines.append(f"  {'Tehdit':<40} {'Klasik':>10} {'PQ-VPN':>10}")
    lines.append(sep2)
    threats = [
        ("Klasik bilgisayar brute-force",     "✅ Güvenli", "✅ Güvenli"),
        ("Shor algoritması (kuantum)",         "❌ KIRGILIR","✅ Güvenli"),
        ("Grover algoritması (kuantum)",       "⚠️  Zayıflar","✅ Güvenli"),
        ("Man-in-the-Middle (şifreli)",        "✅ Güvenli", "✅ Güvenli"),
        ("Harvest-Now-Decrypt-Later saldırısı","❌ Tehlikeli","✅ Güvenli"),
    ]
    for t in threats:
        lines.append(f"  {t[0]:<40} {t[1]:>10} {t[2]:>10}")

    # ── 5. Sonuç ──────────────────────────────────────────────────────────────
    lines.append(f"\n\n  [5] SONUÇ")
    lines.append(sep2)
    lines.append("  Her iki VPN de AES-256-GCM ile AYNI güçte veri şifrelemesi yapar.")
    lines.append("  TEMEL FARK: Oturum anahtarının nasıl değiş tokuş edildiğidir.")
    lines.append("")
    lines.append("  RSA-2048  → Kuantum bilgisayarlar bu anahtarı kırar (Shor, 2048-qubit)")
    lines.append("  Kyber512  → MLWE problemi kuantum için de zordur → geleceğe hazır!")
    lines.append("")
    lines.append("  Sonuç: Az CPU maliyetiyle maksimum uzun vadeli güvenlik = Kyber512")
    lines.append(sep)

    report = "\n".join(lines)
    print(report)

    out = os.path.join(BASE, "comparison_report.txt")
    with open(out, "w", encoding="utf-8") as f:
        f.write(report)
    print(f"\n  Rapor kaydedildi: {out}")
