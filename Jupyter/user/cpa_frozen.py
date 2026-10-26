"""Vorab festgelegte Offline-CPA für eine zweite ChaCha20-Messreihe.

Die Samplepunkte wurden auf der ersten Messreihe explorativ kalibriert.
Dieses Skript wählt auf einer neuen Messreihe weder Modell noch Samplepunkte
anhand des Validierungsschlüssels. Der Schlüssel wird erst nach der gesamten
Kandidatenauswahl eingelesen, wenn eine Validierungsoption angegeben ist.
"""

import argparse
from pathlib import Path

import numpy as np


CONSTANTS = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)
SAMPLES = (726, 1069, 1262, 1518)
WINDOW_RADIUS = 4
FIRMWARE_SHA256 = "361084c757e4e09a0d382da9841bd86604f87c694f35a0912a34c81953ba0376"
EXPECTED_CLKGEN_HZ = 7_384_615.384615385
EXPECTED_ADC_HZ = 29_542_304.0
PAIRS = np.arange(128, dtype=np.uint8)
HW8 = np.unpackbits(np.arange(256, dtype=np.uint8)[:, None], axis=1).sum(axis=1).astype(np.float32)


def normalized_columns(values):
    centered = values.astype(np.float32, copy=True)
    centered -= centered.mean(axis=0, keepdims=True)
    lengths = np.sqrt(np.sum(centered * centered, axis=0, keepdims=True))
    return np.divide(centered, lengths, out=np.zeros_like(centered), where=lengths != 0)


def correlation(models, trace_values):
    return (normalized_columns(models).T @ normalized_columns(trace_values[:, None]))[:, 0]


def window_energy(models, trace_values):
    """Summe der quadrierten Korrelationen über neun vorher festgelegte Samples."""
    correlations = normalized_columns(models).T @ normalized_columns(trace_values)
    return np.sum(correlations * correlations, axis=1)


def attack(traces, public):
    """Wählt Kandidaten ohne Zugriff auf den Testschlüssel."""
    if traces.shape != (1000, 5000) or public.shape != (1000, 16):
        raise ValueError("Erwartet 1000 Traces mit 5000 Samples und 16 Counter/Nonce-Bytes")
    if not np.isfinite(traces).all():
        raise ValueError("Traces enthalten NaN oder unendliche Werte")

    train = np.arange(1000) % 2 == 0
    test = ~train
    results = []
    for word, sample in enumerate(SAMPLES):
        byte_results = []
        for byte in range(4):
            model = HW8[np.bitwise_xor(public[:, 4 * word + byte, None], PAIRS[None, :])]
            r_train = correlation(model[train], traces[train, sample])
            r_test = correlation(model[test], traces[test, sample])
            pair = int(np.argmax(np.abs(r_train)))
            byte_results.append((pair, r_train, r_test))

        # Zwei Möglichkeiten pro Byte: 16 Wörter, acht globale Komplementklassen.
        selected_pairs = [row[0] for row in byte_results]
        s_words = np.array([
            sum((selected_pairs[byte] ^ (0xFF if (mask >> byte) & 1 else 0)) << (8 * byte)
                for byte in range(4))
            for mask in range(16)
        ], dtype=np.uint32)
        model = sum(
            HW8[np.bitwise_xor(public[:, 4 * word + byte, None],
                               ((s_words >> (8 * byte)) & 0xFF).astype(np.uint8)[None, :])]
            for byte in range(4)
        )
        word_train = correlation(model[train], traces[train, sample])
        word_test = correlation(model[test], traces[test, sample])
        if not np.allclose(word_train[:8], -word_train[15:7:-1], atol=1e-5):
            raise AssertionError("Globale Komplementklassen nicht symmetrisch")
        best = int(np.argmax(np.abs(word_train[:8])))
        s_candidates = (int(s_words[best]), int(s_words[best ^ 15]))
        k_candidates = tuple((s - CONSTANTS[word]) & 0xFFFFFFFF for s in s_candidates)
        results.append(dict(word=word, sample=sample, bytes=byte_results,
                            s_words=s_words, best=best, s_candidates=s_candidates,
                            k_candidates=k_candidates, word_train=word_train,
                            word_test=word_test))
    return results


def attack_window4(traces, public):
    """Zusätzliche, vor der zweiten Messung festgelegte Nachbarschaftsanalyse."""
    if traces.shape != (1000, 5000) or public.shape != (1000, 16):
        raise ValueError("Erwartet 1000 Traces mit 5000 Samples und 16 Counter/Nonce-Bytes")
    train = np.arange(1000) % 2 == 0
    test = ~train
    results = []
    for word, sample in enumerate(SAMPLES):
        window = slice(sample - WINDOW_RADIUS, sample + WINDOW_RADIUS + 1)
        byte_results = []
        for byte in range(4):
            model = HW8[np.bitwise_xor(public[:, 4 * word + byte, None], PAIRS[None, :])]
            score_train = window_energy(model[train], traces[train, window])
            score_test = window_energy(model[test], traces[test, window])
            pair = int(np.argmax(score_train))
            byte_results.append((pair, score_train, score_test))

        selected_pairs = [row[0] for row in byte_results]
        s_words = np.array([
            sum((selected_pairs[byte] ^ (0xFF if (mask >> byte) & 1 else 0)) << (8 * byte)
                for byte in range(4))
            for mask in range(16)
        ], dtype=np.uint32)
        model = sum(
            HW8[np.bitwise_xor(public[:, 4 * word + byte, None],
                               ((s_words >> (8 * byte)) & 0xFF).astype(np.uint8)[None, :])]
            for byte in range(4)
        )
        word_train = window_energy(model[train], traces[train, window])
        word_test = window_energy(model[test], traces[test, window])
        if not np.allclose(word_train[:8], word_train[15:7:-1], atol=1e-5):
            raise AssertionError("Globale Komplementklassen nicht symmetrisch")
        best = int(np.argmax(word_train[:8]))
        s_candidates = (int(s_words[best]), int(s_words[best ^ 15]))
        k_candidates = tuple((s - CONSTANTS[word]) & 0xFFFFFFFF for s in s_candidates)
        results.append(dict(word=word, sample=sample, bytes=byte_results,
                            s_words=s_words, best=best, s_candidates=s_candidates,
                            k_candidates=k_candidates, word_train=word_train,
                            word_test=word_test))
    return results


def validate(results, key):
    if len(key) != 32:
        raise ValueError("Validierungsschlüssel muss 32 Bytes lang sein")
    correct_byte_train = correct_byte_test = correct_word_train = correct_word_test = 0
    for result in results:
        word = result["word"]
        true_k = int.from_bytes(key[4 * word:4 * word + 4], "little")
        true_s = (CONSTANTS[word] + true_k) & 0xFFFFFFFF
        for byte, (_, r_train, r_test) in enumerate(result["bytes"]):
            true_byte = (true_s >> (8 * byte)) & 0xFF
            pair = min(true_byte, true_byte ^ 0xFF)
            rank_train = 1 + int(np.sum(np.abs(r_train) > abs(r_train[pair]) + 1e-6))
            rank_test = 1 + int(np.sum(np.abs(r_test) > abs(r_test[pair]) + 1e-6))
            correct_byte_train += rank_train == 1
            correct_byte_test += rank_test == 1
        hits = np.flatnonzero(result["s_words"] == true_s)
        if len(hits):
            true_class = min(int(hits[0]), int(hits[0]) ^ 15)
            for scores, is_train in ((result["word_train"], True), (result["word_test"], False)):
                rank = 1 + int(np.sum(np.abs(scores[:8]) > abs(scores[true_class]) + 1e-6))
                if is_train:
                    correct_word_train += rank == 1
                else:
                    correct_word_test += rank == 1
            word_rank = f"{1 + int(np.sum(np.abs(result['word_train'][:8]) > abs(result['word_train'][true_class]) + 1e-6))}/" \
                        f"{1 + int(np.sum(np.abs(result['word_test'][:8]) > abs(result['word_test'][true_class]) + 1e-6))}"
        else:
            word_rank = "nicht in 16"
        print(f"Wort {word}: wahre Wortklasse Rang Training/Test = {word_rank}")
    print(f"Richtige Byte-Paare Rang 1: Training {correct_byte_train}/16, Test {correct_byte_test}/16")
    print(f"Richtige Wortklassen Rang 1: Training {correct_word_train}/4, Test {correct_word_test}/4")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=Path(__file__).with_name("chacha20_traces_validation.npz"))
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--validation-key-file", type=Path,
                        help="32-Byte-Binärdatei; wird erst nach der Kandidatenauswahl gelesen")
    source.add_argument("--validate-embedded-key", action="store_true",
                        help="nur für die alte Kalibrierungs-NPZ mit eingebettetem Testschlüssel")
    args = parser.parse_args()

    with np.load(args.data) as saved:
        traces = saved["traces"].astype(np.float32)
        public = saved["ctrnonce"]
        if not args.validate_embedded_key:
            required = {"firmware_sha256", "adc_samples", "adc_offset", "adc_src",
                        "adc_freq", "clkgen_freq", "capture_utc"}
            missing = required.difference(saved.files)
            if missing:
                raise ValueError(f"Messmetadaten fehlen: {sorted(missing)}")
            if str(saved["firmware_sha256"].item()) != FIRMWARE_SHA256:
                raise ValueError("Firmware-Hash weicht von der festgelegten Version ab")
            if int(saved["adc_samples"]) != 5000 or int(saved["adc_offset"]) != 0:
                raise ValueError("ADC-Länge oder Offset weicht vom Protokoll ab")
            if str(saved["adc_src"].item()) != "clkgen_x4":
                raise ValueError("ADC-Taktquelle weicht vom Protokoll ab")
            if not np.isclose(float(saved["clkgen_freq"]), EXPECTED_CLKGEN_HZ, rtol=0.02):
                raise ValueError("Target-Takt weicht um mehr als 2 % vom Protokoll ab")
            if not np.isclose(float(saved["adc_freq"]), EXPECTED_ADC_HZ, rtol=0.02):
                raise ValueError("ADC-Takt weicht um mehr als 2 % vom Protokoll ab")
            print("Messmetadaten:", str(saved["capture_utc"].item()),
                  "ADC", float(saved["adc_freq"]), "Hz, Target-Takt",
                  float(saved["clkgen_freq"]), "Hz")
    point_results = attack(traces, public)
    window_results = attack_window4(traces, public)
    print("Hauptauswertung: feste Samples", SAMPLES)
    for label, results in (("Punkt", point_results), ("Fenster ±4", window_results)):
        print(label)
        for result in results:
            w = result["word"]
            s0, s1 = result["s_candidates"]
            k0, k1 = result["k_candidates"]
            chosen = result["best"]
            print(f"Wort {w}, Sample {result['sample']}: S {s0:08x}/{s1:08x}, "
                  f"K {k0:08x}/{k1:08x}, "
                  f"Score Training/Test {result['word_train'][chosen]:+.3f}/{result['word_test'][chosen]:+.3f}")
    print("Beide Kandidatenlisten sind ausgewählt; erst jetzt erfolgt optional die Erfolgskontrolle.")

    if args.validation_key_file:
        key = args.validation_key_file.read_bytes()
        print("Validierung Punkt:")
        validate(point_results, key)
        print("Validierung Fenster ±4:")
        validate(window_results, key)
    elif args.validate_embedded_key:
        with np.load(args.data) as saved:
            key = bytes(saved["key"])
        print("Validierung Punkt:")
        validate(point_results, key)
        print("Validierung Fenster ±4:")
        validate(window_results, key)


if __name__ == "__main__":
    main()
