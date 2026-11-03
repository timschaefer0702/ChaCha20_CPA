"""Rauschfreie CPA auf Spaltenrunde und folgender diagonaler Runde.

Ein synthetischer Trace enthält getrennte HW8-Leakage der ausgewählten
Zwischenwerte in den Spalten- und diagonalen Quarterrounds. Das ist ein
idealisiertes Leakage-Modell, keine Vorhersage für ChipWhisperer-Samples.
Der Angriff bekommt nur öffentliche Counter/Nonce-Wörter und die Leakage;
der geheime Testschlüssel wird erst für die abschließende Prüfung verwendet.
"""

import argparse
import numpy as np


MASK = 0xFFFFFFFF
CONSTANTS = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)
HW8 = np.unpackbits(np.arange(256, dtype=np.uint8)[:, None], axis=1).sum(1)


def corr(models, observations):
    """Pearson-Korrelation je Kandidat; konstante Vektoren ergeben null."""
    x = np.asarray(models, dtype=np.float64)
    y = np.asarray(observations, dtype=np.float64)
    x = x - x.mean(axis=0)
    y = y - y.mean()
    denominator = np.sqrt(np.sum(x * x, axis=0) * np.sum(y * y))
    return np.divide(y @ x, denominator, out=np.zeros(x.shape[1]),
                     where=denominator != 0)


def rotl16(x):
    return ((x << np.uint32(16)) | (x >> np.uint32(16))).astype(np.uint32)


def rotl(x, amount):
    return ((x << np.uint32(amount)) | (x >> np.uint32(32 - amount))).astype(np.uint32)


def byte(x, index):
    return ((x >> np.uint32(8 * index)) & np.uint32(255)).astype(np.uint8)


def make_traces(rng, count, variable_counter, nonce_mode):
    """Fester Schlüssel, eindeutige Nonces, optional variierender Counter."""
    key = rng.integers(0, 2**32, size=8, dtype=np.uint32)
    public = rng.integers(0, 2**32, size=(count, 4), dtype=np.uint32)
    if not variable_counter:
        public[:, 0] = 1  # erster Datenblock eines neuen Aufrufs
    if nonce_mode == "sequential":
        # Einfacher 96-Bit-Nachrichtenzähler: in diesem kurzen Versuch
        # ändert sich nur das niederwertige Nonce-Wort.
        public[:, 1] = np.arange(count, dtype=np.uint32)
        public[:, 2:] = 0
    elif nonce_mode == "random":
        # Die drei 32-Bit-Wörter stammen unverändert aus dem Zufallsgenerator.
        # Die Werte werden als öffentliche Eingaben zusammen mit den Traces
        # gespeichert. Doppelte 96-Bit-Nonces werden im Versuch abgewiesen.
        if len(np.unique(public[:, 1:4], axis=0)) != count:
            raise ValueError("Zufalls-Nonces enthalten eine Wiederholung")
    else:
        raise ValueError("nonce_mode muss 'sequential' oder 'random' sein")

    leak_d = np.empty((count, 4, 4), dtype=np.uint8)
    leak_b = np.empty_like(leak_d)
    for col in range(4):
        a = int(CONSTANTS[col])
        b = int(key[col])
        c = int(key[col + 4])
        s = np.uint32((a + b) & MASK)
        d_before_rotation = public[:, col] ^ s
        d_rotated = rotl16(d_before_rotation)
        c_updated = (np.uint32(c) + d_rotated).astype(np.uint32)
        b_before_rotation = np.uint32(b) ^ c_updated
        for j in range(4):
            leak_d[:, col, j] = HW8[byte(d_before_rotation, j)]
            leak_b[:, col, j] = HW8[byte(b_before_rotation, j)]
    return key, public, leak_d, leak_b


def first_stage(public_word, leak_d):
    """Je Byte das S-Byte/Komplement-Paar; danach 16 mögliche S-Wörter."""
    if any(np.all(byte(public_word, j) == byte(public_word, j)[0]) for j in range(4)):
        return None
    pairs = []
    guesses = np.arange(128, dtype=np.uint8)
    for j in range(4):
        model = HW8[np.bitwise_xor(byte(public_word, j)[:, None], guesses)]
        pairs.append(int(np.argmax(np.abs(corr(model, leak_d[:, j])))))
    words = [sum((pairs[j] ^ (255 if mask & (1 << j) else 0)) << (8 * j)
                 for j in range(4)) for mask in range(16)]
    return pairs, words


def second_stage(public_word, leak_b, constant, s_word):
    """Für ein S-Wort K5..K8 byteweise testen, mit exakten Überträgen."""
    b_word = (s_word - constant) & MASK
    d_rotated = rotl16(public_word ^ np.uint32(s_word))
    carry = np.zeros(len(public_word), dtype=np.uint16)
    guesses = np.arange(256, dtype=np.uint16)
    recovered = 0
    scores = []
    for j in range(4):
        add = byte(d_rotated, j).astype(np.uint16)[:, None] + guesses[None, :] + carry[:, None]
        x = np.bitwise_xor((add & 255).astype(np.uint8), np.uint8((b_word >> (8 * j)) & 255))
        strength = np.abs(corr(HW8[x], leak_b[:, j]))
        choice = int(np.argmax(strength))
        recovered |= choice << (8 * j)
        carry = (add[:, choice] >> 8).astype(np.uint16)
        scores.append(float(strength[choice]))
    return recovered, scores


def column_state(key, public):
    """Zustand nach den vier vollständigen Spalten-Quarterrounds."""
    state = np.empty((len(public), 16), dtype=np.uint32)
    state[:, :4] = np.asarray(CONSTANTS, dtype=np.uint32)
    state[:, 4:12] = np.asarray(key, dtype=np.uint32)
    state[:, 12:16] = public
    for col in range(4):
        a, b, c, d = col, col + 4, col + 8, col + 12
        state[:, a] += state[:, b]
        state[:, d] = rotl(state[:, d] ^ state[:, a], 16)
        state[:, c] += state[:, d]
        state[:, b] = rotl(state[:, b] ^ state[:, c], 12)
        state[:, a] += state[:, b]
        state[:, d] = rotl(state[:, d] ^ state[:, a], 8)
        state[:, c] += state[:, d]
        state[:, b] = rotl(state[:, b] ^ state[:, c], 7)
    return state


def hw_bytes(values):
    return np.stack([HW8[byte(values, j)] for j in range(4)], axis=1)


def diagonal_leakage(state):
    """Ausgewählte HW-Werte der ersten diagonalen Quarterrounds."""
    a0_add = state[:, 0] + state[:, 5]                    # QR (0,5,10,15)
    a1_add = state[:, 1] + state[:, 6]                    # QR (1,6,11,12)
    d12_xor = state[:, 12] ^ a1_add
    c11_add = state[:, 11] + rotl16(d12_xor)
    b6_xor = state[:, 6] ^ c11_add
    a2_add = state[:, 2] + state[:, 7]                    # QR (2,7,8,13)
    c8_add = state[:, 8] + rotl16(state[:, 13] ^ a2_add)
    a3_add = state[:, 3] + state[:, 4]                    # QR (3,4,9,14)
    return {"a0": hw_bytes(a0_add), "d12": hw_bytes(d12_xor),
            "d12_followup": hw_bytes(b6_xor), "c8": hw_bytes(c8_add),
            "b4": hw_bytes(a3_add)}


def recover_addend(known_operand, observations):
    """Unbekanntes 32-Bit-Wort aus HW8(known_operand + word) gewinnen."""
    carry = np.zeros(len(known_operand), dtype=np.uint16)
    guesses = np.arange(256, dtype=np.uint16)
    recovered = 0
    scores = []
    for j in range(4):
        add = byte(known_operand, j).astype(np.uint16)[:, None] + guesses[None, :] + carry[:, None]
        strength = corr(HW8[(add & 255).astype(np.uint8)], observations[:, j])
        choice = int(np.argmax(strength))
        recovered |= choice << (8 * j)
        carry = (add[:, choice] >> 8).astype(np.uint16)
        scores.append(float(strength[choice]))
    return recovered, scores


def recover_d12(known_state, observations, followup):
    """XOR-Paare durch einen späteren diagonalen Zwischenwert auflösen."""
    a1_add = known_state[:, 1] + known_state[:, 6]
    result = first_stage(a1_add, observations)
    if result is None:
        return None
    _, candidates = result
    scores = []
    for candidate in candidates:
        d_rot = rotl16(a1_add ^ np.uint32(candidate))
        b_pre = known_state[:, 6] ^ (known_state[:, 11] + d_rot)
        predicted = hw_bytes(b_pre)
        score = sum(float(corr(predicted[:, j, None], followup[:, j])[0]) for j in range(4))
        scores.append(score)
    choice = int(np.argmax(scores))
    return candidates[choice], scores[choice], len(candidates)


def rotr_scalar(value, amount):
    return ((value >> amount) | (value << (32 - amount))) & MASK


def inverse_quarterround(a, b, c, d):
    """ChaCha-Quarterround rückwärts auf vier 32-Bit-Wörtern."""
    b = rotr_scalar(b, 7) ^ c
    c = (c - d) & MASK
    d = rotr_scalar(d, 8) ^ a
    a = (a - b) & MASK
    b = rotr_scalar(b, 12) ^ c
    c = (c - d) & MASK
    d = rotr_scalar(d, 16) ^ a
    a = (a - b) & MASK
    return a, b, c, d


def attack_diagonal(public, known_key, leakage):
    """K1/K5 nur aus bekannten anderen Spalten und diagonalem Leakage."""
    known_state = column_state(known_key, public)
    a0, a_score = recover_addend(known_state[:, 5], leakage["a0"])
    b4, b_score = recover_addend(known_state[:, 3], leakage["b4"])
    a2_add = known_state[:, 2] + known_state[:, 7]
    c8_operand = rotl16(known_state[:, 13] ^ a2_add)
    c8, c_score = recover_addend(c8_operand, leakage["c8"])
    d_result = recover_d12(known_state, leakage["d12"], leakage["d12_followup"])
    if d_result is None:
        raise AssertionError("Keine Variation für d12 im diagonalen Modell")
    d12, d_score, d_candidates = d_result
    initial_a, k1, k5, initial_d = inverse_quarterround(a0, b4, c8, d12)
    return (k1, k5), (initial_a == CONSTANTS[0] and initial_d == int(public[0, 0])), \
        (a_score, b_score, c_score, d_score, d_candidates)


def run(count, variable_counter, nonce_mode, seed):
    rng = np.random.default_rng(seed)
    key, public, leak_d, leak_b = make_traces(rng, count, variable_counter, nonce_mode)
    print(f"{count} ideale Traces; Counter: {'variabel' if variable_counter else 'fest = 1'}; Nonce: {nonce_mode}")
    print("K1..K4 = Zeile b; K5..K8 = Zeile c (Nummerierung ab 1)")
    selected_key = np.zeros(8, dtype=np.uint32)
    recovered_columns = set()
    for col in range(4):
        result = first_stage(public[:, col], leak_d[:, col])
        if result is None:
            varying = [j for j in range(4) if not np.all(byte(public[:, col], j) == byte(public[:, col], j)[0])]
            print(f"Spalte {col}: K{col+1}/K{col+5}: öffentliche Bytes mit Variation {varying}; "
                  "kein vollständiges Wort über diese frühe Byte-CPA identifizierbar")
            continue
        pairs, s_words = result
        branches = []
        for s in s_words:
            c, scores = second_stage(public[:, col], leak_b[:, col], CONSTANTS[col], s)
            branches.append((sum(scores), s, c, scores))
        branches.sort(key=lambda x: x[0], reverse=True)
        best = branches[0]
        true_s = (CONSTANTS[col] + int(key[col])) & MASK
        true_branch = next((i for i, branch in enumerate(branches)
                            if branch[1] == true_s and branch[2] == int(key[col + 4])), None)
        print(f"Spalte {col}: K{col+1}-Paar {'✓' if true_s in s_words else '✗'}, "
              f"K{col+1}/K{col+5} gemeinsam {'✓' if best[1] == true_s and best[2] == int(key[col+4]) else '✗'}, "
              f"Rang der wahren Kombination: {true_branch+1 if true_branch is not None else 'nicht gefunden'}, "
              f"Score {best[0]:.3f}/4")
        selected_key[col] = np.uint32((best[1] - CONSTANTS[col]) & MASK)
        selected_key[col + 4] = np.uint32(best[2])
        recovered_columns.add(col)
    if not variable_counter and recovered_columns.issuperset({1, 2, 3}):
        leakage = diagonal_leakage(column_state(key, public))
        (k1, k5), consistent, detail = attack_diagonal(public, selected_key, leakage)
        print(f"Diagonale: 1 gewählte Kombination aus K2..K4/K6..K8; "
              f"d12 aus {detail[4]} Wortkandidaten; K1/K5 "
              f"{'✓' if (k1, k5) == (int(key[0]), int(key[4])) else '✗'}; "
              f"Inverse-QR mit Konstante/Counter {'konsistent' if consistent else 'inkonsistent'}")
    return key


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--traces", type=int, default=512)
    parser.add_argument("--seed", type=int, default=20261028)
    args = parser.parse_args()
    run(args.traces, False, "random", args.seed)
    run(args.traces, False, "sequential", args.seed)
    run(args.traces, True, "random", args.seed)
