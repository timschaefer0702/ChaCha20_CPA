"""
Python-Simulation von firmware/mcu/simpleserial-chacha20/chacha20.c

Die Struktur folgt 1:1 der C-Implementierung
(Quelle: https://github.com/shiffthq/chacha20/tree/master):
gleiche Funktionen, gleiche Namen, gleiche Schleifen und gleiche Reihenfolge
der Operationen. Python-spezifische Abkürzungen (int.from_bytes, struct,
Slicing, List Comprehensions, ...) werden bewusst nicht verwendet.

Abbildung C -> Python:
  - uint32_t-Arithmetik: Python-Integer laufen nicht über, deshalb wird nach
    jeder Operation, die in C überlaufen kann (+, <<), explizit mit
    U32_MASK maskiert. Das entspricht dem Wrap-around modulo 2^32 in C.
  - Pointer-Arithmetik (z.B. key + i * 4): wird als (array, offset)
    übergeben.
  - Arrays (uint32_t x[16], uint8_t block[64]): Python-Listen fester Länge.
  - memcpy: elementweise Kopierschleife.

Leakage-Trace (Hamming-Weight-Modell):
  Alle Funktionen bekommen als letzten Parameter eine Liste `trace`
  (in C: ein durchgereichter Pointer). Nach jeder Zuweisung an eine
  ChaCha20-Variable wird HW(neuer Wert) an `trace` angehängt. Schleifenzähler
  (i, j) werden nicht aufgezeichnet, weil sie nicht von den Daten abhängen.
  Der Kontrollfluss ist datenunabhängig, daher hat Index k in `trace` bei
  gleichem inlen immer dieselbe Bedeutung (z.B. "x[12] nach der ersten
  Quarterround"). So lassen sich viele Traces direkt stapeln.
"""

U32_MASK = 0xFFFFFFFF

def HW(x):
    if isinstance(x, (bytes, bytearray)):
        return sum(bin(b).count("1") for b in x)
    return bin(x).count("1")

# static inline void u32t8le(uint32_t v, uint8_t p[4])
def u32t8le(v, p, p_off, trace):
    p[p_off + 0] = v & 0xff;         trace.append(HW(p[p_off + 0]))
    p[p_off + 1] = (v >> 8) & 0xff;  trace.append(HW(p[p_off + 1]))
    p[p_off + 2] = (v >> 16) & 0xff; trace.append(HW(p[p_off + 2]))
    p[p_off + 3] = (v >> 24) & 0xff; trace.append(HW(p[p_off + 3]))


# static inline uint32_t u8t32le(uint8_t p[4])
def u8t32le(p, p_off, trace):
    value = p[p_off + 3];                                trace.append(HW(value))

    value = ((value << 8) | p[p_off + 2]) & U32_MASK;    trace.append(HW(value))
    value = ((value << 8) | p[p_off + 1]) & U32_MASK;    trace.append(HW(value))
    value = ((value << 8) | p[p_off + 0]) & U32_MASK;    trace.append(HW(value))

    return value


# static inline uint32_t rotl32(uint32_t x, int n)
def rotl32(x, n):
    # http://blog.regehr.org/archives/1063
    return ((x << n) & U32_MASK) | (x >> (-n & 31))


# static void chacha20_quarterround(uint32_t *x, int a, int b, int c, int d)
# https://tools.ietf.org/html/rfc7539#section-2.1
def chacha20_quarterround(x, a, b, c, d, trace):
    x[a] = (x[a] + x[b]) & U32_MASK; trace.append(HW(x[a])); x[d] = rotl32(x[d] ^ x[a], 16); trace.append(HW(x[d]))
    x[c] = (x[c] + x[d]) & U32_MASK; trace.append(HW(x[c])); x[b] = rotl32(x[b] ^ x[c], 12); trace.append(HW(x[b]))
    x[a] = (x[a] + x[b]) & U32_MASK; trace.append(HW(x[a])); x[d] = rotl32(x[d] ^ x[a],  8); trace.append(HW(x[d]))
    x[c] = (x[c] + x[d]) & U32_MASK; trace.append(HW(x[c])); x[b] = rotl32(x[b] ^ x[c],  7); trace.append(HW(x[b]))


# static void chacha20_serialize(uint32_t in[16], uint8_t output[64])
def chacha20_serialize(in_, output, trace):
    i = 0
    while i < 16:
        u32t8le(in_[i], output, i << 2, trace)
        i += 1


# static void chacha20_block(uint32_t in[16], uint8_t out[64], int num_rounds)
def chacha20_block(in_, out, num_rounds, trace):
    x = [0] * 16

    # memcpy(x, in, sizeof(uint32_t) * 16);
    i = 0
    while i < 16:
        x[i] = in_[i]; trace.append(HW(x[i]))
        i += 1

    i = num_rounds
    while i > 0:
        chacha20_quarterround(x, 0, 4,  8, 12, trace)
        chacha20_quarterround(x, 1, 5,  9, 13, trace)
        chacha20_quarterround(x, 2, 6, 10, 14, trace)
        chacha20_quarterround(x, 3, 7, 11, 15, trace)
        chacha20_quarterround(x, 0, 5, 10, 15, trace)
        chacha20_quarterround(x, 1, 6, 11, 12, trace)
        chacha20_quarterround(x, 2, 7,  8, 13, trace)
        chacha20_quarterround(x, 3, 4,  9, 14, trace)
        i -= 2

    i = 0
    while i < 16:
        x[i] = (x[i] + in_[i]) & U32_MASK; trace.append(HW(x[i]))
        i += 1

    chacha20_serialize(x, out, trace)


# static void chacha20_init_state(uint32_t s[16], uint8_t key[32], uint32_t counter, uint8_t nonce[12])
# https://tools.ietf.org/html/rfc7539#section-2.3
def chacha20_init_state(s, key, counter, nonce, trace):
    # refer: https://dxr.mozilla.org/mozilla-beta/source/security/nss/lib/freebl/chacha20.c
    # convert magic number to string: "expand 32-byte k"
    s[0] = 0x61707865; trace.append(HW(s[0]))
    s[1] = 0x3320646e; trace.append(HW(s[1]))
    s[2] = 0x79622d32; trace.append(HW(s[2]))
    s[3] = 0x6b206574; trace.append(HW(s[3]))

    i = 0
    while i < 8:
        s[4 + i] = u8t32le(key, i * 4, trace); trace.append(HW(s[4 + i]))
        i += 1

    s[12] = counter & U32_MASK; trace.append(HW(s[12]))  # Parameter ist uint32_t

    i = 0
    while i < 3:
        s[13 + i] = u8t32le(nonce, i * 4, trace); trace.append(HW(s[13 + i]))
        i += 1


# void ChaCha20XOR(uint8_t key[32], uint32_t counter, uint8_t nonce[12], uint8_t *in, uint8_t *out, int inlen)
def ChaCha20XOR(key, counter, nonce, in_, out, inlen, trace):
    s = [0] * 16
    block = [0] * 64

    chacha20_init_state(s, key, counter, nonce, trace)

    i = 0
    while i < inlen:
        chacha20_block(s, block, 20, trace)
        s[12] = (s[12] + 1) & U32_MASK; trace.append(HW(s[12]))

        j = i
        while j < i + 64:
            if j >= inlen:
                break
            out[j] = in_[j] ^ block[j - i]; trace.append(HW(out[j]))
            j += 1

        i += 64


# Selbsttest mit den Testvektoren aus RFC 8439
if __name__ == "__main__":
    # RFC 8439, 2.3.2: Keystream-Block (Klartext = Nullen)
    key = [0] * 32
    i = 0
    while i < 32:
        key[i] = i
        i += 1
    nonce = [0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00]
    zeros = [0] * 64
    out = [0] * 64
    trace = []
    ChaCha20XOR(key, 1, nonce, zeros, out, 64, trace)
    expected = bytes.fromhex(
        "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
        "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e")
    print("RFC 8439 2.3.2 block  :", "OK" if bytes(out) == expected else "FAIL", f"(trace: {len(trace)} Werte)")

    # RFC 8439, 2.4.2: Verschlüsselung
    nonce = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00]
    pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
    ct = [0] * len(pt)
    trace = []
    ChaCha20XOR(key, 1, nonce, pt, ct, len(pt), trace)
    expected = bytes.fromhex(
        "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b"
        "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8"
        "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736"
        "5af90bbf74a35be6b40b8eedf2785e42874d")
    print("RFC 8439 2.4.2 encrypt:", "OK" if bytes(ct) == expected else "FAIL", f"(trace: {len(trace)} Werte)")
