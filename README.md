# ChaCha20 CPA

Side-Channel-Projekt mit dem **ChipWhisperer-Lite (STM32F3-Target, `CWLITEARM`)**:
ChaCha20 (IETF-Variante, RFC 8439) als SimpleSerial-Firmware, plus ein
Jupyter-Notebook zum Bauen, Flashen, Validieren und Aufnehmen von Traces.

## Struktur

```
Jupyter/
  Setup_Scripts/Setup_Generic.ipynb      # Scope/Target-Setup (aus ChipWhisperer)
  user/ChaCha20 - Test (HARDWARE).ipynb  # Test-Notebook + CPA-Angriff (§7)
  user/chacha20_traces.npz               # aufgenommene Traces
  user/ChaCha20_CPA_Erklaerung.md        # Erklärung + Visualisierung der CPA
  user/make_cpa_figures.py               # erzeugt die Abbildungen (cpa_figures/)
  user/cpa_figures/                      # PNGs zur Erklärung
firmware/mcu/
  simpleserial-chacha20/                 # eigene Firmware
    chacha20.c/.h                        # ChaCha20 (github.com/shiffthq/chacha20)
    simpleserial-chacha20.c              # SimpleSerial-Befehle k / n / p / x
    makefile                             # nur PLATFORM=CWLITEARM
  Makefile.inc, simpleserial/, hal/, crypto/   # Build-System aus ChipWhisperer
                                               # (auf STM32F3 reduziert)
```

## Voraussetzungen

- ChipWhisperer-Lite mit STM32F3-Target (CW-Lite Arm)
- **Python 3.9–3.12** (`chipwhisperer==6.0.0` von PyPI braucht `numpy<=1.26.4`,
  dafür gibt es für Python 3.13 keine fertigen Pakete)
- ARM-Toolchain `arm-none-eabi-gcc` und `make`
  - macOS: `brew install --cask gcc-arm-embedded`
  - Ubuntu/Debian: `sudo apt install gcc-arm-none-eabi make`
- Linux: udev-Regeln für den ChipWhisperer, siehe
  [ChipWhisperer-Doku](https://chipwhisperer.readthedocs.io/en/latest/linux-install.html)

## Setup

```bash
git clone https://github.com/timschaefer0702/ChaCha20_CPA.git
cd ChaCha20_CPA
python3.12 -m venv .venv          # oder: conda create -n chacha python=3.12
source .venv/bin/activate
pip install -r requirements.txt
```

## Ausführen

```bash
jupyter lab
```

Dann `Jupyter/user/ChaCha20 - Test (HARDWARE).ipynb` öffnen und alle Zellen
ausführen. Das Notebook baut die Firmware selbst (`make` in
`firmware/mcu/simpleserial-chacha20`) und flasht sie auf das Target.

Firmware manuell bauen:

```bash
cd firmware/mcu/simpleserial-chacha20
make
```

## CPA-Angriff

Sektion **7** des Notebooks führt eine Correlation Power Analysis auf die erste
ChaCha20-Runde durch und gewinnt den **vollständigen 256-bit-Schlüssel** aus 1000
Traces zurück (unabhängig per Re-Encrypt gegen gespeichertes `(pt, ct)` bestätigt):

- **Stufe 1 (XOR):** obere Key-Wörter `s[4..7]` über das Vorzeichen der Bit-Korrelation
- **Stufe 2 (ADD):** untere Key-Wörter `s[8..11]` bitweise LSB→MSB mit Carry

Ausführliche Erklärung mit Abbildungen:
[`Jupyter/user/ChaCha20_CPA_Erklaerung.md`](Jupyter/user/ChaCha20_CPA_Erklaerung.md).
Die Analyse-Sektion lädt nur `chacha20_traces.npz` und läuft offline (ohne Hardware).

## SimpleSerial-Befehle (SimpleSerial 1.1)

| Befehl | Länge | Funktion |
|---|---|---|
| `k` | 32 B | Schlüssel setzen |
| `n` | 16 B | Counter (4 B, little endian) und Nonce (12 B) |
| `p` | 16 B | 16 B Klartext verschlüsseln, Antwort `r` mit 16 B |
| `x` | 0 B | Schlüssel, Nonce und Counter auf null setzen |

## Lizenzen

- `firmware/mcu/Makefile.inc`, `simpleserial/`, `hal/`, `crypto/` und
  `Jupyter/Setup_Scripts/` stammen aus
  [newaetech/chipwhisperer](https://github.com/newaetech/chipwhisperer),
  siehe `firmware/mcu/LICENSE-chipwhisperer.txt` (Apache 2.0). Dateien von
  ST/ARM im HAL tragen ihre eigenen Lizenzhinweise im Dateikopf.
- `chacha20.c/.h` stammen aus
  [shiffthq/chacha20](https://github.com/shiffthq/chacha20).
