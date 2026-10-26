# ChaCha20-CPA: festgelegtes Verfahren für die nächste Messreihe

Stand: 22. Oktober 2026. Dieses Protokoll wurde **vor** der zweiten Messreihe geschrieben. Die erste Messreihe mit 1.000 Traces ist der Entwicklungsdatensatz. Alle Ergebnisse daraus, einschließlich der Wahl der untenstehenden Samples, sind explorativ.

Entwicklungsdatei `Jupyter/user/chacha20_traces.npz`: SHA-256 `ada9d63f95d694c9c000ebd6d23de6cf041029bb1d1434c56dc282eccff4d705`.

## Was auf dem ersten Datensatz festgestellt wurde

- Das Target implementiert die IETF-Variante von ChaCha20. Der Trigger umschließt den gesamten `ChaCha20XOR()`-Aufruf. Die ersten vier Spalten-Quarterrounds werden nacheinander ausgeführt.
- In der aktuell kompilierten STM32F3-Firmware berechnet `chacha20_quarterround` zuerst `add` für `S = C + K` (Adresse `0x080002b8`), dann `eors` für `D XOR S` (`0x080002c2`), danach die 16-Bit-Rotation (`0x080002c4`) und ein Speichern (`0x080002c8`). Dies stützt das HW-Modell, beweist aber noch keine exakte Zuordnung eines ADC-Samples zu einer einzelnen Instruktion.
- Die bisherige Sample-Auswahl griff beim Counter-Wort daneben: Sample 741 lieferte 0/4 richtige Byte-Paare. Eine **Diagnose mit dem bekannten Schlüssel** zeigte um Sample 726 starke Korrelationen des richtigen Wortmodells und 4/4 richtige Byte-Paare. Ein reines Maximieren der Wortkorrelation wählte ebenfalls falsche Stellen in Spalte 0 und 1. Diese Fehlschläge gehören zur Ergebnisdarstellung.
- Für die nächste Messreihe werden **fest** die Samples `(726, 1069, 1262, 1518)` verwendet. Auf dem Entwicklungsdatensatz ergeben sie nachträglich 16/16 richtige Byte-Paare im Training, 14/16 im Test sowie 4/4 richtige 32-Bit-Komplementklassen in beiden Hälften. Dies ist eine Kalibrierungszahl, **kein unabhängiger Angriffserfolg**.
- Ein anderer Schlüssel ändert bei gleichem Firmwarepfad nicht die Reihenfolge der Instruktionen, kann aber die gemessene Form und Stärke lokaler Ausschläge verändern. Deshalb wurde zusätzlich eine feste Nachbarschaft von **±4 Samples** um jeden Punkt als Sensitivitätsauswertung gewählt. Sie bewertet je Hypothese die Summe der quadrierten Korrelationen über neun Samples; die Mittelpunktzeit bleibt fest. Auf dem Entwicklungsdatensatz ergibt dies 16/16 richtige Byte-Paare in beiden Hälften und 4/4 Wortklassen. Auch diese Zahl ist **nur Kalibrierung**. Die Radien ±8 und ±12 wurden ebenfalls auf den alten Daten ausprobiert und lieferten wieder falsche Byte-Paare; die Wahl von ±4 ist daher selbst explorativ.

## Eingefrorenes Angriffsverfahren

Die Implementierung liegt in [`Jupyter/user/cpa_frozen.py`](../Jupyter/user/cpa_frozen.py). Vor der Auswertung des neuen Schlüssels weder Samples, Modell, Teilung noch Tie-Breaking ändern. Jede Änderung beginnt eine neue explorative Runde und wird separat dokumentiert.

1. Erwartet werden genau 1.000 gültige Traces mit je 5.000 Samples. Gerade Zeilenindizes sind Training, ungerade Test. Counter und 96-Bit-Nonce sind pro Trace bekannt; Nonces sind verschieden.
2. Für die vier ersten Spalten gilt `S_j = (C_j + K_j) mod 2^32`. Je Byte und festem Sample korreliert das Skript `HW(D_byte XOR g)` für die 128 Klassenvertreter `g=0..127` mit den Trainings-Traces. Der größte **Betrag** gewinnt; `np.argmax` entscheidet Gleichstände durch den kleinsten Index. Dies ist die **Hauptauswertung**.
3. Aus vier führenden Byte-Paaren werden je Spalte 16 mögliche `S`-Wörter gebildet. Das 32-Bit-Modell ist `HW(D_word XOR S_word)`. Acht globale Komplementklassen werden am **selben** festen Sample nach Betrag der Trainingskorrelation geordnet. Ein Wort und sein vollständiges Bitkomplement bleiben ununterscheidbar.
4. Kandidaten, Korrelationen und Samples werden vor Zugriff auf den Validierungsschlüssel ausgegeben. Danach werden die Ränge der richtigen Byte-Paare und Wortklassen auf Training und Test bestimmt. Der Testschlüssel darf keine Kandidatenentscheidung beeinflussen.
5. Berichtet werden auch falsche Paare, fehlende wahre Wörter, Abweichungen der Korrelationen und alle Änderungen am Messaufbau. Selbst 4/4 richtige Wortklassen wären **keine** eindeutigen Schlüsselwörter und nur die ersten vier der acht 32-Bit-Schlüsselwörter sind angegriffen.
6. Das Skript führt danach **vor** jeder Schlüsselkontrolle dieselbe Byte- und Wortsuche mit dem festgelegten Fenster `[Sample-4, Sample+4]` aus. Für jede Hypothese ist der Score die Summe der neun quadrierten Pearson-Korrelationen; auf dem Testteil wird das gleiche feste Fenster verwendet. Punkt- und Fensterresultate werden **beide** berichtet, auch wenn die Fensterregel schlechter abschneidet. Ergebnisse nicht nachträglich zu einem günstigeren Einzelwert vermischen.

## Vorbereitung der neuen Messung

- **Firmware:** dieselbe HEX-Datei verwenden; SHA-256 `361084c757e4e09a0d382da9841bd86604f87c694f35a0912a34c81953ba0376`. Ein neuer Build mit anderer HEX-Datei ist ein geänderter Messaufbau und benötigt eine dokumentierte Entscheidung über die Übertragbarkeit der Samplepunkte.
- **Aufnahme:** CW-Lite mit STM32F3, `scope.adc.samples = 5000`, `scope.adc.offset = 0`, ADC-Taktquelle `clkgen_x4`, gleicher Trigger um `ChaCha20XOR()`. Im ersten Notebook-Output standen ungefähr 7,3846 MHz Target-Takt und 29,5423 MHz ADC-Takt. Die Aufnahmezelle synchronisiert den ADC-Takt vor der Messung neu, weil der Treiber einen früh gelesenen Frequenzwert zwischenspeichern kann. Danach prüft sie Firmware und Takte vor dem ersten Trace; mehr als 2 % Taktabweichung stoppen den Lauf. Die neuen tatsächlichen Werte werden in der NPZ gespeichert und beim Offline-Angriff erneut geprüft.
- **Eingaben:** ein neuer zufälliger, während aller 1.000 Aufnahmen fester 256-Bit-Schlüssel; je Trace neuer zufälliger Counter und neue zufällige Nonce sowie ein zufälliger 16-Byte-Klartext. Die Antworten weiterhin mit pycryptodome und Simulation prüfen.
- **Speicherung:** Die Aufnahmezelle im Hardware-Notebook schreibt `Jupyter/user/chacha20_traces_validation.npz` **ohne Schlüssel** und `Jupyter/user/chacha20_validation_key.bin` separat. Beide Dateien werden nicht überschrieben und sind bis zur Auswertung in `.gitignore`. Die alte `chacha20_traces.npz` bleibt erhalten. Die NPZ speichert Firmware-Hash, ADC-/Takteinstellungen und UTC-Zeit.
- **Notebook-Auswertung:** Die bisherigen CPA-Zellen laden weiterhin ausdrücklich die **alte** `chacha20_traces.npz` und dienen der Kalibrierungsdokumentation. Die neue NPZ nur mit dem festgelegten Skript auswerten; die alten Notebook-Ränge nicht als Ergebnis der zweiten Messreihe lesen.
- **Vor der Aufnahme prüfen:** korrekte Firmware flashen, gleichen Takt und Trigger prüfen, genügend freien Speicher sicherstellen. Die Speicherzelle akzeptiert nur genau 1.000 gültige Traces; bei Ausfällen die Aufnahme erneut planen und Abweichungen protokollieren.

## Reihenfolge der Auswertung

Aus dem Projektordner zuerst **ohne** Schlüsseldatei ausführen und die Ausgabe beider Regeln sichern:

```bash
.venv/bin/python Jupyter/user/cpa_frozen.py --data Jupyter/user/chacha20_traces_validation.npz
```

Danach, ohne Code oder Parameter zu ändern, die Erfolgskontrolle ausführen:

```bash
.venv/bin/python Jupyter/user/cpa_frozen.py --data Jupyter/user/chacha20_traces_validation.npz --validation-key-file Jupyter/user/chacha20_validation_key.bin
```

Vor dieser zweiten Ausführung SHA-256 der NPZ und den Git-Commit des Skripts notieren. Die erste Ausgabe als Nachweis der schlüsselunabhängigen Kandidatenauswahl aufbewahren. Ein einzelner neuer Schlüssel prüft die Übertragbarkeit auf **eine** weitere Messreihe; daraus folgt keine allgemeine Erfolgswahrscheinlichkeit für andere Geräte oder Schlüssel.
