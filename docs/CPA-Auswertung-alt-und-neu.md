# Wie wir die alten und die neuen ChaCha20-Traces ausgewertet haben

Stand: 26. Oktober 2026. Dieses Dokument erklärt den Ablauf in zeitlicher Reihenfolge. Die konkreten Zahlen der zweiten Messreihe stehen zusätzlich in der [Validierungsdokumentation](CPA-Validierung-2026-10-26.md).

## Gemeinsame Angriffsidee

Wir messen den Stromverbrauch des STM32F3 während einer ChaCha20-Verschlüsselung. Pro Trace kennen wir Counter und Nonce; der Schlüssel ist während der CPA unbekannt. In der ersten Spalten-Quarterround entsteht für Spalte `j` zuerst

```text
S_j = (C_j + K_j) mod 2^32
D_j' = rotl32(D_j XOR S_j, 16)
```

`C_j` ist eine feste, öffentliche ChaCha20-Konstante. `K_j` ist eines der ersten vier geheimen Schlüsselwörter. `D_j` ist das bekannte Counter-Wort (`j=0`) beziehungsweise ein bekanntes Nonce-Wort (`j=1..3`). Das `+` ist eine **arithmetische Addition**, nicht XOR.

Für jedes Byte von `S_j` probieren wir 128 Klassenvertreter `g=0..127` und berechnen über alle Traces `HW(D_byte XOR g)`. Dieses vorhergesagte Hamming-Gewicht korrelieren wir mit den gemessenen Samples. Ein Kandidat `g` und `g XOR ff` ergeben betragsgleiche Korrelationen mit entgegengesetztem Vorzeichen. Deshalb liefert die Byte-CPA zunächst **Kandidatenpaare für Bytes von `S`**, keine eindeutigen Schlüsselbytes.

Aus vier gewählten Byte-Paaren entstehen 16 mögliche vollständige `S`-Wörter. Das zweite Modell bewertet `HW(D_word XOR S_word)`. Wegen der globalen Komplement-Symmetrie bleiben davon acht unterscheidbare Wortklassen. Für jedes vollständige `S`-Wort lässt sich ein **mögliches** Schlüsselwort mit `K_j = (S_j - C_j) mod 2^32` berechnen; die Subtraktion des ganzen Worts berücksichtigt Überträge.

Der ChipWhisperer wird für die **Aufnahme** benötigt. Beide CPA-Auswertungen laufen danach offline auf den gespeicherten NPZ-Dateien.

## Erste Messreihe: Modell und Zeitpunkte entwickeln

Die erste Datei `Jupyter/user/chacha20_traces.npz` enthält 1.000 Traces mit je 5.000 Samples, einen festen Testschlüssel und wechselnde öffentliche Counter-/Nonce-Werte. Der Schlüssel ist dort mitgespeichert und wurde zur Diagnose und Erfolgskontrolle verwendet.

1. Zunächst suchten wir mit dem Byte-HW-Modell breit über Samples `0:2000`. Nur **4/16** richtige `S`-Byte-Kandidatenpaare standen auf Rang 1. Hohe Peaks kamen teils von der Verarbeitung öffentlicher Eingaben.
2. Wir betrachteten die Korrelationen des **bekannten richtigen Zwischenwerts**. So fanden wir zeitliche Bereiche für die vier nacheinander ausgeführten Spalten. Diese Schlüsselkenntnis beeinflusste die Entwicklung der Fenster; das war eine **explorative Kalibrierung**.
3. Im Notebook wählte danach eine schlüsselunabhängige Rechenregel innerhalb dieser Fenster je einen gemeinsamen Samplepunkt pro Spalte. Weil die Fenster anhand derselben Messreihe entstanden, ist ihre Testhälfte keine unabhängige Prüfung des gesamten Verfahrens. Das Ergebnis war **12/16** richtige Byte-Paare auf Rang 1 im Training und **10/16** bei Neubewertung auf der Testhälfte.
4. Beim Counter-Wort wählte diese Regel Sample 741 und lag bei allen vier Bytes daneben. Eine spätere Diagnose mit dem bekannten Schlüssel zeigte um Sample 726 vier richtige Paare. Auch andere einfache Regeln, etwa bloß das größte Wort-Korrelationsmaximum, wählten an einzelnen Stellen falsche Kandidaten.
5. Daraus legten wir vor der zweiten Messreihe die **festen** Samples `(726, 1069, 1262, 1518)` fest. Auf den alten Daten ergaben diese nachträglich **16/16** richtige Byte-Paare im Training, **14/16** auf der Testhälfte und **4/4** richtige Wort-Komplementklassen. Ein zusätzliches Fenster von ±4 Samples ergab auf diesen alten Daten **16/16** richtige Byte-Paare in beiden Hälften. Diese Zahlen sind weiterhin **Kalibrierung am Entwicklungsdatensatz**, kein unabhängiger Angriffserfolg. Auch die Breite ±4 wurde nach Versuchen auf diesem Datensatz festgelegt.

Die Quellcode- und Disassemblierungsprüfung stützt die Operationsreihenfolge: Im kompilierten Quarterround-Code folgen `add`, `eors`, 16-Bit-Rotation und Speichern aufeinander; die vier ersten Quarterrounds werden nacheinander aufgerufen. Eine exakte Zuordnung eines ADC-Samples zu nur einer ARM-Instruktion ist damit noch nicht bewiesen.

## Zweite Messreihe: festgelegte Regeln prüfen

Vor der neuen Aufnahme wurden die Samples, das Byte- und Wortmodell, die Aufteilung der Traces und zwei Auswertungsregeln im [Validierungsprotokoll](CPA-Validierungsprotokoll.md) und im Git-Commit `059be2f` festgehalten. Die beiden Regeln sind:

- **Einzelpunkt (Hauptauswertung):** pro Spalte genau der oben festgelegte Samplepunkt; Kandidaten werden nach dem Betrag der Pearson-Korrelation geordnet.
- **Fenster ±4:** pro Spalte dieselben neun festgelegten Samples; Kandidaten werden nach der Summe der neun quadrierten Korrelationen geordnet. Die Breite und der Score werden auf den neuen Daten nicht angepasst.

Am 26. Oktober 2026 wurden mit **einem anderen festen Schlüssel** 1.000 neue gültige Traces aufgenommen. Die Datei `Jupyter/user/chacha20_traces_validation.npz` enthält keinen Schlüssel; dieser liegt getrennt in einer lokal ignorierten Datei. Firmware-Hash, Takte, Trace-Länge und Nonce-Eindeutigkeit wurden geprüft. Die geraden Zeilenindizes bilden 500 Trainings-Traces, die ungeraden 500 Test-Traces.

Der Ablauf war bewusst zweistufig:

1. [`cpa_frozen.py`](../Jupyter/user/cpa_frozen.py) lief **ohne Schlüsseldatei**. Es wählte Byte-Paare und Wortklassen ausschließlich aus den Traces und bekannten Counter-/Nonce-Werten. Die [vollständige Ausgabe](CPA-Validierung-blind-2026-10-26.txt) sowie Prüfsummen wurden gespeichert, **bevor** die Schlüsseldatei gelesen wurde.
2. Erst danach lief dasselbe unveränderte Skript mit der getrennten Schlüsseldatei zur **Erfolgskontrolle**. Sechs über den Datensatz verteilte Klartext/Chiffrat-Paare wurden mit diesem Schlüssel und pycryptodome nachgerechnet; sie stimmen.

| Neue Messreihe | Richtige Byte-Paare Rang 1, Training | Richtige Byte-Paare Rang 1, Test | Richtige Wortklassen, Training/Test |
| --- | ---: | ---: | ---: |
| Einzelpunkt | 14/16 | 14/16 | 2/4 · 2/4 |
| Fenster ±4 | 14/16 | 13/16 | 2/4 · 2/4 |

**Wichtig zur Testspalte:** Die Kandidaten werden auf der Trainingshälfte ausgewählt. Für die Testzahl werden die Hypothesen **auf der Testhälfte neu gereiht** und der Rang des wahren Paars gezählt. Die ausgewählten Trainingspaare selbst enthalten bei beiden Regeln 14/16 richtige Werte; die Testzahl beschreibt zusätzlich die Stabilität dieser Ränge.

Bei beiden Regeln trifft Wort 0. Wort 1 scheitert bei beiden an Byte 3. Wort 2 trifft nur mit dem ±4-Fenster, Wort 3 nur mit dem Einzelpunkt. Diese Unterschiede dürfen wir **nicht nachträglich mithilfe des bekannten Testschlüssels zusammenstellen** und als einen neuen blinden Angriff ausgeben.

## Was die Ergebnisse bedeuten

Die neue Messreihe zeigt, dass die vorab festgelegten Modelle auch bei einem anderen Schlüssel deutliche, reproduzierbare Korrelationen finden. Sie zeigt zugleich eine klare Grenze: Nur **2/4** der angegriffenen Wort-Komplementklassen treffen pro Regel. Selbst eine richtige Klasse enthält zwei mögliche `S`-Wörter, und der Angriff betrachtet zunächst nur vier der acht Schlüsselwörter. **Der 256-Bit-Schlüssel wurde nicht rekonstruiert.**

Für das Paper sind gerade der Unterschied zwischen Kalibrierung und unabhängiger Prüfung, die dokumentierten Fehlschläge und die mathematische Komplement-Mehrdeutigkeit wesentliche Befunde. Änderungen an Modell oder Zeitpunkten nach Sichtung des neuen Schlüssels sind eine neue **explorative** Phase und brauchen für eine neue unabhängige Erfolgsbehauptung einen weiteren Datensatz.
