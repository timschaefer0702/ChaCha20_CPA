# Unser ChaCha20-CPA-Angriff: Modell und Ablauf

Stand: 3. November 2026. Dieses Dokument beschreibt den **geplanten Angriff auf unsere eigene ChipWhisperer-Laborimplementierung**. Es erklärt die Theorie. Die rauschfreie Simulation und die bisherigen Hardware-Ergebnisse stehen getrennt in den verlinkten Dokumenten.

## 1. Ausgangszustand

ChaCha20 arbeitet mit einer 4×4-Matrix aus 32-Bit-Wörtern. Wir nummerieren die acht Schlüsselwörter hier von `K1` bis `K8`:

```text
              Spalte 0     Spalte 1     Spalte 2     Spalte 3
Zeile 0       C0           C1           C2           C3
Zeile 1       K1           K2           K3           K4
Zeile 2       K5           K6           K7           K8
Zeile 3       CTR          N0           N1           N2
```

`C0..C3` sind die bekannten ChaCha-Konstanten. `CTR` ist der öffentliche Block-Counter, `N0..N2` sind die drei öffentlichen Wörter der 96-Bit-Nonce. Im geplanten Laborversuch bleibt **ein unbekannter Schlüssel** während aller Messungen gleich. Der Counter ist für den ersten Datenblock fest auf `1` gesetzt. Für jeden Trace entsteht eine neue zufällige Nonce; ihr tatsächlicher Wert wird zusammen mit dem Trace gespeichert. Wir müssen die Nonce nicht auswählen können, aber für jede Vorhersage kennen.

[RFC 8439](https://www.rfc-editor.org/rfc/rfc8439) erlaubt bei ChaCha20 allgemein einen anfänglichen Counter; in der dort beschriebenen ChaCha20-Poly1305-Konstruktion beginnt die **Nutzdatenverschlüsselung** bei Counter `1`. Unsere Firmware ist eine ChaCha20-Laborimplementierung, kein vollständiger ChaCha20-Poly1305-Protokollstack.

## 2. Was ein CPA-Modell vorhersagt

Ein ChipWhisperer-Trace ist eine Folge gemessener Stromwerte. Für einen vermuteten Schlüsselwert berechnen wir bei **jedem Trace** den gleichen ausgewählten ChaCha-Zwischenwert und dessen Hamming-Gewicht `HW`: die Zahl der gesetzten Bits. Die Folge dieser HW-Vorhersagen wird mit einem Sample oder einem festen Zeitfenster der gemessenen Traces korreliert.

Die Aussage „HW-Modell“ legt noch **nicht** fest, welcher Zwischenwert und welche Breite auf unserem STM32F3 tatsächlich leaken: ein Byte, ein 32-Bit-Register, der Wert vor oder nach einer Rotation oder ein Speichervorgang. Das müssen wir am kompilierten Code und an den Traces prüfen. Unser aktueller Simulator erzeugt idealisierte **Byte-HW-Werte ohne Rauschen**; ein Erfolg dort beweist noch keinen Erfolg auf dem Board.

## 3. Erste ChaCha-Runde: drei Spalten mit variierender Nonce

Die erste ChaCha-Runde besteht aus vier **Spalten-Quarterrounds**. In einer Spalte stehen zunächst `a=C`, `b=K_oben`, `c=K_unten` und `d=CTR` oder `d=Nonce-Wort`. Die ersten Schritte lauten:

```text
a1 = (C + K_oben) mod 2^32
d1 = rotl32(d XOR a1, 16)
c1 = (K_unten + d1) mod 2^32
b1 = rotl32(K_oben XOR c1, 12)
```

Für die **Spalten 1–3** variiert `d` durch die zufällige Nonce. Das ergibt folgende Angriffskette:

| Spalte | Früher HW-Zwischenwert | Erste Wort-Hypothese | Späterer HW-Zwischenwert | Zweite Wort-Hypothese |
| --- | --- | --- | --- | --- |
| 1 | `d XOR (C1 + K2)` | K2 | Wert aus `K6 + d1` und anschließendem XOR mit K2 | K6 |
| 2 | `d XOR (C2 + K3)` | K3 | Wert aus `K7 + d1` und anschließendem XOR mit K3 | K7 |
| 3 | `d XOR (C3 + K4)` | K4 | Wert aus `K8 + d1` und anschließendem XOR mit K4 | K8 |

So entstehen zuerst Hypothesen für **K2–K4**, danach bedingt auf diese Hypothesen für **K6–K8**. `+` ist immer die Addition modulo `2^32`, **nicht XOR**. Bei Byte-Hypothesen müssen die Überträge zwischen den vier Bytes eines Wortes korrekt mitgerechnet werden. Auch die Rotationen dürfen beim Übergang zum nächsten Zwischenwert nicht weggelassen werden.

Ein einfaches XOR-HW-Modell erzeugt komplementäre Kandidaten mit gleich großer absoluter Korrelation. Deshalb führen wir **Kandidatenlisten mit Scores**, statt einen frühen Sieger schon als eindeutig extrahiertes Schlüsselwort zu bezeichnen. Spätere Zwischenwerte können Kandidaten voneinander trennen. Vier Byte-Paare einer Spalte ergeben zunächst bis zu 16 mögliche 32-Bit-Zwischenwörter; die folgenden Schritte ordnen diese gemeinsam mit den Hypothesen für das zweite Schlüsselwort.

## 4. Warum K1 und K5 später kommen

In **Spalte 0** steht anstelle eines Nonce-Wortes der feste Counter. Bei festem Schlüssel und Counter sind ihre Zwischenwerte in der ersten Spalten-Quarterround über alle Traces gleich. Die oben beschriebene Pearson-CPA erhält dort keine variierende Vorhersage.

Nach den vier Spalten-Quarterrounds beginnt die **zweite ChaCha-Runde mit diagonalen Quarterrounds**. Hier treffen die vier konstanten, noch unbekannten Wörter aus Spalte 0 jeweils auf Zustandswörter der anderen drei Spalten, die wegen der Nonce zwischen den Traces variieren:

| Diagonale Quarterround | Unbekanntes Wort aus Spalte 0 |
| --- | --- |
| `(0,5,10,15)` | Zustand an Position `0` |
| `(1,6,11,12)` | Zustand an Position `12` |
| `(2,7,8,13)` | Zustand an Position `8` |
| `(3,4,9,14)` | Zustand an Position `4` |

Für eine diagonale Vorhersage berechnen wir aus **jeder noch plausiblen Kombination** von K2–K4 und K6–K8 die benötigten Zustandswörter nach der **vollständigen** ersten Spaltenrunde. Wir müssen nicht alle 16 Matrixwörter gleichzeitig erraten; für jeden gewählten Zwischenwert berechnen wir die konkreten bekannten Operanden. Mit HW-CPA lassen sich dann Kandidaten für die vier unbekannten Wörter der ersten Spalte suchen.

Erst wenn deren Zustand nach der Spaltenrunde hinreichend bestimmt ist, invertieren wir die erste Spalten-Quarterround. Daraus folgen Hypothesen für **K1 und K5**. Die Inversion muss zusätzlich wieder die bekannte Konstante `C0` und den festen Counter liefern; das ist eine Konsistenzprüfung.

## 5. Wie viele Kandidaten bleiben?

Die Anzahl ist ein **Messergebnis**, keine feste Potenz. Wenn in jeder der drei Nonce-Spalten zum Beispiel zwei gemeinsame `(K_oben, K_unten)`-Kandidaten verbleiben, müssen für die diagonale Runde `2 × 2 × 2 = 8` Kombinationen betrachtet werden. Falls dagegen jedes der sechs Wörter unabhängig zwei Möglichkeiten hat, sind es `2^6 = 64`. Die Abhängigkeiten innerhalb einer Spalte müssen bei der Zählung erhalten bleiben.

Ein vollständiger Brute-Force über die zwei noch völlig unbekannten 32-Bit-Wörter K1 und K5 hätte `2^64` Möglichkeiten und ist kein sinnvoller Ersatz für die diagonale CPA. **Wenn alle acht Wörter durch CPA auf kleine Listen reduziert sind**, können die wenigen vollständigen Schlüsselkandidaten anhand eines getrennten Klartext/Chiffrat-Paars geprüft werden. Das funktioniert nur, wenn der richtige Kandidat in den Listen geblieben ist.

## 6. Was die Hardwarearbeit noch zeigen muss

1. **Leakage-Punkte festlegen:** Für jeden der oben genannten Zwischenwerte prüfen, welche 32-Bit-Operation die Firmware tatsächlich ausführt und welches HW-Modell zum Board passt. Die zeitliche Lage und die Erfassung der diagonalen Runde müssen gemessen werden.
2. **Kandidaten über beide Runden führen:** K2/K6, K3/K7 und K4/K8 gemeinsam bewerten, mehrere plausible Kombinationen behalten und die Zustände pro Trace daraus berechnen. Danach die diagonalen Kandidaten und die inverse Quarterround auswerten.
3. **Eigene Messreihe für festen Counter aufnehmen:** Die bisherigen Hardware-Traces nutzten randomisierte Counter. Für den neuen Angriff halten wir Firmware, Takt, Trigger und Counter `1` fest, speichern zufällige Nonces und Traces und überschreiben die alten Dateien nicht.
4. **Tracezahl begründen:** Zuerst prüfen, ob Modell und Zeitfenster überhaupt Korrelation zeigen. Dann dokumentieren, wie Kandidatenränge und Trefferquote mit mehr Traces stabiler werden. Mehr Traces können einen falschen Zwischenwert nicht reparieren.
5. **Blind auswerten und nachprüfen:** Die Kandidatenauswahl darf den bekannten Laborschlüssel nicht verwenden. Danach vergleichen wir Ränge, verbleibende vollständige Schlüssel und die Reproduktion eines separaten Klartext/Chiffrat-Paars. Fehlschläge und Annahmen gehören ins Paper.

## 7. Unser aktueller Stand

Die [rauschfreie Simulation](CPA-Simulation-Runden.md) führt diese Kette bei festem Counter und zufälliger, gespeicherter Nonce vollständig durch und findet im **idealen HW-Modell** alle acht Wörter. Die [bisherige Hardware-Validierung](CPA-Validierung-2026-10-26.md) untersuchte dagegen nur frühe Zwischenwerte mit **randomisiertem Counter**: 14 von 16 richtige Byte-Kandidatenpaare, aber nur 2 von 4 richtige Wortklassen. Sie ist ein Ausgangspunkt für das Leakage-Verständnis, kein Nachweis des hier geplanten vollständigen Hardwareangriffs.
