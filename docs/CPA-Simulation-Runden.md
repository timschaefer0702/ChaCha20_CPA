# Rauschfreie CPA der ersten Spaltenrunde und der diagonalen Runde

Stand: 28. Oktober 2026. Experiment: [`Jupyter/user/cpa_simulated_rounds.py`](../Jupyter/user/cpa_simulated_rounds.py).

## Zuordnung der Schlüsselwörter

Die Bezeichnungen `K1` bis `K8` sind hier **einsbasiert**. `K1` bis `K4` liegen in der zweiten Zustandszeile (`b`), `K5` bis `K8` in der dritten (`c`). Die vier Spalten-Quarterrounds sind `(0,4,8,12)`, `(1,5,9,13)`, `(2,6,10,14)` und `(3,7,11,15)`. In Spalte 0 ist `d` der Block-Counter, in den übrigen drei Spalten je ein 32-Bit-Nonce-Wort.

| Spalte | Erste Schlüsselzeile | Zweite Schlüsselzeile | Öffentliche Eingabe `d` |
| --- | --- | --- | --- |
| 0 | K1 | K5 | Block-Counter |
| 1 | K2 | K6 | Nonce-Wort 0 |
| 2 | K3 | K7 | Nonce-Wort 1 |
| 3 | K4 | K8 | Nonce-Wort 2 |

## Zwei Angriffsstufen innerhalb derselben Quarterround

Zunächst gilt `a1 = (Konstante + b) mod 2^32` und `d1 = d XOR a1`. Der synthetische Trace enthält für jedes Byte `HW8(d1_byte)`. Die erste CPA prüft je Byte 128 komplementäre `a1`-Kandidatenpaare. Vier gewählte Paare ergeben 16 mögliche 32-Bit-`a1`-Wörter.

Für **jedes** dieser 16 Wörter wird danach der tatsächliche ChaCha-Rechenweg weitergeführt: `d2 = rotl32(d1, 16)`, `c1 = (c + d2) mod 2^32`, `b1 = b XOR c1`, wobei `b = (a1 - Konstante) mod 2^32`. Die zweite CPA probiert die vier Bytes von `c` nacheinander und führt dabei die Überträge der 32-Bit-Addition pro Trace fort. Der synthetische Trace enthält hier `HW8` der Bytes von `b1` vor dessen 12-Bit-Rotation. Die Auswahl verwendet nur öffentliche Eingaben und synthetische Leakage; der geheime Testschlüssel wird erst zur Erfolgskontrolle verglichen.

## Feste Counter-Spalte: diagonale Runde

Bei festem Counter ist der komplette Zustand der ersten Spalte nach ihrer Spalten-Quarterround konstant. Nach erfolgreicher Auswahl von K2–K4 und K6–K8 lassen sich die Zustände der drei anderen Spalten für jede Nonce berechnen. Die vier **diagonalen** Quarterrounds mischen diese variierenden, nun bekannten Wörter jeweils mit einem unbekannten Wort aus der ersten Spalte:

| Diagonale Quarterround | Gesuchtes Wort nach der Spaltenrunde | Modellierter Zwischenwert |
| --- | --- | --- |
| `(0,5,10,15)` | `state[0]` | `HW8(state[0] + state[5])` |
| `(1,6,11,12)` | `state[12]` | `HW8(state[12] XOR (state[1] + state[6]))`; späterer XOR-Wert löst die Paare auf |
| `(2,7,8,13)` | `state[8]` | `HW8(state[8] + rotl16(state[13] XOR (state[2] + state[7])))` |
| `(3,4,9,14)` | `state[4]` | `HW8(state[3] + state[4])` |

Die Additionen werden byteweise mit den richtigen Überträgen geprüft. Sind die vier Wörter `state[0,4,8,12]` bestimmt, wird **die vollständige erste Spalten-Quarterround invertiert**. Die Inversion liefert K1 und K5; als unabhängige Konsistenzprüfung müssen zugleich die bekannte ChaCha-Konstante und der feste Counter zurückkommen. Der Angriff setzt an dieser Stelle die zuvor **aus der CPA ausgewählten** sechs anderen Schlüsselwörter ein, nicht den geheimen Testschlüssel.

Zur Kandidatenzahl: `2^6 = 64` gilt nur dann, wenn tatsächlich für jedes dieser sechs Wörter genau zwei Kandidaten verbleiben. Die erste Stufe dieses Skripts hat zunächst **16 S-Wörter pro variierender Spalte**; die zweite Stufe bewertet alle 16 und wählt im idealen Versuch je eines. Die diagonale Stufe bekommt somit eine Kombination aus den drei Spalten. Bei realen Messungen müsste man eventuell mehrere nahe Kandidaten weitertragen und die Anzahl als Produkt ihrer jeweiligen Listenlängen angeben.

## Drei Eingabemuster

Ausführen: `python Jupyter/user/cpa_simulated_rounds.py`. Mit `--seed` und `--traces` sind weitere Versuche reproduzierbar. Beim Standardlauf mit 512 Traces ergibt sich:

| Counter | Nonce-Muster | Frühe Angriffspunkte |
| --- | --- | --- |
| Fest `1` | Alle drei Nonce-Wörter variieren über die Traces | K2/K6, K3/K7 und K4/K8 werden in der Spaltenrunde richtig gewählt; K1/K5 folgen aus der diagonalen Runde und der inversen Spalten-Quarterround. |
| Fest `1` | Fortlaufende Nonce `0,1,...,511` | In diesem kleinen Datensatz ändern sich nur die zwei niederwertigen Bytes des ersten Nonce-Worts. Die Byte-CPA kann daraus kein vollständiges Schlüsselwort bestimmen. |
| Variabel | Alle drei Nonce-Wörter variieren | Auch K1/K5 ist im idealen Modell angreifbar; alle vier Spalten werden gemeinsam richtig gewählt. |

**Warum der feste Counter den Angriff verschiebt:** Bei festem Schlüssel und Counter sind `a1`, `d1`, `c1` und `b1` der ersten Spalte in der Spalten-Quarterround über alle Traces gleich. Eine Pearson-CPA braucht variierende Vorhersagen; hier ist der Nenner null. Ein anderer **fester** Startwert, etwa `0` statt `1`, ändert daran nichts. Die diagonalen Quarterrounds mischen danach Zustandswörter aus anderen Spalten; dadurch können die unbekannten Wörter der ersten Spalte gegen variierende, berechenbare Operanden getestet werden.

**Warum eine frische Nonce nicht automatisch genügt:** Frisch heißt eindeutig, nicht dass alle drei 32-Bit-Wörter oder alle Bytes stark variieren. Ein einfacher fortlaufender Nachrichtenzähler ändert bei 512 Aufrufen nur seine unteren Bytes. Unser künstliches `spread`-Muster verteilt die Variation absichtlich auf alle drei Wörter, um die algebraische Angriffskette getrennt von der Eingabeverteilung zu prüfen. Es ist kein behauptetes reales Protokollverhalten.

## Aussagegrenze

Die Leakage ist hier ausdrücklich **ohne Rauschen und exakt gleich der Angriffshypothese**. Das bestätigt Rechenweg, Kandidatenbehandlung, Rotation, Überträge, Inversion und die Abhängigkeit von variierenden öffentlichen Eingaben. Es belegt weder, dass die Firmware die gewählten Werte byteweise leakt, noch dass reale Stromtraces diese Werte an trennbaren Samples zeigen. Der nächste Schritt ist deshalb ein Vergleich der simulierten Zwischenwerte mit den vorhandenen Hardware-Traces; erst danach wäre eine neue Hardware-Messung sinnvoll.

Für den Counter in ChaCha20-Poly1305 spezifiziert [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439) Block `0` zur Erzeugung des Poly1305-Schlüssels und beginnt die Nutzdatenverschlüsselung bei Block `1`. Der Block-Counter steigt innerhalb einer längeren Nachricht. Unsere Firmware akzeptiert den Counter als frei gesetzten 32-Bit-Wert; die bisherigen Labortraces verwendeten randomisierte Counter. Das ist eine andere Eingabeverteilung als der erste Block jeder Protokollnachricht.
