# Arbeitsplan für den ChaCha20-CPA-Versuch auf unserem ChipWhisperer

Stand: 4. November 2026. Dies ist ein **autorisiertes Hochschulprojekt im Modul Advanced IT Security an unserem eigenen ChipWhisperer-Lite mit STM32F3-Target**. Ausgangspunkt und bisherige Grenzen stehen in [README.md](README.md); die 4×4-Matrix und die Gleichungen in der [Angriffstheorie](../docs/CPA-Angriffsmodell-und-Ablauf.md). Dieser Plan beschreibt den **nächsten** Versuch. Das [Validierungsprotokoll von Oktober](../docs/CPA-Validierungsprotokoll.md) gehört zur abgeschlossenen älteren Messreihe.

**Aktueller Schritt: 1. Hardwaremodell prüfen.** Die folgenden Schritte sind keine erledigten Ergebnisse. Jeder Schritt nennt die vorgesehenen Dateien, eine konkrete Implementierungsskizze, die benötigten Eingaben und eine Bedingung für den Übergang zum nächsten Schritt.

## Feste Annahmen

- CW-Lite mit STM32F3 und derselben ChaCha20-Firmware, sofern eine Änderung ausdrücklich dokumentiert wird.
- Ein während der Messreihe fester, unbekannter 256-Bit-Schlüssel. Der Laborschlüssel wird getrennt für die spätere Kontrolle gespeichert.
- Erster Datenblock mit Counter `1`; pro Trace eine neue zufällige Nonce. Counter und Nonce sind öffentliche Eingaben und werden mit jedem Trace gespeichert. Die Nonce wird nicht nach Angriffserfolg ausgewählt.
- **Hamming-Gewicht** als Modellfamilie. Exakter Zwischenwert, Breite und Zeitpunkt werden anhand der Firmware und Messdaten begründet.
- Alte Daten und alte Skripte bleiben als historische Baseline erhalten. Neue Aufnahmen erhalten neue Dateinamen und Hashes.

### Counter, Nonce und die erste Spalte

In der 4×4-Anfangsmatrix steht in der unteren Zeile `(CTR,N0,N1,N2)`. [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439) erlaubt für die ChaCha20-Verschlüsselung einen anfänglichen Block-Counter; **üblich sind `0` oder `1`, nicht ausnahmslos vorgeschrieben**. Bei ChaCha20-Poly1305 verwendet die RFC-Konstruktion Block `0` für den Poly1305-Schlüssel und startet die **Nutzdaten** mit Block `1`. Innerhalb einer längeren Nachricht wird der Counter anschließend für weitere 64-Byte-Blöcke erhöht. Unsere 16-Byte-Laboraufrufe betrachten jeweils den ersten Datenblock und setzen dessen Counter daher fest auf `1`.

Über verschiedene Messungen mit demselben Schlüssel ist damit das Wort `CTR` gleich. Die **erste Spalten-Quarterround** `(0,4,8,12)` sieht zunächst nur `C0`, `K1`, `K5` und `CTR`; alle vier sind in diesem Versuch über die Traces konstant. Eine Pearson-Korrelation ihrer frühen HW-Vorhersagen hat daher keine Variation und kann K1/K5 dort nicht identifizieren. **Der gesamte erste ChaCha-Block ist dennoch nicht konstant:** `N0..N2` ändern sich pro Trace. Sie beeinflussen die drei anderen Spalten und nach deren Mischung die diagonale Runde. Ein fester Startwert `0` statt `1` würde die fehlende Variation in der ersten Spalte nicht beheben.

## Dateistruktur und Wiederverwendung

| Ort | Rolle |
| --- | --- |
| [`Jupyter/user/chacha20_sim.py`](../Jupyter/user/chacha20_sim.py) | Referenz für die vorhandene ChaCha20-Simulation und deren Testvektoren. |
| [`Jupyter/user/cpa_simulated_rounds.py`](../Jupyter/user/cpa_simulated_rounds.py) | Rechenreferenz für die zwei Spaltenstufen, diagonale Stufe und inverse Quarterround. Seine idealen HW8-Traces sind **keine** Hardwaremessung. |
| [`Jupyter/user/cpa_frozen.py`](../Jupyter/user/cpa_frozen.py) | Historisch festgelegte Auswertung der zweiten Messreihe. Nicht stillschweigend für den neuen Versuch umschreiben. |
| [`Jupyter/user/ChaCha20 - Test (HARDWARE).ipynb`](<../Jupyter/user/ChaCha20 - Test (HARDWARE).ipynb>) | Historisches Hardware-Notebook für Aufbau und Aufnahme. Eine neue Aufnahmezelle oder ein neuer Arbeitsablauf bekommt eine eigene Datei. |
| `attack/` | Neue Analyseskripte, Modellübersicht und Ergebnisse dieses Versuchs. Neue Funktionen zunächst hier anlegen; die alte NPZ und das alte Notebook nicht verschieben. |

Vorgesehene neue Dateien, **erst bei Umsetzung des jeweiligen Schritts**: `attack/targets.md` für die Instruktions- und Sampletabelle; `attack/data.py` zum Laden und Prüfen von NPZ-Dateien; `attack/model.py` für ChaCha-Zwischenwerte und HW-Vorhersagen; `attack/rank.py` für Korrelation und Kandidatenlisten; `attack/diagonal.py` für die zweite Runde; `attack/capture_fixed_counter.py` oder ein eigenes Notebook für neue Messungen; `attack/report.py` für Auswertung und Tabellen. Diese Namen sind ein Leitfaden, keine bereits vorhandenen Dateien.

## Datenvertrag für den neuen Code

Die vorhandenen Dateien zeigen das tatsächliche Format. `traces` hat Form `(1000, 5000)` und Typ `float64`; `ctrnonce` hat Form `(1000, 16)` und Typ `uint8`. In `ctrnonce[i, :4]` steht der 32-Bit-Counter im Little-Endian-Format, in `ctrnonce[i, 4:]` die 12-Byte-Nonce. `pt` und `ct` haben Form `(1000, 16)`. Die erste alte NPZ enthält außerdem `key` für die **explorative** Kontrolle. Die zweite NPZ enthält keinen Schlüssel; dieser liegt separat in `chacha20_validation_key.bin`.

`attack/data.py` soll aus `ctrnonce` pro Trace vier öffentliche 32-Bit-Wörter `(CTR,N0,N1,N2)` machen und für neue Daten prüfen: erwartete Formen, endliche Samples, Counter überall `1`, gespeicherte Nonces, Firmware-Hash, Takt- und Samplemetadaten. Die erste Aufgabe kann mit `np.frombuffer`/`np.fromfile` oder `np.ndarray.view('<u4')` gelöst werden; dabei die Byte-Reihenfolge ausdrücklich durch einen bekannten RFC-Testvektor prüfen. Die alte NPZ wird mit einem **anderen Modus** geladen, weil dort Counter zufällig ist und Metadaten fehlen.

Für die Angriffsberechnung bleibt der Testschlüssel außerhalb von `load_public_traces(...)`. Eine getrennte Funktion `validate_with_lab_key(...)` darf ihn erst nach gespeicherter Kandidatenauswahl öffnen. Das macht die Unterscheidung zwischen explorativer Diagnose und blinder Prüfung auch im Code sichtbar.

## 1. Hardwaremodell prüfen

**Jetzt an der Reihe.** Die C-Operationen und den tatsächlich geflashten Build für die ersten vier Spalten- und vier diagonalen Quarterrounds auflisten. Für jeden vorgesehenen HW-Zwischenwert festhalten: mathematische Formel, beteiligte Zustandsindizes, möglicher Registerwert vor/nach Rotation, Byte- oder 32-Bit-Breite und erwartetes Aufnahmefenster. Die vorhandenen 5.000-Sample-Traces darauf prüfen, ob sie die diagonale Runde überhaupt enthalten.

**Umsetzung im Code und in der Analyse:**

1. In `firmware/mcu/simpleserial-chacha20/chacha20.c` die Reihenfolge der acht Quarterrounds und innerhalb jeder Quarterround die vier Paare aus Addition sowie XOR/Rotation erfassen. Die 4×4-Zustandsindizes aus der [Theorie](../docs/CPA-Angriffsmodell-und-Ablauf.md) daneben schreiben. Als ersten Kandidaten für eine Spalte `HW(d XOR (Konstante + K_oben))` und als späteren Kandidaten den Wert nach `c += d` beziehungsweise `b ^= c` notieren.
2. Das vorhandene Firmware-HEX und den im historischen [Protokoll](../docs/CPA-Validierungsprotokoll.md) festgehaltenen Hash zuordnen. Die dort bereits dokumentierten Instruktionen `add`, `eors`, Rotation und Speichern für den ersten Angriffspunkt sind ein Startpunkt; für den späteren Punkt und die diagonale Runde fehlt diese Zuordnung noch. Wenn ein neuer Build nötig wird, neue Hashes und neue Samplekalibrierung verwenden.
3. In `attack/targets.md` pro Zieloperation eine Zeile mit `Runde`, `Quarterround`, `Zustandsindizes`, `Ausdruck`, `Instruktion`, `HW8/HW32`, `Samplebereich` und `Beobachtungsstatus` anlegen. „Im C-Code vorhanden“ und „als Leakage in Traces sichtbar“ sind zwei verschiedene Beobachtungen.
4. Ein kleines Leseskript für die alten NPZ-Dateien soll die Traces nach ihrer Sampleachse zusammenfassen und die bekannten ersten Fenster um `726`, `1069`, `1262`, `1518` als Orientierung markieren. Danach gezielt prüfen, ob die **späteren** Operationen der Spaltenrunde und die **diagonalen** Quarterrounds noch innerhalb der 5.000 Samples liegen. Die alten Samples nicht automatisch auf den neuen festen-Counter-Datensatz übertragen.
5. Für jeden Kandidatenwert die Vorhersage als Vektor `modell[i]` über alle Traces berechnen und mit einem Zeitbereich `traces[:, start:stop]` korrelieren. `HW(C + K)` allein ist bei festem Schlüssel über alle Traces konstant und daher kein brauchbarer Pearson-Angriffspunkt. Die Variation kommt beim frühen XOR über `N0..N2` und später über die gemischten Zustandswörter.

**Ergebnis:** Eine Tabelle `Zustandswert → Instruktion → Samplebereich → Modellbreite` samt Firmware-Hash und nachvollziehbarer Begründung. Falls ein Zielwert nur als Annahme vorhanden ist, wird er so markiert.

**Entscheidung:** Wir gehen erst zur Hardware-Kandidatensuche über, wenn mindestens ein plausibler früher und ein plausibler späterer Zielpunkt im Aufnahmefenster stehen. Andernfalls passen wir die Aufnahmelänge oder das Zielmodell vor einer neuen Messung an.

## 2. Angriffscode für Kandidatenlisten vorbereiten

Die vorhandene [rauschfreie Simulation](../Jupyter/user/cpa_simulated_rounds.py) als Rechenreferenz nutzen. Der neue Angriffscode soll pro Spalte **mehrere gemeinsame** `(K_oben,K_unten)`-Kandidaten samt Korrelation behalten. Die 32-Bit-Addition muss Überträge über Bytegrenzen, die Quarterround muss alle Rotationen exakt berücksichtigen. Gleichwertige Komplementkandidaten bleiben sichtbar.

**Umsetzung im Code:**

1. `attack/model.py`: `rotl32(x,n)`, `hw8(x)`, `hw32(x)`, `initial_state(key_candidates, public_words)` und `quarterround(...)` aus der vorhandenen Simulation ableiten. Für die Angriffsfunktionen nur die **benötigten** unbekannten Wörter als Parameter übergeben. Der unbekannte Laborschlüssel darf nicht im Modellcode importiert werden. Gegen die vorhandenen RFC-Testvektoren und `chacha20_sim.py` prüfen, ob Rotation, Little Endian und Addition modulo `2^32` stimmen.
2. Erste Stufe für Spalten `1,2,3`: `S = (C_j + K_oben) mod 2^32`, `u_i = N_{j-1,i} XOR S`. Für jedes hypothetische Byte `g` den Vektor `HW8(N_byte XOR g)` berechnen. `cpa_frozen.py` enthält mit `HW8`, `correlation(...)` und der Vektorisierung einen vorhandenen Ausgangspunkt. Der neue Code muss **mehrere** Byte-Paare und daraus mehrere `S`-Wörter mit Scores behalten; `K_oben = (S - C_j) mod 2^32` erst über das ganze Wort berechnen.
3. Zweite Stufe je Spalte: Für jedes weitergereichte `S` und jeden Trace `d1_i = rotl32(N_i XOR S,16)` berechnen. Dann Hypothesen für `K_unten` in `c1_i = (K_unten + d1_i) mod 2^32` und einen tatsächlich messbaren späteren Wert aus `b1_i = rotl32(K_oben XOR c1_i,12)` aufstellen. Wenn Byte für Byte gesucht wird, den Übertrag von Byte `j` nach `j+1` pro Trace fortführen. `second_stage(...)` in `cpa_simulated_rounds.py` zeigt diese Rechenabhängigkeit, wählt momentan aber nur **einen** Bytewert je Stufe; für Hardware werden Listen und Ränge benötigt.
4. `attack/rank.py`: Modellmatrix und Traces spaltenweise zentrieren, Pearson-Korrelation je Hypothese und Sample berechnen, konstante Modellvektoren als nicht auswertbar markieren. Beim frühen XOR die Vorzeichen- beziehungsweise Komplementäquivalenz explizit ausgeben. Für jeden Kandidaten `Wert`, `Score`, `Sample/Fenster`, `Rang` und `Elternkandidat` speichern. Die Score-Regel und die Zahl der weitergereichten Kandidaten werden für eine unabhängige Messreihe vorher festgelegt.
5. Auf synthetischen Traces mit einem **anderen** zufälligen Schlüssel als dem Entwicklungsschlüssel prüfen, ob der echte Wert in den Listen bleibt. Anschließend die beiden alten Hardware-Dateien nur explorativ nutzen: Die erste enthält den Testschlüssel direkt, die zweite separat; beides darf bei der **Entwicklung** zur nachträglichen Diagnose dienen, aber nicht als unabhängiger Erfolg einer neu gewählten Regel berichtet werden.

**Ergebnis:** Reproduzierbare Ausgabe von Kandidatenlisten, Scores und Anzahl der Kombinationen, zuerst auf synthetischen Traces mit bekanntem Schlüssel. Danach einmal mit der alten Hardware-Messreihe **explorativ** prüfen, ob der richtige Kandidat bei K2/K6, K3/K7 und K4/K8 überhaupt in den weitergereichten Listen liegt.

**Entscheidung:** Wenn der wahre Wert bereits aus den Listen fällt, verbessern wir Modell oder Fenster und dokumentieren das als neue explorative Regel. Mehr Tracezahl allein wird nicht als Erklärung angenommen.

## 3. Diagonale Angriffsstufe vorbereiten

Für jede weitergereichte Kombination der sechs Wörter und für jeden Trace den Zustand **nach den vier vollständigen Spalten-Quarterrounds** berechnen. Die HW-Zwischenwerte der vier diagonalen Quarterrounds für die vier unbekannten Wörter aus Spalte 0 vorhersagen. Kandidaten für diese vier Zustandswörter kombinieren und die erste Spalten-Quarterround invertieren; nur konsistente Ergebnisse für Konstante und Counter weiterreichen.

**Umsetzung im Code:**

1. `attack/diagonal.py` soll gemeinsame Spaltenkandidaten aus Schritt 2 übernehmen, also etwa Listen für `(K2,K6)`, `(K3,K7)` und `(K4,K8)`. Die Zahl der Eingangskombinationen ist das **Produkt der drei Listenlängen**. Nicht aus sechs isolierten Wortlisten den Zustand zusammensetzen, wenn die Wörter einer Spalte nur gemeinsam plausibel sind.
2. Für jede Eingangskombination und jeden Trace die drei vollständig bekannten Spalten durch **alle acht Updates ihrer ersten Quarterround** rechnen. Der vorhandene `column_state(...)` in `cpa_simulated_rounds.py` ist die Rechenreferenz. K1/K5 bleiben an diesem Punkt unbekannt; keine Werte aus der Testschlüsseldatei einsetzen. Die vier unbekannten Wörter der ersten Spalte nach ihrer Quarterround als `U0,U4,U8,U12` benennen.
3. Die vier diagonalen Quarterrounds `(0,5,10,15)`, `(1,6,11,12)`, `(2,7,8,13)` und `(3,4,9,14)` verwenden jeweils eines dieser `U`-Wörter zusammen mit bekannten, nonceabhängigen Operanden. `diagonal_leakage(...)`, `recover_addend(...)` und `recover_d12(...)` in der Simulation zeigen mögliche mathematische HW-Ziele. Im Hardwarecode nur die Ziele übernehmen, deren **tatsächliche** Leakage und Sampleposition in Schritt 1 gestützt wurden.
4. Kandidaten für `U0,U4,U8,U12` mit ihren Eingangskombinationen verknüpfen. `inverse_quarterround(...)` führt daraus zurück zur ersten Spalte des **Anfangszustands**; die Schlüsselwörter an den Positionen 4 und 8 sind K1 und K5. Die anderen rückgerechneten Wörter müssen `C0` und dem festen Counter entsprechen. Die Inversion vor dem Einsatz auf Hardwaredaten gegen direkte Quarterround-Rechnungen für mehrere Zufallszustände prüfen.
5. Eine vollständige Kandidatenstruktur soll die Herkunft erhalten, beispielsweise `((K2,K6),(K3,K7),(K4,K8),(U0,U4,U8,U12),(K1,K5),scores)`. Wenn die Zahl zu groß wird, Kandidaten nach einer **vorher festgelegten** Regel begrenzen und die verworfenen Ränge dokumentieren. Ein „Treffer“ darf nicht aus dem bekannten Schlüssel für die günstigste Kombination herausgesucht werden.

### Konkrete Zustandsabhängigkeiten der diagonalen Runde

Für einen Trace `i` sei `Xj_i` das Zustandswort an Position `j` **nach der vollständigen Spaltenrunde**. Die bekannten Spalten `(1,5,9,13)`, `(2,6,10,14)` und `(3,7,11,15)` werden für jeden öffentlichen Nonce-Wert und jede weitergereichte Sechs-Wort-Kombination neu berechnet. Nur die erste Spalte bleibt als `U0=X0`, `U4=X4`, `U8=X8`, `U12=X12` unbekannt. Diese vier Wörter sind wegen des festen Counters und Schlüssels über die Traces konstant, ihre Partner aus den anderen Spalten variieren mit der Nonce.

Die vier diagonalen Quarterrounds benutzen getrennte Zustandspositionen. Für ihre **ersten Updates** ergeben sich mögliche HW-Hypothesen; `+` meint Addition modulo `2^32`, `rotl` eine 32-Bit-Rotation:

| Diagonale Quarterround | Erstes hypothesiertes Zwischenwort | Unbekanntes Wort | Variierender, berechneter Anteil |
| --- | --- | --- | --- |
| `(0,5,10,15)` | `A_i = U0 + X5_i` | `U0` | `X5_i` |
| `(1,6,11,12)` | `V_i = U12 XOR (X1_i + X6_i)`; danach `D_i = rotl(V_i,16)` | `U12` | `X1_i + X6_i` |
| `(2,7,8,13)` | `D_i = rotl(X13_i XOR (X2_i + X7_i),16)`; danach `C_i = U8 + D_i` | `U8` | `D_i` |
| `(3,4,9,14)` | `A_i = X3_i + U4` | `U4` | `X3_i` |

Das sind **mathematische Angriffspunkte, noch keine bestätigten Hardware-Leakages**. Für `U12` verwendet die vorhandene Simulation `HW8(V_i)`, also den XOR-Wert **vor** der Rotation; `D_i` bezeichnet erst den folgenden rotierten Wert. In `attack/targets.md` für jeden prüfen, ob die Firmware das ganze Wort oder ein Byte davon im beobachteten Zeitfenster verarbeitet; erst dann `HW8` oder `HW32` und die relevante Byteposition festlegen. Ein guter synthetischer Score ersetzt diese Prüfung nicht. Als zweites, unabhängiges Ziel pro Quarterround kann ein späterer Wert nach `c += d` oder `b ^= c` helfen, gleichwertige Kandidaten zu unterscheiden.

In `attack/diagonal.py` pro Sechs-Wort-Hypothese zunächst die `Xj_i`-Arrays für alle Traces berechnen. Dann für die vier `U`-Wörter Kandidatenvektoren nach obigen Formeln erzeugen, mit **denselben vorab festgelegten** Zeitfenstern korrelieren und mehrere Rangplätze behalten. Die Kombinationen bilden gemeinsame Zustände `(U0,U4,U8,U12)`; einzelne hohe Scores dürfen nicht stillschweigend als ein eindeutiger Zustand ausgegeben werden.

### Rückrechnung zur Anfangsmatrix

Auf jeden vollständigen `U`-Kandidaten die inverse **erste Spalten-Quarterround** anwenden. Bei Ausgabe `(a,b,c,d)=(U0,U4,U8,U12)` werden die acht Updates in umgekehrter Reihenfolge zurückgenommen:

```text
b = rotr(b, 7) XOR c
c = c - d
d = rotr(d, 8) XOR a
a = a - b
b = rotr(b, 12) XOR c
c = c - d
d = rotr(d, 16) XOR a
a = a - b
```

Alle Subtraktionen erfolgen modulo `2^32`. Das Ergebnis muss `(C0,K1,K5,CTR)` sein. `C0` ist die bekannte ChaCha-Konstante, `CTR` in dieser Messreihe `1`; diese beiden Gleichheiten sind **Konsistenzbedingungen**, keine anhand des Laborschlüssels gewählten Treffer. Nur dann werden `b` und `c` als K1-/K5-Kandidaten weitergereicht. Vor der Hardwareauswertung `inverse_quarterround(quarterround(state)) == state` für mehrere bekannte Zufallszustände prüfen und die Indexreihenfolge gegen die Firmware kontrollieren.

### Was für diese Stufe noch fehlt

| Benötigt | Stand und konkrete nächste Prüfung |
| --- | --- |
| Drei gemeinsame Wortpaare für K2/K6, K3/K7, K4/K8 | Die alte Hardwareanalyse lieferte vor allem Byte-Paare; der richtige 32-Bit-Wert war nur bei zwei von vier Wörtern führend. Kandidatenlisten mit Elternbezug und Überträgen neu implementieren und auf alten Daten explorativ prüfen. |
| Belastbares Modell für die vier diagonalen Ziele | C-Instruktion, Registerwert, HW-Breite und Samplefenster sind noch nicht für alle vier Ziele belegt. `attack/targets.md` und den Piloten dafür nutzen. |
| Ausreichendes Aufnahmefenster | Prüfen, ob alle vier diagonalen Zieloperationen in 5.000 Samples liegen. Falls nicht, neue Aufnahme mit dokumentierter Länge/Offset; alte Samples nicht umdeuten. |
| Fester Counter, zufällige Nonces | Die alten Hardwaredateien hatten einen variierenden Counter. Eine neue, separat gespeicherte ChipWhisperer-Reihe mit `CTR=1` wird für dieses Szenario benötigt. |
| Zahl der Traces und Kandidatenbudget | Pilot und Teildatensätze mit steigender Tracezahl auswerten; Rangstabilität, Laufzeit und Kandidatenverlust messen. Die nötige Zahl steht noch nicht fest. |
| Unabhängige Erfolgsprüfung | Regeln vor einer neuen Reihe mit anderem Schlüssel fixieren; Kandidaten ohne Schlüsselzugriff erzeugen und erst danach gegen Laborschlüssel und getrenntes Ein-/Ausgabepaar prüfen. |

Wenn die Diagonale trotz korrekter früher Kandidaten scheitert, zuerst Zielwert, Zeitlage und Wortbreite prüfen. Wenn ein früher richtiger Kandidat bereits aus der Liste fiel, hilft die diagonale Rechnung nicht; dort muss die Liste oder das Modell verbessert werden. Beide Fälle getrennt protokollieren.

**Ergebnis:** K1/K5-Kandidaten und ihre Abhängigkeit von den sechs früheren Wortkandidaten, zuerst in der Simulation. Mit alten Hardware-Traces nur explorative Machbarkeit prüfen. Das Skript soll ausgeben, wie viele vollständige Schlüsselhypothesen entstehen; keine implizite Annahme `2^6`.

## 4. Neue Hardware-Messreihe mit festem Counter

Wenn die Zielzeitpunkte und Modelle feststehen: Aufnahme mit Counter `1`, zufälliger bekannter Nonce und einem festen Laborschlüssel. Firmware, Takte, Trigger, Samplezahl, Fehler, Dateinamen und SHA-256 protokollieren. Einen kleinen Piloten für Signal und Zeitfenster verwenden; die endgültige Tracezahl anhand der beobachteten Rangstabilität und verfügbaren Aufnahmezeit wählen. Die zwei alten NPZ-Dateien bleiben unangetastet.

**Umsetzung an unserem ChipWhisperer:**

1. Die Setup- und Referenzprüfungen des vorhandenen Hardware-Notebooks wiederverwenden. Für den neuen Versuch eine eigene Aufnahmezelle oder `attack/capture_fixed_counter.py` anlegen. Der entscheidende Eingabeunterschied zur alten Zelle ist `ctr = 1` **bei jedem Trace**; `nonce = os.urandom(12)` bleibt zufällig und wird gespeichert. Der Schlüssel wird **einmal vor der Schleife** erzeugt und gesetzt.
2. Vor dem ersten Trace Firmware-Hash, Plattform `CWLITEARM`, Target- und ADC-Takt, `scope.adc.samples`, `scope.adc.offset` und Trigger prüfen. Die alte Messung verwendete 5.000 Samples; falls Schritt 1 zeigt, dass die diagonale Runde später liegt, die Aufnahmelänge bewusst erhöhen und die neue Länge in NPZ und Plan dokumentieren. Einen Zeitausschnitt nicht nachträglich als identisch mit den alten Samples bezeichnen.
3. Pro Trace `ctrnonce`, Messvektor, Klartext und Chiffrat speichern. Die Firmware-Antwort gegen `pycryptodome` und die ChaCha-Simulation prüfen; bei Timeout, falscher Antwort oder fehlendem ACK den Fehler zählen und den Trace nicht als gültig übernehmen. Für den Piloten zunächst Zeitlage und Qualität prüfen, dann die Aufnahmebedingungen für die größere Reihe festhalten.
4. Neue Dateinamen wie `attack/data/fixed_ctr1_pilot_YYYY-MM-DD.npz` und `attack/data/fixed_ctr1_run01_YYYY-MM-DD.npz` wählen; vor jedem Schreiben Existenz prüfen und nicht überschreiben. Schlüssel getrennt in einer lokalen, ignorierten Datei speichern. Die NPZ erhält dieselben Kernfelder `traces`, `ctrnonce`, `pt`, `ct` sowie Firmware-Hash, Takte, Samplezahl, Offset, UTC-Zeit und eine kurze Versuchskennung. Binärdaten und Schlüssel werden nicht ins Git-Repository aufgenommen.
5. Die Anzahl gültiger Traces, Nonce-Eindeutigkeit und `counter == 1` unmittelbar nach der Speicherung prüfen. SHA-256 der Messdatei ins Versuchsprotokoll schreiben. Eine Pilotmessung kann nach Modelländerungen weiter explorativ sein; die spätere unabhängige Validierung braucht eine neue Reihe mit neuem Schlüssel und zuvor festgelegten Regeln.

**Ergebnis:** Neuer Datensatz und getrennte Schlüsseldatei. Vor einer späteren **unabhängigen** Messreihe die endgültigen Regeln für Modell, Fenster, Kandidatenzahl und Auswertung schriftlich fixieren.

## 5. Hardware-CPA und unabhängige Prüfung

Die festgelegten Regeln ohne Zugriff auf den Laborschlüssel ausführen. Für jede Stufe Kandidatenlisten, Korrelationen, Ränge auf getrennten Traces und die Anzahl vollständiger Schlüsselhypothesen speichern. Erst danach den Laborschlüssel zur Erfolgskontrolle öffnen. Ein vollständiger Kandidat muss außerdem ein separates Klartext/Chiffrat-Paar reproduzieren.

**Umsetzung im Auswerteskript:**

1. Eine Kommandozeile mit `--data`, `--config` und optionalem `--validation-key-file` vorsehen. `--config` enthält Firmware-Hash, Modellnamen, Fenster, Zahl der Kandidaten je Stufe und Traceaufteilung. Ohne die Schlüsseloption muss der gesamte Angriff laufen und die vollständigen Kandidatenlisten sowie einen Hash der Ausgabe speichern.
2. Eine feste Aufteilung wie gerade/ungerade Traceindizes oder zwei getrennte Messreihen verwenden. Kandidaten und Zeitfenster ausschließlich mit dem Entwicklungsteil wählen; auf dem Testteil die **gleichen** Hypothesen und Fenster auswerten. Eine Regel, die nach Einsicht in den Testschlüssel geändert wird, ist wieder explorativ.
3. Für jede Stufe getrennt berichten: Ist der richtige Bytewert in der Liste? Ist das richtige 32-Bit-Wort in der Liste? Welchen Rang hat es? Wie viele gemeinsame Spaltenkombinationen erreichen die Diagonale? Wie viele vollständige Schlüssel bleiben nach Inversion und Konsistenzprüfung? Diese Zahlen sind verschieden von „eindeutiger Schlüssel extrahiert“.
4. Erst nach Speichern der blinden Ausgabe die getrennte Schlüsseldatei öffnen und die Ränge nachtragen. Die endgültigen Schlüsselkandidaten zusätzlich mit einem **nicht zur Kandidatenauswahl benutzten** Klartext/Chiffrat-Paar verifizieren. Kandidatenmenge, Zeitaufwand und Fehlstellen auch dann berichten, wenn kein vollständiger Schlüssel gefunden wird.

**Ergebnis:** Klar getrennte Zahlen für richtige Byte-Paare, richtige Wörter, vollständige Kandidaten und eindeutig verifizierten Schlüssel. Wenn die Regel nach dem ersten Versuch geändert wird, ist dieser Versuch wieder Entwicklung; eine neue Messreihe ist für die erneute unabhängige Prüfung nötig.

## 6. Kandidatenprüfung und Paper

Nur wenn **alle acht Wörter** in kleinen Kandidatenlisten vertreten sind, vollständige Schlüssel kombinieren und gegen bekannte Ein-/Ausgaben prüfen. Falls K1/K5 völlig unbekannt bleiben, wären `2^64` Möglichkeiten offen; das ist kein realistischer Abschluss unseres Laborversuchs.

Im Paper die 4×4-Matrix, die gewählten Leakage-Punkte, die tatsächlichen Messbedingungen, die Kandidatenabhängigkeiten, die Tracezahl, Erfolge und Fehlstellen darstellen. Ergebnisse der alten zufälligen-Counter-Reihen, der idealen Simulation und der neuen festen-Counter-Reihe getrennt ausweisen.

**Konkrete Ausgaben für das Paper:** Eine Tabelle der HW-Zielwerte und Samplefenster, ein Diagramm des Zustandsflusses von Spalten- zu diagonaler Runde, Korrelation/Rang gegen Tracezahl, Kandidatenanzahl nach jeder Stufe sowie eine Tabelle mit Simulation, explorativer Hardwareanalyse und unabhängiger Hardwarevalidierung. Als Grenzen ausdrücklich die angenommene Leakage-Breite, Sampleauswahl, feste Counter-Position, zufällige bekannte Nonces und die Abhängigkeit der Diagonale von richtigen früheren Kandidaten nennen.

## Reihenfolge ab heute

1. **Als Erstes:** `attack/targets.md` mit den konkreten Instruktionen und möglichen Samples erstellen; dabei nur die vorhandene Firmware und alten Traces lesen. ChipWhisperer muss dafür nicht angeschlossen sein.
2. **Danach:** Das synthetische Modell an den tatsächlich beobachtbaren Registerwert und die gewählte HW-Breite anpassen. Mehrere Kandidaten statt nur des besten weiterreichen.
3. **Erst dann:** Pilot auf dem ChipWhisperer mit festem Counter `1` und zufälliger gespeicherter Nonce aufnehmen. Aufnahmelänge und Tracezahl aus den vorherigen Prüfungen ableiten.
4. **Zum Schluss:** Regeln einfrieren, neue unabhängige Messreihe auswerten, Kandidaten verifizieren und das Paper schreiben.
