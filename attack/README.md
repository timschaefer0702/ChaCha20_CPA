# ChaCha20-CPA: aktuelle Arbeitsphase

Stand: 4. November 2026. **Hier beginnen wir mit der nächsten Arbeitsphase.** Die alten Messreihen, das Notebook und ihre Auswertungen bleiben als nachvollziehbare Ergebnisse erhalten. Neue Angriffsskripte und Versuchsprotokolle sollen künftig in `attack/` liegen; bestehende Skripte werden zunächst verlinkt und nicht dupliziert.

## Unsere konkrete Frage

Können wir bei einem festen, unbekannten 256-Bit-Schlüssel, **Counter `1` für den ersten Datenblock** und je Trace einer zufälligen, bekannten Nonce aus ChipWhisperer-Traces erst Kandidaten für K2–K4 und K6–K8, dann für K1 und K5 gewinnen? Wir benutzen Hamming-Gewicht als Leakage-Modell. Die Frage ist für **unsere STM32F3-Firmware und unseren Messaufbau** zu beantworten.

Die [Angriffstheorie](../docs/CPA-Angriffsmodell-und-Ablauf.md) beginnt bei der 4×4-Anfangsmatrix und führt durch Spalten- und diagonale Quarterrounds. Der [Arbeitsplan](PLAN.md) nennt die überprüfbaren nächsten Schritte.

## Was wir bereits haben

| Ergebnis | Aussage | Datei |
| --- | --- | --- |
| Firmware und Hardware-Notebook | ChaCha20 auf CW-Lite/STM32F3; Trigger, Aufnahme und Referenzvergleich funktionieren. | [`firmware/mcu/simpleserial-chacha20/`](../firmware/mcu/simpleserial-chacha20/), [Hardware-Notebook](<../Jupyter/user/ChaCha20 - Test (HARDWARE).ipynb>) |
| Erste Hardware-Messreihe | 1.000 Traces mit randomisiertem Counter und Nonce; Entwicklung von Modell und Samplepunkten. | [`chacha20_traces.npz`](../Jupyter/user/chacha20_traces.npz), [historisches Protokoll](../docs/CPA-Validierungsprotokoll.md) |
| Zweite Hardware-Messreihe | Neuer Schlüssel, wieder randomisierter Counter und Nonce; vorab festgelegter Angriff auf frühe Zwischenwerte. 14/16 richtige Byte-*Paare* und 2/4 richtige 32-Bit-Wortklassen. Kein vollständiger Schlüssel. | [Validierung](../docs/CPA-Validierung-2026-10-26.md), [`cpa_frozen.py`](../Jupyter/user/cpa_frozen.py) |
| Rauschfreie Simulation | Vollständige theoretische Kette mit Counter `1` und zufälliger, gespeicherter Nonce; alle acht Wörter werden bei **exakt angenommener HW8-Leakage** gefunden. | [`cpa_simulated_rounds.py`](../Jupyter/user/cpa_simulated_rounds.py), [Erläuterung](../docs/CPA-Simulation-Runden.md) |

Die zweite NPZ und der getrennte Testschlüssel liegen lokal unter `Jupyter/user/`; sie sind absichtlich nicht im Git-Repository. Die gespeicherten Validierungsprotokolle dokumentieren ihren Hash und die Auswertung.

## Wo unser bisheriger Weg begrenzt war

1. **Andere Counter-Verteilung:** Die alten Hardware-Traces verwenden zufällige Counter. Dadurch ist auch die erste Spalte früh angreifbar. Unser neuer, realitätsnäherer Laborfall setzt den Counter für den ersten Datenblock fest auf `1` und verlagert K1/K5 in die diagonale Runde.
2. **Wortpaare statt fertiger Schlüsselbytes:** Der Betrag der Korrelation unseres frühen XOR-HW-Modells kann globale Komplemente nicht unterscheiden. 14/16 richtige Byte-Paare bedeuten keine 14 eindeutig extrahierten Schlüsselbytes. In der zweiten Messreihe waren nur 2/4 richtige Wortklassen vorn.
3. **Ideale Simulation:** Die synthetische Leakage ist rauschfrei und entspricht exakt der Angriffshypothese. Damit haben wir den Rechenweg geprüft, aber noch nicht die tatsächliche Leakage-Breite, den Instruktionszeitpunkt und die Qualität der Hardware-Traces.
4. **Noch keine zweite Hardware-Stufe:** K5–K8 sowie die diagonalen Modelle für K1/K5 wurden auf gemessenen Traces noch nicht geprüft. Ein vollständiger Schlüssel ist daher gegenwärtig weder gemessen noch aus einer kleinen Kandidatenliste ableitbar.

## Arbeitsregel

Jedes Resultat bekommt eine klare Herkunft: **Simulation**, **explorative Hardwareanalyse** oder **vorab festgelegte Hardwarevalidierung**. Der bekannte Laborschlüssel darf für Diagnose und spätere Erfolgskontrolle genutzt werden; eine als blind ausgewiesene Kandidatenauswahl darf ihn nicht lesen. Änderungen am Modell oder Zeitfenster werden vor einer weiteren unabhängigen Messreihe festgehalten.

**Unmittelbar als Nächstes:** Die HW-Zielwerte der ersten zwei Runden mit dem kompilierten Code und dem 5.000-Sample-Aufnahmefenster abgleichen. Erst wenn Zieloperationen und Fenster plausibel sind, bauen wir die Hardware-CPA für die sechs Nonce-Spaltenwörter weiter. Siehe [Schritt 1 im Plan](PLAN.md#1-hardwaremodell-pruefen).
