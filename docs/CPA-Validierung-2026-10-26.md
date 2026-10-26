# Zweite Messreihe: CPA-Validierung

## Vor der Schlüsselkontrolle festgehalten

- Aufnahmezeit laut NPZ: 26. Oktober 2026, 18:34:24 UTC.
- 1.000 Traces × 5.000 Samples, alle endlich; 1.000 verschiedene Nonces.
- Firmware-SHA-256: `361084c757e4e09a0d382da9841bd86604f87c694f35a0912a34c81953ba0376`.
- ADC: `clkgen_x4`, 29.538.459 Hz; Target-Takt: 7.384.615,38 Hz; Offset 0.
- NPZ-SHA-256: `8787ea34301575e5146dc204c63f99fff26905a7ad3f2d7f9e0c8d595968375c`.
- Vorab festgelegter Skript-Commit: `059be2f` auf `fred`; `Jupyter/user/cpa_frozen.py` war bei der Ausführung lokal unverändert.
- Die Auswertung **ohne Schlüsseldatei** wurde als [Roh-Ausgabe](CPA-Validierung-blind-2026-10-26.txt) gespeichert. SHA-256 dieser Ausgabe: `fdcdfc338612f59b73f95a64455e9e7eee89ea481bdddd9acec7c1a081685560`.
- Punkt- und ±4-Fensterregel lieferten für die Wörter 0, 1 und 3 dieselben Kandidatenklassen. Für Wort 2 unterscheiden sich die Kandidatenklassen. Diese Aussage wurde vor Öffnen der Validierungsschlüsseldatei festgehalten.

Die Kandidaten sind 32-Bit-`S`-Wörter beziehungsweise daraus durch `K = S - C mod 2^32` abgeleitete Schlüsselwort-Hypothesen. Jede ausgegebene Klasse enthält zwei globale Komplemente von `S`; auch ein Treffer ist damit noch kein eindeutiges Schlüsselwort.

## Erfolgskontrolle

Erst nach der obigen Aufzeichnung wurde der getrennt gespeicherte Validierungsschlüssel eingelesen. Die [Roh-Ausgabe mit Erfolgskontrolle](CPA-Validierung-mit-Schluessel-2026-10-26.txt) hat SHA-256 `05e4070f2407e7208182cb6e73ba7c3e89973163711e1d70dc9964d830ff6657`.

| Vorab festgelegte Regel | Richtige Byte-Paare auf Rang 1, Training/Test | Richtige 32-Bit-Komplementklassen auf Rang 1, Training/Test |
| --- | ---: | ---: |
| Einzelpunkt | 14/16 · 14/16 | 2/4 · 2/4 |
| Fenster ±4 | 14/16 · 13/16 | 2/4 · 2/4 |

Die Testzahl für Byte-Paare bezeichnet den **Rang des korrekten Paars bei eigenständiger Neubewertung auf den Test-Traces**. Die tatsächlich ausgegebenen Paare wurden zuvor ausschließlich auf Trainings-Traces gewählt. Ihre Übereinstimmung mit dem wahren Paar beträgt für beide Regeln 14/16; die beiden Testzahlen sagen zusätzlich etwas über Stabilität der Ränge aus.

| Wort | Einzelpunkt | Fenster ±4 | Ausschlaggebender Trainingsfehler |
| ---: | --- | --- | --- |
| 0, Counter | richtige Klasse | richtige Klasse | keiner |
| 1, erste Nonce | wahres Wort nicht unter 16 | wahres Wort nicht unter 16 | Byte 3 bei beiden Regeln falsch |
| 2, zweite Nonce | wahres Wort nicht unter 16 | richtige Klasse | Byte 0 nur beim Einzelpunkt falsch |
| 3, dritte Nonce | richtige Klasse | wahres Wort nicht unter 16 | Byte 0 nur beim Fenster falsch |

Sechs über den neuen Datensatz verteilte Klartext/Chiffrat-Paare wurden nach der CPA mit dem separat gespeicherten Schlüssel und pycryptodome nachgerechnet; alle stimmen. Die Schlüsseldatei passt damit zu den gespeicherten Daten.

**Einordnung:** Der neue Schlüssel bestätigt, dass das Modell auf diesem Target auch in einer zweiten Messreihe deutliche Leakage findet. Die festgelegten Regeln erreichen jedoch jeweils nur zwei von vier richtigen Wortklassen. Die Regeln treffen unterschiedliche Wörter; eine nachträgliche Auswahl des jeweils richtigen Resultats anhand des bekannten Schlüssels wäre kein blinder Angriff. Auch eine richtige Klasse lässt zwei `S`-Wörter zu und die angegriffenen vier Wörter bilden nur die erste Hälfte des 256-Bit-Schlüssels. Keine vollständige oder eindeutige Schlüsselrekonstruktion behaupten.

Für den nächsten Versuch erst die Fehlstellen in Wort 1 Byte 3 und die gegensätzlichen Entscheidungen für Wort 2 und 3 untersuchen. Jede daraus abgeleitete Änderung ist eine **neue explorative Phase** und müsste an einer weiteren unabhängigen Messreihe geprüft werden.
