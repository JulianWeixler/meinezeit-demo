# MeineZeit – Zeiterfassung & Urlaubsverwaltung

Diese Version unterstützt zwei Betriebsarten:

1. **Lokaler Testbetrieb:** SQLite + Streamlit
2. **Produktivbetrieb:** PostgreSQL + Docker + Caddy/HTTPS

Für einen Kindergarten mit ca. 20 Mitarbeitenden ist der Produktivbetrieb auf einem kleinen VPS ausreichend.

## Lokal testen

```bash
python3 -m pip install -r requirements.txt
python3 -m streamlit run app.py
```

Ohne `DATABASE_URL` verwendet die App SQLite in `daten/zeiterfassung.db`.

## Produktivbetrieb

Siehe **PRODUKTION.md**.

Kurz:

```text
Handy/PC
   ↓ HTTPS
Caddy
   ↓
Streamlit
   ↓
PostgreSQL
   ↓
Backup → externer Cloud-Speicher
```

Die Mitarbeiter benötigen keine lokale Installation.

## Support

Supportkontakt und Supportzeiten werden über `.env` gesetzt:

```text
SUPPORT_KONTAKT=support@deine-domain.de
SUPPORT_ZEITEN=Mo-Fr 18:00-20:00 Uhr
```

Damit muss während deiner normalen Arbeitszeit keine Support-Erreichbarkeit zugesagt werden.

## Bestehende Daten

Die mitgelieferte Migration übernimmt eine vorhandene SQLite-Datenbank nach PostgreSQL:

```bash
export DATABASE_URL='postgresql://...'
python migrate_sqlite_to_postgres.py daten/zeiterfassung.db
```

Die ursprüngliche SQLite-Datei wird nicht verändert.

## Wichtiger Hinweis

Vor einem echten Kundeneinsatz müssen Datenschutz/AVV, Aufbewahrung, Zugriffskonzept, Backup-Wiederherstellung und Vertragsbedingungen geprüft werden. Die technische Konfiguration ersetzt keine rechtliche Prüfung.


SYSTEMADMIN: Das Systemadministrator-Konto ist ein Betreiber-Superuser und erhält automatisch alle Kunden-Admin-Rechte plus technische Wartungsrechte.


AUTOMATISCHE TESTS
------------------
Zwei Testsammlungen prüfen die App vor jeder Auslieferung:

    python3 test_logik.py          # Rechenregeln: Pausen, Feiertage, Saldo ...
    python3 test_oberflaeche.py    # Bedienung: Anmelden, Stempeln, Anträge ...

Die Oberflächentests bedienen die App wie ein Mensch, nur ohne Browser. Jeder
Test arbeitet mit einer eigenen, frischen Datenbank in einem temporären Ordner –
die echten Daten werden nie berührt. Ein Durchlauf dauert einige Minuten.

Empfehlung: Nach jeder Änderung an app.py beide Testsammlungen ausführen.
Erst wenn alles grün ist, an einen Kunden ausliefern.


AENDERUNGSPROTOKOLL
-------------------
Jede Änderung an Arbeitszeiten und Abwesenheiten wird mit altem und neuem Wert,
Benutzer und Zeitpunkt in der Tabelle "aenderungsprotokoll" festgehalten.
Anlegen, Ändern, Löschen, Genehmigen, Ablehnen und Stornieren werden erfasst.
Die App bietet bewusst keine Funktion zum Ändern oder Löschen von
Protokolleinträgen.

Ansicht: Leitung/Admin -> Reiter "Zeiten" -> "Änderungsprotokoll"
(Filter nach Mitarbeiter, Zeitraum und Aktion, Export als CSV).
Mitarbeitende sehen in "Meine Zeiten", wenn die Leitung ihre Einträge geändert hat.
