"""
Automatische Oberflächentests für MeineZeit.

Diese Tests bedienen die App wie ein Mensch – Anmelden, Stempeln, Zeiten
eintragen, Anträge stellen und entscheiden – nur ohne Browser. Sie fangen genau
die Fehler ab, die eine reine Code-Prüfung nicht findet: Abstürze, die erst beim
Klicken entstehen, weil Widget-Zustände nicht zusammenpassen.

Ausführen (im App-Ordner):
    python3 test_oberflaeche.py

Jeder Test startet mit einer eigenen, frischen Datenbank in einem temporären
Ordner. Deine echten Daten werden nie berührt.
"""

from __future__ import annotations

import ast
import os
import shutil
import sqlite3
import sys
import tempfile
import traceback
from datetime import date, datetime, time, timedelta
from pathlib import Path

# Nur für Testumgebungen ohne installiertes Streamlit: zusätzlicher Suchpfad
if os.getenv("MEINEZEIT_TEST_EXTRA_PATH"):
    sys.path.append(os.environ["MEINEZEIT_TEST_EXTRA_PATH"])

import pandas as pd
from streamlit.testing.v1 import AppTest


def _tabellen_ersatz_falls_noetig() -> bool:
    """Ersatz für Tabellen, wenn pyarrow fehlt (nur in reinen Testumgebungen).

    Streamlit zeichnet Tabellen über pyarrow. Fehlt es, werden st.dataframe und
    st.data_editor durch Platzhalter ersetzt: Tabellen erscheinen dann nicht,
    der gesamte übrige App-Ablauf wird aber echt durchlaufen. Mit normal
    installiertem Streamlit greift dieser Ersatz nicht.
    """
    try:
        import pyarrow  # noqa: F401
        return False
    except ImportError:
        pass
    import streamlit as _st
    from streamlit.delta_generator import DeltaGenerator

    def _dataframe(self, data=None, *args, **kwargs):
        return None

    def _data_editor(self, data=None, *args, **kwargs):
        if hasattr(data, "data"):          # Styler -> zugrunde liegende Daten
            data = data.data
        return data.copy() if hasattr(data, "copy") else data

    DeltaGenerator.dataframe = _dataframe
    DeltaGenerator.data_editor = _data_editor
    _st.dataframe = lambda *a, **k: None
    _st.data_editor = lambda data=None, *a, **k: _data_editor(None, data)
    return True


TABELLEN_ERSATZ = _tabellen_ersatz_falls_noetig()


def _auswahlfeld_schwaeche_abfangen() -> None:
    """Umgeht eine Schwäche von AppTest bei Auswahlfeldern mit format_func.

    AppTest übernimmt bei manchen Auswahlfeldern die Beschriftungsfunktion nicht
    und vergleicht dann den Rohwert (z. B. "a.mueller") mit den beschrifteten
    Optionen ("a.mueller · Anna Müller"). Das wirft einen ValueError, obwohl die
    App korrekt ist – der Browser arbeitet mit Positionen, nicht mit Texten.
    In diesem Fall bleibt das Feld einfach auf seinem Standardwert.
    """
    from streamlit.testing.v1 import element_tree as _et
    urspruenglich = _et.Selectbox.index.fget

    def index(self):
        try:
            return urspruenglich(self)
        except ValueError:
            return None

    _et.Selectbox.index = property(index)


_auswahlfeld_schwaeche_abfangen()

APP_ORDNER = Path(__file__).resolve().parent
START_PW = "Start-Test-2026"
NEUES_PW = "NeuesPasswort-2026"
SYS_PW = "Systemadmin-Test-2026!"
TIMEOUT = 90

os.environ["MEINEZEIT_START_PASSWORD"] = START_PW
os.environ["MEINEZEIT_SYSTEMADMIN_PASSWORD"] = SYS_PW


# ================================================================ Hilfen

class Umgebung:
    """Frische App-Kopie mit eigener Datenbank in einem temporären Ordner."""

    def __init__(self):
        self.ordner = Path(tempfile.mkdtemp(prefix="meinezeit_test_"))
        for datei in ("app.py", "logik.py"):
            shutil.copy(APP_ORDNER / datei, self.ordner / datei)
        if (APP_ORDNER / ".streamlit").exists():
            shutil.copytree(APP_ORDNER / ".streamlit", self.ordner / ".streamlit")

    @property
    def db(self) -> Path:
        return self.ordner / "daten" / "zeiterfassung.db"

    def app(self) -> AppTest:
        at = AppTest.from_file(str(self.ordner / "app.py"), default_timeout=TIMEOUT)
        at.run()
        return at

    def sql(self, befehl: str, werte=()) -> None:
        with sqlite3.connect(self.db) as conn:
            conn.execute(befehl, werte)
            conn.commit()

    def lesen(self, abfrage: str, werte=()) -> pd.DataFrame:
        with sqlite3.connect(self.db) as conn:
            return pd.read_sql(abfrage, conn, params=werte)

    def aufraeumen(self) -> None:
        shutil.rmtree(self.ordner, ignore_errors=True)


def ohne_ausnahme(at: AppTest, schritt: str) -> None:
    if at.exception:
        meldungen = "\n".join(e.message[:400] for e in at.exception)
        raise AssertionError(f"Ausnahme bei '{schritt}':\n{meldungen}")


def knopf(at: AppTest, text: str):
    for b in at.button:
        if text.lower() in str(b.label).lower():
            return b
    raise AssertionError(f"Knopf '{text}' nicht gefunden. Vorhanden: {[b.label for b in at.button]}")


def textfeld(at: AppTest, text: str):
    for f in at.text_input:
        if text.lower() in str(f.label).lower():
            return f
    raise AssertionError(f"Textfeld '{text}' nicht gefunden. Vorhanden: {[f.label for f in at.text_input]}")


def anmelden(at: AppTest, benutzer: str, passwort: str = START_PW,
             neues_passwort: str = NEUES_PW) -> AppTest:
    """Meldet an und erledigt einen erzwungenen Passwortwechsel."""
    textfeld(at, "Benutzername").input(benutzer)
    textfeld(at, "Passwort").input(passwort)
    knopf(at, "Anmelden").click()
    at.run()
    ohne_ausnahme(at, f"Anmeldung {benutzer}")
    labels = [str(f.label) for f in at.text_input]
    if any("Neues Passwort" in l for l in labels):
        textfeld(at, "Neues Passwort wiederholen").input(neues_passwort)
        [f for f in at.text_input if str(f.label) == "Neues Passwort"][0].input(neues_passwort)
        knopf(at, "Passwort speichern").click()
        at.run()
        ohne_ausnahme(at, "Passwortwechsel")
    return at


def zur_leitung_machen(u: Umgebung, benutzer: str) -> None:
    u.sql('UPDATE benutzer SET "Rolle" = ? WHERE "Benutzername" = ?', ("Leitung / Admin", benutzer))


def branche_setzen(u: Umgebung, branche: str) -> None:
    import json
    u.sql('INSERT INTO einstellungen ("Schluessel", "Wert") VALUES (?, ?) '
          'ON CONFLICT("Schluessel") DO UPDATE SET "Wert" = excluded."Wert"',
          ("branche", json.dumps(branche)))


def reiter(at: AppTest) -> list[str]:
    return [str(t.label) for t in at.tabs]


# ================================================================ Tests: Anmeldung

def test_anmeldeseite_laedt():
    u = Umgebung()
    try:
        at = u.app()
        ohne_ausnahme(at, "Start")
        textfeld(at, "Benutzername"); textfeld(at, "Passwort"); knopf(at, "Anmelden")
    finally:
        u.aufraeumen()


def test_falsches_passwort_zeigt_fehler():
    u = Umgebung()
    try:
        at = u.app()
        textfeld(at, "Benutzername").input("a.mueller")
        textfeld(at, "Passwort").input("ganz-falsch-123")
        knopf(at, "Anmelden").click(); at.run()
        ohne_ausnahme(at, "falsches Passwort")
        assert any("falsch" in str(e.value).lower() for e in at.error), "Keine Fehlermeldung angezeigt"
    finally:
        u.aufraeumen()


def test_erster_login_erzwingt_passwortwechsel():
    u = Umgebung()
    try:
        at = u.app()
        textfeld(at, "Benutzername").input("a.mueller")
        textfeld(at, "Passwort").input(START_PW)
        knopf(at, "Anmelden").click(); at.run()
        assert any("Neues Passwort" in str(f.label) for f in at.text_input), \
            "Passwortwechsel wurde nicht erzwungen"
    finally:
        u.aufraeumen()


def test_zu_kurzes_passwort_wird_abgelehnt():
    u = Umgebung()
    try:
        at = u.app()
        textfeld(at, "Benutzername").input("a.mueller")
        textfeld(at, "Passwort").input(START_PW)
        knopf(at, "Anmelden").click(); at.run()
        textfeld(at, "Neues Passwort wiederholen").input("kurz")
        [f for f in at.text_input if str(f.label) == "Neues Passwort"][0].input("kurz")
        knopf(at, "Passwort speichern").click(); at.run()
        ohne_ausnahme(at, "kurzes Passwort")
        assert at.error, "Zu kurzes Passwort wurde akzeptiert"
    finally:
        u.aufraeumen()


# ================================================================ Tests: Mitarbeiter

def test_mitarbeiteransicht_hat_drei_reiter():
    u = Umgebung()
    try:
        at = anmelden(u.app(), "a.mueller")
        assert len(reiter(at)) == 3, f"Erwartet 3 Reiter, gefunden: {reiter(at)}"
    finally:
        u.aufraeumen()


def test_zeit_eintragen_speichert_und_protokolliert():
    u = Umgebung()
    try:
        at = anmelden(u.app(), "a.mueller")
        knopf(at, "Speichern").click(); at.run()
        ohne_ausnahme(at, "Zeit speichern")
        zeiten = u.lesen('SELECT * FROM time_logs WHERE "Mitarbeiter" = ?', ("Anna Müller",))
        assert len(zeiten) == 1, f"Erwartet 1 Eintrag, gefunden {len(zeiten)}"
        assert float(zeiten.iloc[0]["Netto (Std)"]) == 8.0, "Nettozeit falsch berechnet"
        log = u.lesen('SELECT * FROM aenderungsprotokoll')
        assert (log["Aktion"] == "Angelegt").any(), "Anlage wurde nicht protokolliert"
        assert (log["Benutzer"] == "a.mueller").any(), "Falscher Benutzer im Protokoll"
    finally:
        u.aufraeumen()


def test_doppelte_zeit_wird_abgelehnt():
    u = Umgebung()
    try:
        at = anmelden(u.app(), "a.mueller")
        knopf(at, "Speichern").click(); at.run()
        knopf(at, "Speichern").click(); at.run()
        ohne_ausnahme(at, "Doppelbuchung")
        zeiten = u.lesen('SELECT * FROM time_logs WHERE "Mitarbeiter" = ?', ("Anna Müller",))
        assert len(zeiten) == 1, f"Überschneidung wurde gespeichert ({len(zeiten)} Einträge)"
    finally:
        u.aufraeumen()


def test_live_stempeln_start_und_feierabend():
    u = Umgebung()
    try:
        at = anmelden(u.app(), "b.schmidt")
        knopf(at, "ARBEIT STARTEN").click(); at.run()
        ohne_ausnahme(at, "Arbeit starten")
        laufend = u.lesen('SELECT * FROM time_logs WHERE "Status" = ?', ("Läuft",))
        assert len(laufend) == 1, "Keine laufende Buchung angelegt"

        knopf(at, "FEIERABEND").click(); at.run()
        ohne_ausnahme(at, "Feierabend")
        zeile = u.lesen('SELECT * FROM time_logs').iloc[0]
        assert zeile["Status"] == "Erfasst", f"Status nach Feierabend: {zeile['Status']}"
        assert float(zeile["Netto (Std)"]) < 1.0, \
            f"Sofortiger Feierabend bucht {zeile['Netto (Std)']} Stunden"
        aktionen = set(u.lesen('SELECT "Aktion" FROM aenderungsprotokoll')["Aktion"])
        assert {"Eingestempelt", "Ausgestempelt"} <= aktionen, f"Protokoll: {aktionen}"
    finally:
        u.aufraeumen()


def test_nullbuchung_bleibt_nach_neuberechnung_null():
    """Regressionstest für einen echten Fehler.

    Start und Feierabend in derselben Minute ergeben zunächst korrekt fast null
    Stunden, weil der Feierabend mit Sekunden rechnet. Gespeichert werden aber
    nur Stunden und Minuten (z. B. 12:17–12:17). Speichert danach jemand die
    Zeitentabelle, wird jede Zeile neu berechnet – und gleiche Zeiten galten
    früher als Schicht über Mitternacht: 23,25 Stunden.
    """
    u = Umgebung()
    try:
        at = anmelden(u.app(), "b.schmidt")
        knopf(at, "ARBEIT STARTEN").click(); at.run()
        knopf(at, "FEIERABEND").click(); at.run()
        # Gleiche Minute erzwingen, wie sie in der Datenbank steht
        u.sql('UPDATE time_logs SET "Gehen" = "Kommen"')

        zur_leitung_machen(u, "a.mueller")
        at = anmelden(u.app(), "a.mueller")
        knopf(at, "Alle Änderungen speichern").click(); at.run()
        ohne_ausnahme(at, "Tabelle speichern")
        netto = float(u.lesen('SELECT "Netto (Std)" FROM time_logs').iloc[0]["Netto (Std)"])
        assert netto < 1.0, f"Nach dem Speichern stehen {netto} Stunden statt 0"
    finally:
        u.aufraeumen()


def test_abwesenheit_beantragen():
    u = Umgebung()
    try:
        at = anmelden(u.app(), "c.meier")
        knopf(at, "Antrag senden").click(); at.run()
        ohne_ausnahme(at, "Antrag senden")
        antraege = u.lesen('SELECT * FROM vacation_requests WHERE "Mitarbeiter" = ?', ("Clara Meier",))
        assert len(antraege) == 1 and antraege.iloc[0]["Status"] == "Ausstehend", \
            f"Antrag nicht korrekt gespeichert: {antraege[['Status']].to_dict('records')}"
    finally:
        u.aufraeumen()


# ================================================================ Tests: Leitung

def _leitung_mit_antrag(u: Umgebung) -> AppTest:
    """Mitarbeiterin stellt einen Antrag, danach meldet sich die Leitung an."""
    at = anmelden(u.app(), "c.meier")
    knopf(at, "Antrag senden").click(); at.run()
    zur_leitung_machen(u, "a.mueller")
    return anmelden(u.app(), "a.mueller")


def test_leitungsansicht_laedt_alle_reiter():
    u = Umgebung()
    try:
        zur_leitung_machen(u, "a.mueller") if u.db.exists() else None
        u.app()                                   # Datenbank anlegen
        zur_leitung_machen(u, "a.mueller")
        at = anmelden(u.app(), "a.mueller")
        assert len(reiter(at)) >= 7, f"Zu wenige Reiter: {reiter(at)}"
    finally:
        u.aufraeumen()


def test_ablehnung_ohne_grund_wird_verhindert():
    u = Umgebung()
    try:
        at = _leitung_mit_antrag(u)
        knopf(at, "Ablehnen").click(); at.run()
        ohne_ausnahme(at, "Ablehnen ohne Grund")
        status = u.lesen('SELECT "Status" FROM vacation_requests').iloc[0]["Status"]
        assert status == "Ausstehend", f"Antrag ohne Grund abgelehnt (Status {status})"
    finally:
        u.aufraeumen()


def test_ablehnung_mit_grund_wird_gespeichert_und_protokolliert():
    u = Umgebung()
    try:
        at = _leitung_mit_antrag(u)
        grund = [f for f in at.text_input if "Grund" in str(f.label)][0]
        grund.input("Personalengpass in der Gruppe")
        knopf(at, "Ablehnen").click(); at.run()
        ohne_ausnahme(at, "Ablehnen mit Grund")
        antrag = u.lesen('SELECT * FROM vacation_requests').iloc[0]
        assert antrag["Status"] == "Abgelehnt", f"Status: {antrag['Status']}"
        assert "Personalengpass" in str(antrag["Entscheidungsgrund"])
        log = u.lesen('SELECT * FROM aenderungsprotokoll WHERE "Feld" = ?', ("Status",))
        assert not log.empty and log.iloc[0]["Neuer Wert"] == "Abgelehnt", \
            "Statuswechsel wurde nicht protokolliert"
        assert log.iloc[0]["Alter Wert"] == "Ausstehend"
    finally:
        u.aufraeumen()


def test_genehmigung_wird_protokolliert():
    u = Umgebung()
    try:
        at = _leitung_mit_antrag(u)
        knopf(at, "Genehmigen").click(); at.run()
        ohne_ausnahme(at, "Genehmigen")
        assert u.lesen('SELECT "Status" FROM vacation_requests').iloc[0]["Status"] == "Genehmigt"
        log = u.lesen('SELECT * FROM aenderungsprotokoll WHERE "Feld" = ?', ("Status",))
        assert (log["Neuer Wert"] == "Genehmigt").any()
        assert (log["Benutzer"] == "a.mueller").any(), "Entscheider fehlt im Protokoll"
    finally:
        u.aufraeumen()


# ================================================================ Tests: Branchen

def test_kita_ohne_kunden_und_projekte():
    u = Umgebung()
    try:
        u.app()
        branche_setzen(u, "Kita / Soziales")
        zur_leitung_machen(u, "a.mueller")
        at = anmelden(u.app(), "a.mueller")
        namen = " ".join(reiter(at))
        assert "Kunden" not in namen and "Projekte" not in namen, f"Kita zeigt: {reiter(at)}"
    finally:
        u.aufraeumen()


def test_handwerk_mit_kunden_und_projekten():
    u = Umgebung()
    try:
        u.app()
        branche_setzen(u, "Handwerk / Bau")
        zur_leitung_machen(u, "a.mueller")
        at = anmelden(u.app(), "a.mueller")
        namen = " ".join(reiter(at))
        assert "Kunden" in namen and "Projekte" in namen, f"Handwerk zeigt: {reiter(at)}"
    finally:
        u.aufraeumen()


# ================================================================ Tests: Datenbank

def test_datenbank_zieht_vom_alten_ort_um():
    """Ältere Fassungen legten die Datenbank im Hauptordner ab, Backups suchen
    sie aber in daten/. Beim Start muss sie mitsamt Inhalt umziehen."""
    u = Umgebung()
    try:
        at = anmelden(u.app(), "a.mueller")
        knopf(at, "Speichern").click(); at.run()
        # Zustand einer älteren Fassung herstellen: Datenbank im Hauptordner
        alter_ort = u.ordner / "zeiterfassung.db"
        shutil.move(u.db, alter_ort)
        for endung in ("-wal", "-shm"):
            rest = Path(str(u.db) + endung)
            if rest.exists():
                shutil.move(rest, Path(str(alter_ort) + endung))
        assert not u.db.exists()

        at = u.app()
        ohne_ausnahme(at, "Start nach Umzug")
        assert u.db.exists(), "Datenbank wurde nicht nach daten/ verschoben"
        assert not alter_ort.exists(), "Alte Datenbank liegt noch im Hauptordner"
        zeiten = u.lesen('SELECT * FROM time_logs')
        assert len(zeiten) == 1, f"Daten beim Umzug verloren ({len(zeiten)} Einträge)"
    finally:
        u.aufraeumen()


# ================================================================ Tests: Protokoll-Logik

def _protokollfunktionen():
    """Lädt die Vergleichslogik des Protokolls aus app.py – ohne die App zu starten."""
    quelle = (APP_ORDNER / "app.py").read_text(encoding="utf-8")
    baum = ast.parse(quelle)
    namen = {"_protokollwert", "_kurzbeschreibung", "_protokolleintraege"}
    teile = [ast.get_source_segment(quelle, k) for k in baum.body
             if isinstance(k, ast.FunctionDef) and k.name in namen]
    konstante = [ast.get_source_segment(quelle, k) for k in baum.body
                 if isinstance(k, ast.Assign) and any(
                     getattr(z, "id", "") in {"PROTOKOLLIERTE_TABELLEN", "DATUMSFORMAT"}
                     for z in k.targets)]

    class _St:
        session_state = {"username": "test.leitung", "role": "Leitung / Admin"}

    import uuid
    raum = {"pd": pd, "datetime": datetime, "date": date, "uuid": uuid, "st": _St()}
    exec("\n".join(konstante + teile), raum)
    return raum["_protokolleintraege"]


def test_protokoll_erkennt_feldaenderung():
    eintraege = _protokollfunktionen()
    alt = pd.DataFrame([{"ID": "z1", "Mitarbeiter": "Anna", "Datum": date(2026, 9, 21),
                         "Kommen": "08:00", "Gehen": "16:30", "Netto (Std)": 8.0, "Status": "Erfasst"}])
    neu = alt.copy(); neu.loc[0, "Gehen"] = "17:30"; neu.loc[0, "Netto (Std)"] = 9.0
    zeilen = eintraege("time_logs", alt, neu)
    felder = {z[8]: (z[9], z[10]) for z in zeilen}
    assert felder.get("Gehen") == ("16:30", "17:30"), f"Gehen-Änderung falsch: {felder}"
    assert felder.get("Netto (Std)") == ("8", "9"), f"Netto-Änderung falsch: {felder}"
    assert all(z[2] == "test.leitung" for z in zeilen), "Benutzer fehlt"


def test_protokoll_ignoriert_scheinbare_aenderungen():
    eintraege = _protokollfunktionen()
    alt = pd.DataFrame([{"ID": "z1", "Mitarbeiter": "Anna", "Netto (Std)": 8, "Notiz": None}])
    neu = pd.DataFrame([{"ID": "z1", "Mitarbeiter": "Anna", "Netto (Std)": 8.0, "Notiz": ""}])
    assert eintraege("time_logs", alt, neu) == [], "8 und 8.0 bzw. None und '' als Änderung gewertet"


def test_protokoll_erkennt_loeschung():
    eintraege = _protokollfunktionen()
    alt = pd.DataFrame([{"ID": "z1", "Mitarbeiter": "Anna", "Datum": date(2026, 9, 21),
                         "Kommen": "08:00", "Gehen": "16:30", "Netto (Std)": 8.0}])
    neu = alt.iloc[0:0]
    zeilen = eintraege("time_logs", alt, neu)
    assert len(zeilen) == 1 and zeilen[0][4] == "Gelöscht"
    assert "08:00" in zeilen[0][9], "Gelöschter Inhalt fehlt im Protokoll"


def test_protokoll_fasst_ausstempeln_zusammen():
    eintraege = _protokollfunktionen()
    alt = pd.DataFrame([{"ID": "z1", "Mitarbeiter": "Ben", "Kommen": "08:00", "Gehen": "",
                         "Netto (Std)": None, "Status": "Läuft"}])
    neu = pd.DataFrame([{"ID": "z1", "Mitarbeiter": "Ben", "Kommen": "08:00", "Gehen": "16:00",
                         "Netto (Std)": 7.5, "Status": "Erfasst"}])
    zeilen = eintraege("time_logs", alt, neu)
    assert len(zeilen) == 1 and zeilen[0][4] == "Ausgestempelt", \
        f"Ausstempeln erzeugt {len(zeilen)} Zeilen statt einer"


def test_protokoll_ignoriert_andere_tabellen():
    eintraege = _protokollfunktionen()
    df = pd.DataFrame([{"MA-ID": "ma-1", "Mitarbeiter": "Anna"}])
    assert eintraege("mitarbeiter_stammdaten", df.iloc[0:0], df) == []


# ================================================================ Testlauf

def _alle_tests():
    return [(n, f) for n, f in globals().items() if n.startswith("test_") and callable(f)]


if __name__ == "__main__":
    import logging
    logging.getLogger("streamlit").setLevel(logging.ERROR)
    bestanden, fehler = 0, []
    for name, funktion in _alle_tests():
        try:
            funktion()
            bestanden += 1
            print(f"  ✓ {name}")
        except Exception as exc:
            fehler.append((name, exc))
            print(f"  ✗ {name}")
            print("      " + str(exc).replace("\n", "\n      ")[:800])
    print(f"\n{bestanden} von {bestanden + len(fehler)} Oberflächentests bestanden.")
    if TABELLEN_ERSATZ:
        print("Hinweis: pyarrow fehlt – Tabellen wurden durch Platzhalter ersetzt.")
    raise SystemExit(1 if fehler else 0)
