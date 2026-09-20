"""
Zeiterfassung & Urlaubsverwaltung / Time tracking & absence management
======================================================================
Branchenneutrale Streamlit-App (Handwerk, Büro, Kita, Pflege, Gastronomie, Handel).
Zweisprachig: jede Benutzerin / jeder Benutzer wählt Deutsch oder Englisch.

Start:  streamlit run app.py
Abhängigkeiten: streamlit, pandas, openpyxl
"""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import logging
import os
import platform
import secrets
import sqlite3

try:
    import psycopg
except ImportError:
    psycopg = None
import sys
import traceback
import uuid
from datetime import date, datetime, time, timedelta
from logging.handlers import RotatingFileHandler
from pathlib import Path

import pandas as pd
import streamlit as st

# Fachlogik liegt in einem eigenen Modul ohne Streamlit-Bezug. Dadurch bleibt sie
# beim Wechsel der Oberfläche unverändert nutzbar und ist per test_logik.py prüfbar.
import logik
from logik import Abwesenheit, Buchung, Regeln, ZeitFehler

# ============================================================
# 1. GRUNDKONFIGURATION
# ============================================================

# Versionsangabe: erscheint in der Fußzeile und im Diagnosebericht. Bei jeder
# Auslieferung an einen Kunden hochzählen – ohne sie beginnt jeder Support-Fall
# mit der Frage, welcher Stand überhaupt installiert ist.
APP_VERSION = "1.2.0"
APP_VERSIONSDATUM = "2026-09-20"
SUPPORT_KONTAKT = os.getenv("SUPPORT_KONTAKT", "support@example.de")
SUPPORT_ZEITEN = os.getenv("SUPPORT_ZEITEN", "Mo–Fr 18:00–20:00 Uhr")

DATUMSFORMAT = "%d.%m.%Y"           # europäisches Format, in beiden Sprachen
DATUMSFORMAT_UI = "DD.MM.YYYY"
ZEITFORMAT = "%H:%M"

APP_DIR = Path(__file__).resolve().parent
DATEN_DIR = APP_DIR / "daten"
BACKUP_DIR = APP_DIR / "backups"
PERSISTENZ = True

# ------------------------------------------------------------
# Protokollierung
# ------------------------------------------------------------
# Schreibt Fehler in daten/app.log. Der Handler hängt am Root-Logger, damit auch
# die von Streamlit selbst abgefangenen Ausnahmen ("Uncaught app exception") in
# der Datei landen. Ohne Logdatei besteht Support aus dem Erraten von Symptomen.
LOG_DATEI = DATEN_DIR / "app.log"
LOG_MAX_BYTES = 1_000_000
LOG_SICHERUNGEN = 3


def _protokoll_einrichten() -> logging.Logger:
    logger = logging.getLogger("meinezeit")
    if getattr(_protokoll_einrichten, "_fertig", False):
        return logger
    try:
        DATEN_DIR.mkdir(parents=True, exist_ok=True)
        handler = RotatingFileHandler(
            LOG_DATEI, maxBytes=LOG_MAX_BYTES, backupCount=LOG_SICHERUNGEN, encoding="utf-8"
        )
        handler.setFormatter(logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%d.%m.%Y %H:%M:%S",
        ))
        handler.setLevel(logging.WARNING)
        wurzel = logging.getLogger()
        # Doppelte Handler bei Streamlit-Reruns vermeiden
        if not any(isinstance(h, RotatingFileHandler) and
                   Path(getattr(h, "baseFilename", "")) == LOG_DATEI
                   for h in wurzel.handlers):
            wurzel.addHandler(handler)
        wurzel.setLevel(min(wurzel.level or logging.WARNING, logging.WARNING))
        logger.setLevel(logging.INFO)
    except Exception:
        pass  # Protokollierung darf die App niemals blockieren
    _protokoll_einrichten._fertig = True
    return logger


LOG = _protokoll_einrichten()


def protokolliere(nachricht: str, exc: BaseException | None = None, stufe: int = logging.ERROR) -> None:
    """Schreibt einen Eintrag ins Protokoll – nie mit personenbezogenen Daten."""
    try:
        if exc is not None:
            LOG.log(stufe, "%s | %s: %s", nachricht, type(exc).__name__, exc)
            LOG.debug("%s", "".join(traceback.format_exception(type(exc), exc, exc.__traceback__)))
        else:
            LOG.log(stufe, "%s", nachricht)
    except Exception:
        pass


def protokoll_zeilen(anzahl: int = 50) -> list[str]:
    """Letzte Protokollzeilen – Grundlage für den Diagnosebericht."""
    try:
        if not LOG_DATEI.exists():
            return []
        with LOG_DATEI.open("r", encoding="utf-8", errors="replace") as datei:
            return [z.rstrip() for z in datei.readlines()[-anzahl:]]
    except Exception:
        return []


# Der Systemadministrator gehört zum Betreiber der Software, nicht zum Kundenbetrieb.
# Das Passwort wird niemals im Quellcode hinterlegt. Bei der Erstinstallation kann
# es über MEINEZEIT_SYSTEMADMIN_PASSWORD gesetzt werden; andernfalls wird einmalig
# ein zufälliges Passwort erzeugt und lokal in einer Bootstrap-Datei abgelegt.
SYSTEMADMIN_USERNAME = "systemadmin"
SYSTEMADMIN_ENV = "MEINEZEIT_SYSTEMADMIN_PASSWORD"
# Einmaliger Wiederherstellungswert für die aktuell ausgelieferte Installation.
# Nach erfolgreichem Login unbedingt über den erzwungenen Passwortwechsel ändern.
SYSTEMADMIN_RECOVERY_PASSWORD = os.getenv("MEINEZEIT_SYSTEMADMIN_RECOVERY_PASSWORD", "").strip()
START_PASSWORT = os.getenv("MEINEZEIT_START_PASSWORD", "").strip()
MIN_PASSWORTLAENGE = 10
PBKDF2_ITERATIONEN = 200_000  # Legacy-Verifikation; neue Passwörter nutzen scrypt.
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 32
# hashlib.scrypt begrenzt den Arbeitsspeicher standardmäßig auf 32 MB. Die obigen
# Parameter benötigen 128 * N * r = 33,5 MB und laufen damit ohne diese Angabe je
# nach OpenSSL-Version in "memory limit exceeded". Das Limit muss also explizit
# über dem Bedarf liegen.
SCRYPT_MAXMEM = 128 * 1024 * 1024
PASSWORT_ALGORITHMUS = "scrypt"
MAX_LOGIN_VERSUCHE = 5
SPERRDAUER_MINUTEN = 5
ROLLEN = ["Mitarbeiter", "Leitung / Admin", "Systemadministrator"]
SPRACHEN = {"de": "Deutsch", "en": "English"}
STANDARD_NACHTRAGSLIMIT = 24.0      # Stunden – "1 Tag rückwirkend"
# Leitung und Admin korrigieren Zeiten auch für zurückliegende Abrechnungen.
# Deshalb bekommen sie als Vorgabe ein praktisch unbegrenztes Fenster, das sich
# in den Stammdaten jederzeit auf einen konkreten Wert zurücksetzen lässt.
NACHTRAG_UNBEGRENZT = 876000.0      # 100 Jahre
NACHTRAG_UNBEGRENZT_AB = 87600.0    # ab hier gilt die Anzeige als "unbegrenzt"

BUNDESLAENDER = logik.BUNDESLAENDER   # einzige Quelle: das Fachlogik-Modul

# Alle Werte werden intern deutsch gespeichert und nur für die Anzeige übersetzt.
BRANCHEN = {
    "Allgemein / Büro": {
        "label": ("Allgemein / Büro", "General / office"),
        "projekt_label": ("Kostenstelle / Projekt", "Cost center / project"),
        "projekt_aktiv": True,
        "kategorien": [("Arbeitszeit", "Working time"), ("Homeoffice", "Home office"),
                       ("Dienstreise", "Business trip"), ("Fortbildung", "Training")],
        "wochenstunden": 40.0,
    },
    "Handwerk / Bau": {
        "label": ("Handwerk / Bau", "Trades / construction"),
        "projekt_label": ("Baustelle / Auftrag", "Site / job"),
        "projekt_aktiv": True,
        "kategorien": [("Arbeitszeit", "Working time"), ("Fahrtzeit", "Travel time"),
                       ("Rüstzeit / Lager", "Setup / warehouse"), ("Bereitschaft", "On call"),
                       ("Schulung", "Training")],
        "wochenstunden": 40.0,
    },
    "Dienstleistung / Beratung": {
        "label": ("Dienstleistung / Beratung", "Services / consulting"),
        "projekt_label": ("Projekt / Auftrag", "Project / assignment"),
        "projekt_aktiv": True,
        "kategorien": [("Arbeitszeit", "Working time"), ("Kundentermin", "Customer appointment"),
                       ("Projektarbeit", "Project work"), ("Reisezeit", "Travel time"),
                       ("Vorbereitung", "Preparation")],
        "wochenstunden": 40.0,
    },
    "Kita / Soziales": {
        "label": ("Kita / Soziales", "Childcare / social work"),
        "projekt_label": ("Gruppe / Bereich", "Group / area"),
        # Kitas buchen weder auf Kunden noch auf Projekte – das Feld würde die
        # Erfassung nur verlängern, ohne ausgewertet zu werden.
        "projekt_aktiv": False,
        "kategorien": [("Arbeitszeit", "Working time"), ("Vorbereitungszeit", "Preparation"),
                       ("Elterngespräch", "Parent meeting"), ("Fortbildung", "Training")],
        "wochenstunden": 39.0,
    },
    "Pflege / Gesundheit": {
        "label": ("Pflege / Gesundheit", "Care / health"),
        "projekt_label": ("Station / Tour", "Ward / route"),
        "projekt_aktiv": True,
        "kategorien": [("Frühdienst", "Early shift"), ("Spätdienst", "Late shift"),
                       ("Nachtdienst", "Night shift"), ("Bereitschaft", "On call"),
                       ("Fortbildung", "Training")],
        "wochenstunden": 38.5,
    },
    "Gastronomie / Hotel": {
        "label": ("Gastronomie / Hotel", "Hospitality / hotel"),
        "projekt_label": ("Betrieb / Schicht", "Venue / shift"),
        "projekt_aktiv": True,
        "kategorien": [("Service", "Service"), ("Küche", "Kitchen"),
                       ("Vorbereitung", "Preparation"), ("Veranstaltung", "Event")],
        "wochenstunden": 40.0,
    },
    "Einzelhandel": {
        "label": ("Einzelhandel", "Retail"),
        "projekt_label": ("Filiale / Abteilung", "Store / department"),
        "projekt_aktiv": True,
        "kategorien": [("Verkauf", "Sales"), ("Warenannahme", "Goods receipt"),
                       ("Inventur", "Stocktaking"), ("Schulung", "Training")],
        "wochenstunden": 38.0,
    },
}

# Demo-Daten je Branche: 3 Mitarbeitende mit passenden Namen, Stunden, Urlaub und
# einem Beispiel-Projekt/-Standort. Wird von "Demo zurücksetzen" in den Einstellungen
# verwendet, damit eine Vorführung sofort realistisch aussieht statt leer zu sein.
DEMO_MITARBEITER = {
    "Allgemein / Büro": [
        {"name": "Julia Hoffmann", "wochenstunden": 40.0, "urlaub": 30, "rest": 2, "projekt": "Projekt Alpha"},
        {"name": "Tobias Wagner", "wochenstunden": 40.0, "urlaub": 30, "rest": 0, "projekt": "Kunde Beispiel AG"},
        {"name": "Nina Krause", "wochenstunden": 32.0, "urlaub": 30, "rest": 3, "projekt": "Interne Prozesse"},
    ],
    "Handwerk / Bau": [
        {"name": "Michael Bauer", "wochenstunden": 40.0, "urlaub": 28, "rest": 2, "projekt": "Neubau Musterstraße 12"},
        {"name": "Kevin Fischer", "wochenstunden": 40.0, "urlaub": 28, "rest": 0, "projekt": "Sanierung Rathausplatz"},
        {"name": "Sabine Roth", "wochenstunden": 35.0, "urlaub": 30, "rest": 4, "projekt": "Bürogebäude Nord"},
    ],
    "Dienstleistung / Beratung": [
        {"name": "Laura Becker", "wochenstunden": 40.0, "urlaub": 30, "rest": 2, "projekt": "Digitalisierung Muster GmbH"},
        {"name": "Max König", "wochenstunden": 40.0, "urlaub": 30, "rest": 0, "projekt": "Prozessberatung Beispiel AG"},
        {"name": "Sophie Wagner", "wochenstunden": 32.0, "urlaub": 30, "rest": 3, "projekt": "Automatisierung Kundenservice"},
    ],
    "Kita / Soziales": [
        {"name": "Anna Müller", "wochenstunden": 39.0, "urlaub": 30, "rest": 2, "projekt": "Bärengruppe"},
        {"name": "Daniela Freitag", "wochenstunden": 30.0, "urlaub": 30, "rest": 1, "projekt": "Igelgruppe"},
        {"name": "Julian Weixler", "wochenstunden": 39.0, "urlaub": 30, "rest": 0, "projekt": "Leitung / Springer"},
    ],
    "Pflege / Gesundheit": [
        {"name": "Petra Schulz", "wochenstunden": 38.5, "urlaub": 30, "rest": 3, "projekt": "Station 2"},
        {"name": "Markus Lang", "wochenstunden": 38.5, "urlaub": 30, "rest": 0, "projekt": "Ambulanter Dienst"},
        {"name": "Christine Böhm", "wochenstunden": 30.0, "urlaub": 30, "rest": 2, "projekt": "Nachtwache"},
    ],
    "Gastronomie / Hotel": [
        {"name": "Lukas Peters", "wochenstunden": 40.0, "urlaub": 24, "rest": 1, "projekt": "Restaurant"},
        {"name": "Melanie Voss", "wochenstunden": 30.0, "urlaub": 24, "rest": 0, "projekt": "Bankett & Events"},
        {"name": "David Kaya", "wochenstunden": 40.0, "urlaub": 24, "rest": 2, "projekt": "Küche"},
    ],
    "Einzelhandel": [
        {"name": "Sandra Klein", "wochenstunden": 35.0, "urlaub": 28, "rest": 1, "projekt": "Filiale Innenstadt"},
        {"name": "Jonas Richter", "wochenstunden": 20.0, "urlaub": 28, "rest": 0, "projekt": "Filiale Innenstadt"},
        {"name": "Yvonne Neumann", "wochenstunden": 40.0, "urlaub": 28, "rest": 3, "projekt": "Lager & Logistik"},
    ],
}
DEMO_FIRMENNAMEN = {
    "Allgemein / Büro": "Beispiel Consulting GmbH",
    "Handwerk / Bau": "Mustermann Bau GmbH",
    "Kita / Soziales": "Kita Sonnenschein e.V.",
    "Dienstleistung / Beratung": "Beispiel Beratung GmbH",
    "Pflege / Gesundheit": "Pflegedienst Lebensfreude GmbH",
    "Gastronomie / Hotel": "Hotel & Restaurant Musterhof",
    "Einzelhandel": "Modehaus Beispiel GmbH",
}

# Abwesenheitsarten: (intern, englisch, stundenweise erlaubt)
ABWESENHEITSARTEN = [
    ("Urlaub", "Vacation", False),
    ("Freizeitausgleich", "Time off in lieu", True),
    ("Überstundenabbau", "Overtime reduction", True),
    ("Sonderurlaub", "Special leave", True),
    ("Unbezahlt", "Unpaid leave", True),
]

SPALTEN_ZEITEN = [
    "ID", "Mitarbeiter", "Datum", "Kommen", "Gehen",
    "Brutto (Std)", "Pause (Min)", "Netto (Std)",
    "Kategorie", "Kunde-ID", "Projekt-ID", "Projekt", "Notiz", "Typ", "Status",
]
SPALTEN_KUNDEN = [
    "Kunden-ID", "Kundennummer", "Kunde", "Ansprechpartner", "Telefon",
    "E-Mail", "Straße", "PLZ", "Ort", "Aktiv", "Notiz",
]
SPALTEN_PROJEKTE = [
    "Projekt-ID", "Projektnummer", "Projekt", "Kunden-ID", "Status",
    "Startdatum", "Enddatum", "Stundensatz", "Aktiv", "Notiz",
]
SPALTEN_URLAUB = [
    "ID", "Mitarbeiter", "Startdatum", "Enddatum", "Einheit", "Tage", "Stunden",
    "Art", "Kommentar", "Status", "Eingereicht am", "Entscheidungsgrund", "Erfasst von",
]
SPALTEN_STAMM = [
    "MA-ID", "Mitarbeiter", "Personalnummer", "Wochenstunden",
    "Urlaub_Pro_Jahr", "Resturlaub_Vorjahr", "Nachtrag_Std_Limit", "Aktiv",
]
SPALTEN_ARBEITSZEITKALENDER = [
    # KAL-ID ist zwingend: der inkrementelle Speicher-Abgleich braucht je Zeile einen
    # eindeutigen Schlüssel. Mit "MA-ID" als Schlüssel überschrieben sich die sieben
    # Wochentage gegenseitig und nur der Sonntag blieb erhalten.
    "KAL-ID", "MA-ID", "Wochentag", "Arbeitstag", "Von", "Bis", "Pause_Min", "Soll_Std",
]
SPALTEN_BENUTZER = [
    "Benutzername", "Salt", "Passwort_Hash", "Rolle", "MA-ID",
    "Sprache", "Aktiv", "Passwort_wechseln", "Letzter Login", "Passwort_Algorithmus",
]

DATUMSSPALTEN = {"Datum", "Startdatum", "Enddatum", "Eingereicht am", "Letzter Login"}
TEXTSPALTEN = {
    "Entscheidungsgrund", "Erfasst von",
    "MA-ID", "Mitarbeiter", "Personalnummer", "Benutzername", "Salt", "Passwort_Hash",
    "Rolle", "Sprache", "Projekt", "Notiz", "Kategorie", "Kommentar", "Art", "Einheit",
    "Kunden-ID", "Kundennummer", "Kunde", "Ansprechpartner", "Telefon", "E-Mail", "Straße", "PLZ", "Ort", "Projekt-ID", "Projektnummer",
    "Status", "Typ", "Kommen", "Gehen", "Von", "Bis", "Wochentag", "ID",
}

# Spaltenüberschriften für die englische Anzeige
SPALTEN_LABELS_EN = {
    "Mitarbeiter": "Employee", "Datum": "Date", "Kommen": "Start", "Gehen": "End",
    "Brutto (Std)": "Gross (h)", "Pause (Min)": "Break (min)", "Netto (Std)": "Net (h)",
    "Kategorie": "Category", "Kunde-ID": "Customer ID", "Projekt-ID": "Project ID", "Kunde": "Customer",
    "Projekt": "Project", "Notiz": "Note", "Typ": "Type",
    "Status": "Status", "Startdatum": "Start date", "Enddatum": "End date",
    "Einheit": "Unit", "Tage": "Days", "Stunden": "Hours", "Art": "Type",
    "Kommentar": "Comment", "Eingereicht am": "Submitted",
    "Entscheidungsgrund": "Reason for decision", "Erfasst von": "Recorded by", "Benutzername": "Username",
    "Rolle": "Role", "Aktiv": "Active", "Passwort_wechseln": "Must change password",
    "Letzter Login": "Last login", "Person": "Person", "MA-ID": "Emp. ID",
    "Personalnummer": "Staff no.", "Wochenstunden": "Weekly hours",
    "Urlaub_Pro_Jahr": "Leave / year", "Resturlaub_Vorjahr": "Carry-over",
    "Nachtrag_Std_Limit": "Edit window (h)", "Login": "Login", "Sprache": "Language",
    "Ist (Std)": "Actual (h)", "Soll (Std)": "Target (h)", "Saldo (Std)": "Balance (h)",
    "Einträge": "Entries", "Netto-Stunden": "Net hours", "Löschen": "Delete",
}

# Feldwerte für die englische Anzeige
WERT_LABELS_EN = {
    "Ausstehend": "Pending", "Genehmigt": "Approved", "Abgelehnt": "Rejected", "Storniert": "Cancelled",
    "Läuft": "Running", "Erfasst": "Recorded", "Freigegeben": "Released",
    "Live": "Live", "Manuell": "Manual", "Korrigiert": "Corrected",
    "Tage": "Days", "Stunden": "Hours",
    "Mitarbeiter": "Employee", "Leitung / Admin": "Management / admin",
}
for _de, _en, _ in ABWESENHEITSARTEN:
    WERT_LABELS_EN[_de] = _en
for _branche in BRANCHEN.values():
    for _de, _en in _branche["kategorien"]:
        WERT_LABELS_EN.setdefault(_de, _en)

WOCHENTAGE = {
    "de": ["Montag", "Dienstag", "Mittwoch", "Donnerstag", "Freitag", "Samstag", "Sonntag"],
    "en": ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"],
}

st.set_page_config(
    page_title="Zeiterfassung",
    page_icon="⏱️",
    layout="wide",
    initial_sidebar_state="collapsed",
)


# ============================================================
# 2. SPRACHE & RÜCKMELDUNGEN
# ============================================================

if "sprache" not in st.session_state:
    st.session_state.sprache = "de"


def t(de: str, en: str) -> str:
    """Kurzform für zweisprachige Texte."""
    return de if st.session_state.get("sprache", "de") == "de" else en


def ist_englisch() -> bool:
    return st.session_state.get("sprache", "de") == "en"


def wert_label(wert) -> str:
    """Übersetzt gespeicherte Feldwerte (Status, Art, Kategorie) für die Anzeige."""
    if not ist_englisch():
        return str(wert)
    return WERT_LABELS_EN.get(str(wert), str(wert))


def spalten_label(spalte: str) -> str:
    if not ist_englisch():
        return spalte
    return SPALTEN_LABELS_EN.get(spalte, spalte)


def loeschabfrage(schluessel: str, ids: list, frage: str, hinweis: str = ""):
    """Zweistufige Sicherheitsabfrage vor dem Löschen.

    Erster Klick stellt die Frage, erst der zweite löscht. Gibt die Liste der zu
    löschenden Einträge zurück, sobald bestätigt wurde – sonst None. Gelöschte
    Daten lassen sich nur über eine Sicherung zurückholen.
    """
    merker = f"_loeschfrage_{schluessel}"
    if not st.session_state.get(merker):
        return None
    with st.container(border=True):
        st.warning(frage)
        if hinweis:
            st.caption(hinweis)
        c1, c2 = st.columns(2)
        if c1.button(t("🗑️ Ja, endgültig löschen", "🗑️ Yes, delete permanently"),
                     key=f"_loeschja_{schluessel}", use_container_width=True):
            gemerkt = st.session_state.pop(merker, [])
            return gemerkt if isinstance(gemerkt, list) else list(ids)
        if c2.button(t("Abbrechen", "Cancel"), key=f"_loeschnein_{schluessel}",
                     use_container_width=True, type="primary"):
            st.session_state.pop(merker, None)
            melde("Löschen abgebrochen.", "Deletion cancelled.", "↩️")
            st.rerun()
    return None


def melde(de: str, en: str, icon: str = "✅") -> None:
    """Merkt eine Rückmeldung vor, die nach dem nächsten Rerun als Toast erscheint."""
    st.session_state.setdefault("meldungen", []).append((de, en, icon))


def meldungen_anzeigen() -> None:
    for de_text, en_text, icon in st.session_state.pop("meldungen", []):
        st.toast(t(de_text, en_text), icon=icon)


# ============================================================
# 3. PERSISTENZ (SQLite-Datenbank im Ordner "daten")
# ============================================================
#
# Warum SQLite: eine einzelne Datei, kein Serverbetrieb nötig – für Demos beim
# Kunden reicht das, ist aber eine "echte" Datenbank statt loser CSV-Dateien.

DB_DATEI = APP_DIR / "zeiterfassung.db"
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
PRODUKTIONS_DB = bool(DATABASE_URL)


def _dateirechte_sichern(pfad: Path) -> None:
    try:
        if os.name != "nt" and pfad.exists():
            pfad.chmod(0o600)
    except OSError:
        pass


class _PostgresVerbindung:
    """Kompatibilitätsschicht für den Produktionsbetrieb mit PostgreSQL."""
    def __init__(self, url: str):
        if psycopg is None:
            raise RuntimeError("PostgreSQL ist aktiviert, aber das Paket 'psycopg' fehlt.")
        self._conn = psycopg.connect(url, connect_timeout=10)
    def __enter__(self):
        return self
    def __exit__(self, exc_type, exc, tb):
        try:
            if exc_type is None:
                self._conn.commit()
            else:
                self._conn.rollback()
        finally:
            self._conn.close()
    def _sql(self, sql: str) -> str:
        return sql.replace("?", "%s").replace("BEGIN IMMEDIATE", "BEGIN")
    def execute(self, sql: str, params=()):
        normalized = str(sql).strip().upper()
        if normalized.startswith("BEGIN"):
            # psycopg starts a transaction automatically on the first statement.
            return self._conn.execute("SELECT 1")
        return self._conn.execute(self._sql(sql), params)
    def commit(self):
        self._conn.commit()
    def rollback(self):
        self._conn.rollback()
    def close(self):
        self._conn.close()


def _verbindung():
    if PRODUKTIONS_DB:
        return _PostgresVerbindung(DATABASE_URL)
    DATEN_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_DATEI, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA temp_store=MEMORY")
    if DB_DATEI.exists():
        _dateirechte_sichern(DB_DATEI)
    return conn

def sqlite_integritaet_pruefen() -> bool:
    """Prüft Verbindung bzw. lokale SQLite-Datei."""
    if PRODUKTIONS_DB:
        try:
            with _verbindung() as conn:
                return conn.execute("SELECT 1").fetchone()[0] == 1
        except Exception:
            return False
    if not DB_DATEI.exists():
        return False
    try:
        with _verbindung() as conn:
            return conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    except Exception:
        return False

def backup_datenbank(ziel_dir: Path | None = None) -> Path | None:
    """Erstellt ein konsistentes PostgreSQL- oder SQLite-Backup."""
    ziel_dir = ziel_dir or BACKUP_DIR
    ziel_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    try:
        if PRODUKTIONS_DB:
            import subprocess
            ziel = ziel_dir / f"meinezeit_{stamp}.dump"
            result = subprocess.run(
                ["pg_dump", DATABASE_URL, "--format=custom", "--file", str(ziel)],
                capture_output=True, text=True, timeout=120,
            )
            if result.returncode != 0:
                ziel.unlink(missing_ok=True)
                protokolliere("PostgreSQL-Backup fehlgeschlagen", RuntimeError(result.stderr[-1000:]))
                return None
            _dateirechte_sichern(ziel)
            return ziel

        if not DB_DATEI.exists():
            return None
        ziel = ziel_dir / f"zeiterfassung_{stamp}.db"
        tmp = ziel.with_suffix(".tmp")
        with sqlite3.connect(DB_DATEI, timeout=30) as source, sqlite3.connect(tmp) as target:
            source.execute("PRAGMA busy_timeout=30000")
            source.backup(target)
        with sqlite3.connect(tmp) as check_conn:
            ok = check_conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        if not ok:
            tmp.unlink(missing_ok=True)
            return None
        tmp.replace(ziel)
        _dateirechte_sichern(ziel)
        return ziel
    except Exception as exc:
        protokolliere("Datenbank-Backup fehlgeschlagen", exc)
        return None

def diagnosebericht() -> str:
    """Technischer Statusbericht für den Support – bewusst ohne personenbezogene Daten.

    Enthält Version, Umgebung, Datenbankzustand, Backup-Lage, Kontostatistik und die
    letzten Protokollzeilen. Der Kunde lädt die Datei herunter und hängt sie an seine
    Support-Anfrage an; damit entfallen die meisten Rückfragen.
    """
    zeilen: list[str] = []
    zeilen.append("MEINEZEIT – DIAGNOSEBERICHT")
    zeilen.append("=" * 60)
    zeilen.append(f"Erstellt am:        {datetime.now():%d.%m.%Y %H:%M:%S}")
    zeilen.append(f"App-Version:        {APP_VERSION} ({APP_VERSIONSDATUM})")
    zeilen.append("")

    zeilen.append("UMGEBUNG")
    zeilen.append("-" * 60)
    zeilen.append(f"Python:             {sys.version.split()[0]}")
    try:
        zeilen.append(f"Streamlit:          {st.__version__}")
    except Exception:
        zeilen.append("Streamlit:          unbekannt")
    zeilen.append(f"Pandas:             {pd.__version__}")
    if PRODUKTIONS_DB:
        zeilen.append("Datenbank:          PostgreSQL")
    else:
        zeilen.append(f"SQLite:             {sqlite3.sqlite_version}")
    zeilen.append(f"Betriebssystem:     {platform.system()} {platform.release()}")
    zeilen.append(f"App-Verzeichnis:    {APP_DIR}")
    zeilen.append("")

    zeilen.append("DATENBANK")
    zeilen.append("-" * 60)
    if PRODUKTIONS_DB or DB_DATEI.exists():
        if PRODUKTIONS_DB:
            zeilen.append("Quelle:              PostgreSQL")
        else:
            zeilen.append(f"Datei:              {DB_DATEI.name}")
            zeilen.append(f"Größe:              {DB_DATEI.stat().st_size / 1024:.1f} KB")
            zeilen.append(f"Zuletzt geändert:   {datetime.fromtimestamp(DB_DATEI.stat().st_mtime):%d.%m.%Y %H:%M}")
        zeilen.append(f"Verbindungstest:    {'OK' if sqlite_integritaet_pruefen() else 'FEHLGESCHLAGEN'}")
        try:
            with _verbindung() as conn:
                if PRODUKTIONS_DB:
                    tabellen = [r[0] for r in conn.execute(
                        "SELECT table_name FROM information_schema.tables "
                        "WHERE table_schema='public' ORDER BY table_name")]
                else:
                    tabellen = [r[0] for r in conn.execute(
                        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
                for tabelle in tabellen:
                    anzahl = conn.execute(f'SELECT COUNT(*) FROM "{tabelle}"').fetchone()[0]
                    zeilen.append(f"  Tabelle {tabelle:<24} {anzahl:>6} Datensätze")
        except Exception as exc:
            zeilen.append(f"  Tabellen nicht lesbar: {exc}")
    else:
        zeilen.append("Datenbank noch nicht vorhanden.")
    zeilen.append("")

    zeilen.append("BACKUPS")
    zeilen.append("-" * 60)
    try:
        backups = sorted(BACKUP_DIR.glob("zeiterfassung_*.db"), reverse=True) if BACKUP_DIR.exists() else []
        zeilen.append(f"Anzahl:             {len(backups)}")
        if backups:
            neuestes = backups[0]
            alter = datetime.now() - datetime.fromtimestamp(neuestes.stat().st_mtime)
            zeilen.append(f"Neuestes:           {neuestes.name}")
            zeilen.append(f"Alter:              {alter.days} Tage, {alter.seconds // 3600} Stunden")
            if alter.days > 2:
                zeilen.append("HINWEIS:            Letztes Backup älter als 2 Tage – Aufgabenplanung prüfen!")
        else:
            zeilen.append("HINWEIS:            Noch kein Backup vorhanden – install_backup.bat ausführen!")
    except Exception as exc:
        zeilen.append(f"Backups nicht lesbar: {exc}")
    zeilen.append("")

    zeilen.append("KONTEN (nur Anzahl, keine Namen)")
    zeilen.append("-" * 60)
    try:
        konten = st.session_state.get("benutzer")
        if konten is not None and not konten.empty:
            for rolle in ROLLEN:
                gesamt = int((konten["Rolle"] == rolle).sum())
                aktiv = int(((konten["Rolle"] == rolle) & konten["Aktiv"].astype(bool)).sum())
                zeilen.append(f"  {rolle:<22} {aktiv} aktiv / {gesamt} gesamt")
        stamm = st.session_state.get("mitarbeiter_stammdaten")
        if stamm is not None:
            aktiv = int(stamm["Aktiv"].astype(bool).sum()) if not stamm.empty else 0
            zeilen.append(f"  Mitarbeiterstammdaten  {aktiv} aktiv / {len(stamm)} gesamt")
    except Exception as exc:
        zeilen.append(f"  Kontostatistik nicht lesbar: {exc}")
    zeilen.append("")

    zeilen.append("EINSTELLUNGEN")
    zeilen.append("-" * 60)
    try:
        for schluessel, wert in st.session_state.get("config", {}).items():
            zeilen.append(f"  {schluessel:<28} {wert}")
    except Exception:
        zeilen.append("  Einstellungen nicht lesbar")
    zeilen.append("")

    zeilen.append("LETZTE PROTOKOLLEINTRÄGE")
    zeilen.append("-" * 60)
    eintraege = protokoll_zeilen(40)
    zeilen.extend(eintraege if eintraege else ["Keine Einträge vorhanden."])
    zeilen.append("")
    zeilen.append("=" * 60)
    zeilen.append(f"Support: {SUPPORT_KONTAKT} · {SUPPORT_ZEITEN}")
    return "\n".join(zeilen)


def alte_backups_loeschen(tage: int = 90) -> None:
    if not BACKUP_DIR.exists():
        return
    grenze = datetime.now() - timedelta(days=tage)
    for pfad in BACKUP_DIR.glob("zeiterfassung_*.db"):
        try:
            if datetime.fromtimestamp(pfad.stat().st_mtime) < grenze:
                pfad.unlink()
        except OSError:
            pass


def backup_beim_app_start() -> None:
    """Maximal ein automatisches Backup pro Kalendertag."""
    if not DB_DATEI.exists():
        return
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    heute = datetime.now().strftime("%Y-%m-%d")
    if not any(BACKUP_DIR.glob(f"zeiterfassung_{heute}_*.db")):
        backup_datenbank()
    alte_backups_loeschen()


def _tabelle_vorhanden(conn, key: str) -> bool:
    if PRODUKTIONS_DB:
        treffer = conn.execute(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema='public' AND table_name=?", (key,)
        ).fetchone()
    else:
        treffer = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (key,)
        ).fetchone()
    return treffer is not None


def _fuer_db(df: pd.DataFrame) -> pd.DataFrame:
    """Datumswerte als ISO-Text, damit SQLite sie sortierbar und lesbar speichert."""
    aus = df.copy().drop(columns=["Kunde-ID", "Projekt-ID"], errors="ignore")
    for spalte in aus.columns:
        if spalte in DATUMSSPALTEN:
            aus[spalte] = aus[spalte].apply(lambda w: w.isoformat() if isinstance(w, date) else None)
    return aus


def _sqlite_wert(wert):
    """Wandelt pandas-Werte sicher in SQLite-kompatible Werte um."""
    if pd.isna(wert):
        return None
    if isinstance(wert, (pd.Timestamp, datetime)):
        return wert.isoformat()
    if isinstance(wert, date):
        return wert.isoformat()
    if isinstance(wert, bool):
        return int(wert)
    if hasattr(wert, "item"):
        try:
            return wert.item()
        except Exception:
            pass
    return wert


LOGIN_SPERREN_TABELLE = "login_sperren"

def login_sperre_tabelle_anlegen() -> None:
    try:
        with _verbindung() as conn:
            conn.execute('CREATE TABLE IF NOT EXISTS "login_sperren" ("Benutzername" TEXT PRIMARY KEY, "Fehlversuche" INTEGER NOT NULL DEFAULT 0, "Gesperrt_bis" TEXT, "Letzter_Fehlversuch" TEXT)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_login_sperren_bis ON "login_sperren"("Gesperrt_bis")')
            conn.commit()
    except Exception as exc:
        protokolliere("Login-Sperrtabelle konnte nicht angelegt werden", exc, logging.WARNING)

def _login_sperrstatus(benutzername: str) -> tuple[bool, datetime | None, int]:
    name = str(benutzername or "").strip().lower()
    if not name: return False, None, 0
    try:
        with _verbindung() as conn:
            row = conn.execute('SELECT "Fehlversuche", "Gesperrt_bis" FROM "login_sperren" WHERE "Benutzername"=?', (name,)).fetchone()
        if not row: return False, None, 0
        fehlversuche, gesperrt_bis = int(row[0] or 0), row[1]
        bis = datetime.fromisoformat(gesperrt_bis) if gesperrt_bis else None
        return bool(bis and bis > datetime.now()), bis, fehlversuche
    except Exception as exc:
        protokolliere("Login-Sperrstatus konnte nicht gelesen werden", exc, logging.WARNING)
        return False, None, 0

def login_fehlversuch(benutzername: str) -> tuple[bool, datetime | None]:
    name = str(benutzername or "").strip().lower()
    if not name: return False, None
    max_versuche = int(st.session_state.get("config", {}).get("max_login_versuche", MAX_LOGIN_VERSUCHE))
    dauer = int(st.session_state.get("config", {}).get("sperrdauer_minuten", SPERRDAUER_MINUTEN))
    jetzt = datetime.now()
    try:
        with _verbindung() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute('SELECT "Fehlversuche" FROM "login_sperren" WHERE "Benutzername"=?', (name,)).fetchone()
            fehlversuche = (int(row[0]) if row else 0) + 1
            bis = jetzt + timedelta(minutes=dauer) if fehlversuche >= max_versuche else None
            conn.execute('INSERT INTO "login_sperren" ("Benutzername", "Fehlversuche", "Gesperrt_bis", "Letzter_Fehlversuch") VALUES (?, ?, ?, ?) ON CONFLICT("Benutzername") DO UPDATE SET "Fehlversuche"=excluded."Fehlversuche", "Gesperrt_bis"=excluded."Gesperrt_bis", "Letzter_Fehlversuch"=excluded."Letzter_Fehlversuch"', (name, fehlversuche, bis.isoformat() if bis else None, jetzt.isoformat()))
            conn.commit()
        return bool(bis), bis
    except Exception as exc:
        protokolliere("Login-Fehlversuch konnte nicht gespeichert werden", exc, logging.WARNING)
        return False, None

def login_erfolg(benutzername: str) -> None:
    name = str(benutzername or "").strip().lower()
    if not name: return
    try:
        with _verbindung() as conn:
            conn.execute('DELETE FROM "login_sperren" WHERE "Benutzername"=?', (name,))
            conn.commit()
    except Exception as exc:
        protokolliere("Login-Sperre konnte nach erfolgreichem Login nicht gelöscht werden", exc, logging.WARNING)


TABELLEN_SCHLUESSEL = {
    "time_logs": "ID",
    "vacation_requests": "ID",
    "mitarbeiter_stammdaten": "MA-ID",
    "benutzer": "Benutzername",
    "arbeitszeitkalender": "KAL-ID",
    "kunden": "Kunden-ID",
    "projekte": "Projekt-ID",
}


def _zeilenvergleich(df: pd.DataFrame, schluessel: str) -> dict:
    """Erzeugt einen stabilen Index für den inkrementellen SQLite-Abgleich."""
    if df.empty or schluessel not in df.columns:
        return {}
    out = {}
    for _, row in df.iterrows():
        key = row.get(schluessel)
        if pd.isna(key) or str(key) == "":
            continue
        out[str(key)] = row.to_dict()
    return out


# ------------------------------------------------------------
# Mehrbenutzerbetrieb: Indizes, gezielte Abfragen, gemeinsame Einstellungen
# ------------------------------------------------------------
# Die App wird von mehreren Personen gleichzeitig genutzt (Handy + Büro).
# Deshalb gilt: Daten werden bei jedem Seitenaufbau frisch gelesen, jede Sitzung
# lädt nur ihren eigenen Datenausschnitt, und die Einstellungen liegen in der
# Datenbank statt in der Sitzung.

INDIZES = {
    "time_logs": ['CREATE INDEX IF NOT EXISTS idx_zeiten_ma_datum ON time_logs("Mitarbeiter", "Datum")',
                  'CREATE INDEX IF NOT EXISTS idx_zeiten_status ON time_logs("Status")'],
    "vacation_requests": ['CREATE INDEX IF NOT EXISTS idx_urlaub_ma ON vacation_requests("Mitarbeiter")',
                          'CREATE INDEX IF NOT EXISTS idx_urlaub_status ON vacation_requests("Status")'],
    "benutzer": ['CREATE INDEX IF NOT EXISTS idx_benutzer_name ON benutzer("Benutzername")'],
    "arbeitszeitkalender": ['CREATE INDEX IF NOT EXISTS idx_azkal_ma ON arbeitszeitkalender("MA-ID")'],
    "kunden": [
        'CREATE INDEX IF NOT EXISTS idx_kunden_nr ON kunden("Kundennummer")',
        'CREATE UNIQUE INDEX IF NOT EXISTS ux_kunden_kundennummer ON kunden("Kundennummer")',
    ],
    "projekte": [
        'CREATE INDEX IF NOT EXISTS idx_projekte_nr ON projekte("Projektnummer")',
        'CREATE UNIQUE INDEX IF NOT EXISTS ux_projekte_projektnummer ON projekte("Projektnummer")',
    ],
}


def eindeutige_nummer_pruefen(df: pd.DataFrame, spalte: str, nummer: str, eigene_id: str | None = None) -> bool:
    """Prüft, ob eine Kunden-/Projektnummer bereits vergeben ist."""
    nummer = str(nummer or "").strip()
    if not nummer or df.empty or spalte not in df.columns:
        return True
    mask = df[spalte].fillna("").astype(str).str.strip().str.casefold() == nummer.casefold()
    if eigene_id is not None and "Kunden-ID" in df.columns and spalte == "Kundennummer":
        mask &= df["Kunden-ID"].astype(str) != str(eigene_id)
    if eigene_id is not None and "Projekt-ID" in df.columns and spalte == "Projektnummer":
        mask &= df["Projekt-ID"].astype(str) != str(eigene_id)
    return not bool(mask.any())


def doppelte_nummern(df: pd.DataFrame, spalte: str) -> list[str]:
    if df.empty or spalte not in df.columns:
        return []
    werte = df[spalte].fillna("").astype(str).str.strip()
    werte = werte[werte != ""]
    return sorted(werte[werte.str.casefold().duplicated(keep=False)].unique().tolist())


def indizes_anlegen() -> None:
    """Legt fehlende Indizes an. Ohne sie wird jede Abfrage zum vollen Tabellenscan."""
    try:
        with _verbindung() as conn:
            for tabelle, befehle in INDIZES.items():
                if _tabelle_vorhanden(conn, tabelle):
                    for befehl in befehle:
                        conn.execute(befehl)
            conn.commit()
    except Exception as exc:
        protokolliere("Indizes konnten nicht angelegt werden", exc, logging.WARNING)


def _query_df(conn, sql: str, params=()) -> pd.DataFrame:
    """DBAPI-unabhängiges SELECT -> DataFrame."""
    cur = conn.execute(sql, params)
    rows = cur.fetchall()
    columns = [d.name if hasattr(d, "name") else d[0] for d in (cur.description or [])]
    return pd.DataFrame(rows, columns=columns)


def zeiten_abfragen(mitarbeiter: str | None = None,
                    von: date | None = None, bis: date | None = None) -> pd.DataFrame:
    """Liest Zeiteinträge gezielt aus der Datenbank statt die ganze Tabelle zu laden.

    Mitarbeitende laden dadurch nur ihre eigenen Daten – schneller und
    datenschutzrechtlich sauberer, weil nicht jede Sitzung die Zeiten aller
    Kolleginnen und Kollegen im Speicher hält.
    """
    leer = pd.DataFrame(columns=SPALTEN_ZEITEN)
    if not PERSISTENZ:
        return leer
    try:
        with _verbindung() as conn:
            if not _tabelle_vorhanden(conn, "time_logs"):
                return leer
            bedingungen, werte = [], []
            if mitarbeiter:
                bedingungen.append('"Mitarbeiter" = ?')
                werte.append(str(mitarbeiter))
            if von is not None:
                bedingungen.append('"Datum" >= ?')
                werte.append(von.isoformat())
            if bis is not None:
                bedingungen.append('"Datum" <= ?')
                werte.append(bis.isoformat())
            sql = 'SELECT * FROM "time_logs"'
            if bedingungen:
                sql += " WHERE " + " AND ".join(bedingungen)
            df = _query_df(conn, sql, werte)
        for spalte in df.columns:
            if spalte in DATUMSSPALTEN:
                df[spalte] = pd.to_datetime(df[spalte], errors="coerce").dt.date
        return _typen_angleichen(df, SPALTEN_ZEITEN)
    except Exception as exc:
        protokolliere("Zeitabfrage fehlgeschlagen", exc)
        return leer


# --- Gemeinsame Einstellungen ---------------------------------

EINSTELLUNGEN_TABELLE = "einstellungen"


def einstellungen_laden() -> dict:
    """Liest die betriebsweiten Einstellungen aus der Datenbank."""
    if not PERSISTENZ:
        return {}
    try:
        with _verbindung() as conn:
            conn.execute(f'CREATE TABLE IF NOT EXISTS "{EINSTELLUNGEN_TABELLE}" '
                         '("Schluessel" TEXT PRIMARY KEY, "Wert" TEXT)')
            conn.commit()
            zeilen = conn.execute(f'SELECT "Schluessel", "Wert" FROM "{EINSTELLUNGEN_TABELLE}"').fetchall()
        werte = {}
        for schluessel, wert in zeilen:
            try:
                werte[schluessel] = json.loads(wert)
            except Exception:
                werte[schluessel] = wert
        return werte
    except Exception as exc:
        protokolliere("Einstellungen konnten nicht geladen werden", exc)
        return {}


def einstellungen_speichern(werte: dict) -> bool:
    """Schreibt die Einstellungen betriebsweit – für alle Sitzungen gültig."""
    if not PERSISTENZ:
        return True
    try:
        with _verbindung() as conn:
            conn.execute(f'CREATE TABLE IF NOT EXISTS "{EINSTELLUNGEN_TABELLE}" '
                         '("Schluessel" TEXT PRIMARY KEY, "Wert" TEXT)')
            conn.execute("BEGIN IMMEDIATE")
            for schluessel, wert in werte.items():
                conn.execute(
                    f'INSERT INTO "{EINSTELLUNGEN_TABELLE}" ("Schluessel", "Wert") VALUES (?, ?) '
                    'ON CONFLICT("Schluessel") DO UPDATE SET "Wert" = excluded."Wert"',
                    (str(schluessel), json.dumps(wert, ensure_ascii=False)))
            conn.commit()
        return True
    except Exception as exc:
        protokolliere("Einstellungen konnten nicht gespeichert werden", exc)
        return False


def _tabellenspalten_synchronisieren(conn: sqlite3.Connection, key: str, spalten) -> None:
    """Fügt bei kleinen Schema-Erweiterungen fehlende SQLite-Spalten nachträglich hinzu."""
    if not _tabelle_vorhanden(conn, key):
        return
    if PRODUKTIONS_DB:
        vorhanden = {str(row[0]) for row in conn.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_schema='public' AND table_name=?", (key,)).fetchall()}
    else:
        vorhanden = {str(row[1]) for row in conn.execute(f'PRAGMA table_info("{key}")').fetchall()}
    for spalte in spalten:
        if spalte in vorhanden:
            continue
        # SQLite erlaubt ADD COLUMN ohne Tabellen-Rewrite; bestehende Zeilen erhalten NULL.
        quote = '"' + str(spalte).replace('"', '""') + '"'
        conn.execute(f'ALTER TABLE "{str(key).replace(chr(34), chr(34)*2)}" ADD COLUMN {quote} TEXT')


def _df_tabelle_anlegen(conn, key: str, df: pd.DataFrame) -> None:
    """Legt eine Tabelle direkt über die DB-API an; kein SQLAlchemy erforderlich."""
    cols = []
    schluessel = TABELLEN_SCHLUESSEL.get(key)
    for spalte in df.columns:
        serie = df[spalte]
        if pd.api.types.is_bool_dtype(serie):
            typ = "BOOLEAN" if PRODUKTIONS_DB else "INTEGER"
        elif pd.api.types.is_integer_dtype(serie):
            typ = "BIGINT" if PRODUKTIONS_DB else "INTEGER"
        elif pd.api.types.is_float_dtype(serie):
            typ = "DOUBLE PRECISION" if PRODUKTIONS_DB else "REAL"
        else:
            typ = "TEXT"
        q = '"' + str(spalte).replace('"', '""') + '"'
        cols.append(f"{q} {typ}")
    if schluessel and schluessel in df.columns:
        q = '"' + str(schluessel).replace('"', '""') + '"'
        cols.append(f"UNIQUE ({q})")
    conn.execute(f'CREATE TABLE IF NOT EXISTS "{key}" ({", ".join(cols)})')
    _df_zeilen_einfuegen(conn, key, df)


def _df_zeilen_einfuegen(conn, key: str, df: pd.DataFrame) -> None:
    if df.empty:
        return
    quote = lambda c: '"' + str(c).replace('"', '""') + '"'
    cols = list(df.columns)
    sql = f'INSERT INTO "{key}" ({", ".join(quote(c) for c in cols)}) VALUES ({", ".join("?" for _ in cols)})'
    for _, row in df.iterrows():
        conn.execute(sql, [_sqlite_wert(row.get(c)) for c in cols])


def _speichern_inkrementell(conn: sqlite3.Connection, key: str,
                            alt: pd.DataFrame, neu: pd.DataFrame) -> None:
    """Speichert nur echte Änderungen, statt die komplette Tabelle zu ersetzen.

    Dadurch können zwei gleichzeitig geöffnete Browser-Sitzungen unterschiedliche
    Datensätze bearbeiten, ohne sich gegenseitig mit einem veralteten DataFrame
    zu überschreiben. Änderungen an derselben Zeile bleiben bewusst 'last write wins'.
    """
    schluessel = TABELLEN_SCHLUESSEL.get(key)
    if not schluessel or schluessel not in neu.columns:
        _df_tabelle_anlegen(conn, key, _fuer_db(neu))
        return

    if not _tabelle_vorhanden(conn, key):
        _df_tabelle_anlegen(conn, key, _fuer_db(neu))
        return

    _tabellenspalten_synchronisieren(conn, key, neu.columns)
    alt_idx = _zeilenvergleich(alt, schluessel)
    neu_idx = _zeilenvergleich(neu, schluessel)

    alle_spalten = list(neu.columns)
    update_spalten = [c for c in alle_spalten if c != schluessel]
    quote = lambda c: '"' + str(c).replace('"', '""') + '"'
    table = quote(key)
    pk = quote(schluessel)

    # Gelöschte Datensätze
    for row_id in set(alt_idx) - set(neu_idx):
        conn.execute(f"DELETE FROM {table} WHERE {pk} = ?", (row_id,))

    # Neue und geänderte Datensätze
    for row_id, row in neu_idx.items():
        if row_id not in alt_idx:
            cols = [schluessel] + update_spalten
            values = [_sqlite_wert(row.get(c)) for c in cols]
            placeholders = ", ".join("?" for _ in cols)
            col_sql = ", ".join(quote(c) for c in cols)
            conn.execute(f"INSERT INTO {table} ({col_sql}) VALUES ({placeholders})", values)
            continue

        alt_row = alt_idx[row_id]
        geaendert = any(
            _sqlite_wert(alt_row.get(c)) != _sqlite_wert(row.get(c))
            for c in update_spalten
        )
        if geaendert and update_spalten:
            set_sql = ", ".join(f"{quote(c)} = ?" for c in update_spalten)
            values = [_sqlite_wert(row.get(c)) for c in update_spalten]
            values.append(row_id)
            conn.execute(f"UPDATE {table} SET {set_sql} WHERE {pk} = ?", values)


def speichern(key: str) -> bool:
    """Speichert Änderungen atomar und inkrementell in der konfigurierten Datenbank."""
    # Zwischenspeicher verwerfen, die von dieser Tabelle abhängen
    if key == "vacation_requests":
        st.session_state.pop("_abwesenheiten_cache", None)
    if not PERSISTENZ:
        return True

    try:
        neu = st.session_state[key].copy()
        snapshots = st.session_state.setdefault("_db_snapshots", {})
        alt = snapshots.get(key, pd.DataFrame(columns=neu.columns)).copy()

        with _verbindung() as conn:
            conn.execute("BEGIN IMMEDIATE")
            _speichern_inkrementell(conn, key, alt, neu)
            conn.commit()

        snapshots[key] = neu.copy(deep=True)
        return True
    except Exception as exc:
        protokolliere(f"Speichern fehlgeschlagen (Tabelle: {key})", exc)
        st.error(t(f"Daten konnten nicht gespeichert werden: {exc}",
                   f"Could not save data: {exc}"))
        return False



def _csv_pfad(key: str) -> Path:
    return DATEN_DIR / f"{key}.csv"


def _zu_bool(werte: pd.Series) -> pd.Series:
    """Erkennt sowohl 0/1 (aus SQLite) als auch 'True'/'False'-Text (aus alten CSV-Dateien)."""
    def einzelwert(x):
        if isinstance(x, bool):
            return x
        return str(x).strip().lower() in ("true", "1", "wahr", "1.0")
    return werte.apply(einzelwert)


def _typen_angleichen(df: pd.DataFrame, spalten: list[str]) -> pd.DataFrame:
    for spalte in ("Aktiv", "Passwort_wechseln"):
        if spalte in df.columns and df[spalte].dtype != bool:
            df[spalte] = _zu_bool(df[spalte])
    if "Passwort_Algorithmus" in df.columns:
        df["Passwort_Algorithmus"] = df["Passwort_Algorithmus"].fillna("pbkdf2-sha256").replace("", "pbkdf2-sha256")
    for spalte in spalten:
        if spalte not in df.columns:
            df[spalte] = pd.NA
    return df[spalten]


def _aus_alter_csv_migrieren(key: str, spalten: list[str]) -> pd.DataFrame | None:
    """Einmalige Übernahme einer CSV-Datei aus Versionen vor der Datenbank."""
    pfad = _csv_pfad(key)
    if not pfad.exists():
        return None
    try:
        df = pd.read_csv(pfad, encoding="utf-8", dtype=str, keep_default_na=False, na_values=[""])
    except Exception:
        return None
    for spalte in df.columns:
        if spalte in DATUMSSPALTEN:
            df[spalte] = pd.to_datetime(df[spalte], errors="coerce", dayfirst=True).dt.date
        elif spalte not in TEXTSPALTEN:
            umgewandelt = pd.to_numeric(df[spalte], errors="coerce")
            if umgewandelt.notna().sum() >= df[spalte].notna().sum():
                df[spalte] = umgewandelt
    return _typen_angleichen(df, spalten)


def laden(key: str, spalten: list[str]) -> pd.DataFrame | None:
    """Liest eine Tabelle aus der Datenbank; übernimmt bei Bedarf einmalig eine ältere CSV-Datei."""
    if not PERSISTENZ:
        return None
    try:
        with _verbindung() as conn:
            if _tabelle_vorhanden(conn, key):
                df = _query_df(conn, f'SELECT * FROM "{key}"')
                for spalte in df.columns:
                    if spalte in DATUMSSPALTEN:
                        df[spalte] = pd.to_datetime(df[spalte], errors="coerce").dt.date
                df = _typen_angleichen(df, spalten)
                st.session_state.setdefault("_db_snapshots", {})[key] = df.copy(deep=True)
                return df
    except Exception as exc:
        protokolliere(f"Laden fehlgeschlagen (Tabelle: {key})", exc)
        return None

    migriert = _aus_alter_csv_migrieren(key, spalten)
    if migriert is not None:
        st.session_state[key] = migriert
        speichern(key)
        return migriert
    return None


def neue_id() -> str:
    return uuid.uuid4().hex[:8]


def zeile_anhaengen(df: pd.DataFrame, zeile: dict) -> pd.DataFrame:
    neu = pd.DataFrame([zeile])[list(df.columns)]
    return neu if df.empty else pd.concat([df, neu], ignore_index=True)


# ============================================================
# 4. PASSWÖRTER & BENUTZERNAMEN
# ============================================================

def passwort_hash(passwort: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", passwort.encode("utf-8"), bytes.fromhex(salt), PBKDF2_ITERATIONEN).hex()

def scrypt_verfuegbar() -> bool:
    """Prüft einmalig, ob scrypt mit den konfigurierten Parametern läuft.

    Manche Umgebungen begrenzen den Speicher fester als von uns angefragt. Dann
    darf die App nicht beim Start abstürzen, sondern weicht auf PBKDF2 aus.
    """
    if "_scrypt_ok" not in st.session_state:
        try:
            # Einige Python-Builds (insbesondere ältere macOS-/LibreSSL-
            # Umgebungen) stellen hashlib.scrypt überhaupt nicht bereit.
            # Deshalb zuerst das Attribut prüfen, bevor es aufgerufen wird.
            scrypt = getattr(hashlib, "scrypt", None)
            if scrypt is None:
                raise RuntimeError("Diese Python-Umgebung stellt hashlib.scrypt nicht bereit.")
            scrypt(b"pruefung", salt=b"0123456789abcdef", n=SCRYPT_N, r=SCRYPT_R,
                   p=SCRYPT_P, dklen=SCRYPT_DKLEN, maxmem=SCRYPT_MAXMEM)
            st.session_state["_scrypt_ok"] = True
        except (ValueError, MemoryError, RuntimeError, OSError) as fehler:
            protokolliere("scrypt nicht verfügbar, weiche auf PBKDF2 aus", fehler, logging.WARNING)
            st.session_state["_scrypt_ok"] = False
    return bool(st.session_state["_scrypt_ok"])


def passwort_hash_neu(passwort: str, salt_hex: str | None = None) -> tuple[str, str]:
    """Erzeugt einen scrypt-Hash. Aufruf nur, wenn scrypt verfügbar ist."""
    salt = bytes.fromhex(salt_hex) if salt_hex else secrets.token_bytes(16)
    scrypt = getattr(hashlib, "scrypt", None)
    if scrypt is None:
        raise RuntimeError("hashlib.scrypt ist in dieser Python-Umgebung nicht verfügbar.")
    digest = scrypt(passwort.encode("utf-8"), salt=salt, n=SCRYPT_N, r=SCRYPT_R,
                    p=SCRYPT_P, dklen=SCRYPT_DKLEN, maxmem=SCRYPT_MAXMEM)
    return salt.hex(), digest.hex()

def passwort_pruefen(passwort: str, salt: str, hashwert: str, algorithmus: str | None) -> bool:
    if str(algorithmus or "").lower() == PASSWORT_ALGORITHMUS:
        try:
            _, digest = passwort_hash_neu(passwort, salt)
            return hmac.compare_digest(str(hashwert), digest)
        except (ValueError, TypeError, MemoryError) as fehler:
            protokolliere("Passwortprüfung mit scrypt fehlgeschlagen", fehler, logging.WARNING)
            return False
    return hmac.compare_digest(str(hashwert), passwort_hash(passwort, salt))

def passwort_neu_berechnen(passwort: str) -> tuple[str, str, str]:
    """Erzeugt Salt und Hash für ein neues Passwort – mit Rückfall auf PBKDF2."""
    if scrypt_verfuegbar():
        salt, digest = passwort_hash_neu(passwort)
        return salt, digest, PASSWORT_ALGORITHMUS
    salt = secrets.token_hex(16)
    return salt, passwort_hash(passwort, salt), "pbkdf2"

def neuer_benutzer_datensatz(benutzername: str, passwort: str, rolle: str,
                             ma_id: str = "", sprache: str = "de",
                             wechsel_erzwingen: bool = True) -> dict:
    salt, digest, algorithmus = passwort_neu_berechnen(passwort)
    return {
        "Benutzername": benutzername.strip().lower(),
        "Salt": salt,
        "Passwort_Hash": digest,
        "Rolle": rolle,
        "MA-ID": ma_id,
        "Sprache": sprache,
        "Aktiv": True,
        "Passwort_wechseln": wechsel_erzwingen,
        "Letzter Login": pd.NA,
        "Passwort_Algorithmus": algorithmus,
    }


def _ohne_umlaute(text: str) -> str:
    return logik.ohne_umlaute(text)


def benutzername_vorschlag(name: str, vergeben=()) -> str:
    return logik.benutzername_vorschlag(name, tuple(vergeben))


def passwort_regeln_verletzt(passwort: str, benutzername: str = "") -> str | None:
    mindestlaenge = int(st.session_state.get("config", {}).get("passwort_mindestlaenge", MIN_PASSWORTLAENGE))
    if len(passwort) < mindestlaenge:
        return t(f"Das Passwort muss mindestens {mindestlaenge} Zeichen lang sein.",
                 f"The password needs at least {mindestlaenge} characters.")
    if benutzername and passwort.lower() == benutzername.lower():
        return t("Das Passwort darf nicht dem Benutzernamen entsprechen.",
                 "The password must not match the username.")
    if passwort == START_PASSWORT:
        return t("Bitte ein eigenes Passwort wählen, nicht das Startpasswort.",
                 "Please choose your own password, not the initial one.")
    return None


# ============================================================
# 5. SYSTEMADMINISTRATOR / BOOTSTRAP
# ============================================================

def _systemadmin_initialpasswort() -> tuple[str, bool]:
    """Liefert das Bootstrap-Passwort; nur bei Erstinstallation wird eines erzeugt."""
    env_pw = os.getenv(SYSTEMADMIN_ENV, "").strip()
    if env_pw:
        return env_pw, False
    bootstrap = DATEN_DIR / "systemadmin_initial.txt"
    if bootstrap.exists():
        try:
            inhalt = bootstrap.read_text(encoding="utf-8")
            # Die Datei enthält bewusst einen kleinen Hinweistext. Als Passwort
            # darf nur der Wert hinter "Passwort:" verwendet werden.
            for zeile in inhalt.splitlines():
                if zeile.startswith("Passwort:"):
                    return zeile.split(":", 1)[1].strip(), True
        except OSError:
            pass
    # Neue Installationen erhalten ein zufälliges Bootstrap-Passwort.
    pw = secrets.token_urlsafe(18)
    DATEN_DIR.mkdir(parents=True, exist_ok=True)
    try:
        bootstrap.write_text(
            "MEINEZEIT – einmaliges Systemadministrator-Bootstrap-Passwort\n"
            "Benutzername: systemadmin\n"
            f"Passwort: {pw}\n\n"
            "Nach dem ersten Login sofort ändern und diese Datei löschen.",
            encoding="utf-8",
        )
    except OSError:
        pass
    return pw, True


def systemadmin_vorhanden() -> bool:
    df = st.session_state.get("benutzer", pd.DataFrame())
    return (not df.empty) and bool(((df["Benutzername"].astype(str).str.lower() == SYSTEMADMIN_USERNAME) &
                                     (df["Rolle"] == "Systemadministrator")).any())


def systemadmin_bootstrap_reparieren() -> None:
    """Repariert ältere Installationen, die den kompletten Bootstrap-Text gehasht haben."""
    bootstrap = DATEN_DIR / "systemadmin_initial.txt"
    if not bootstrap.exists():
        return
    pw, _ = _systemadmin_initialpasswort()
    if not pw or not systemadmin_vorhanden():
        return
    df = st.session_state.benutzer
    maske = ((df["Benutzername"].astype(str).str.lower() == SYSTEMADMIN_USERNAME) &
             (df["Rolle"].astype(str) == "Systemadministrator"))
    if not maske.any():
        return
    # Nur ein noch nicht abgeschlossener Bootstrap darf automatisch repariert werden.
    if bool(df.loc[maske, "Passwort_wechseln"].iloc[0]):
        salt = secrets.token_hex(16)
        df.loc[maske, "Salt"] = salt
        df.loc[maske, "Passwort_Hash"] = passwort_hash(pw, salt)
        if "Passwort_Algorithmus" in df.columns:
            df.loc[maske, "Passwort_Algorithmus"] = "pbkdf2-sha256"
        st.session_state.benutzer = df
        speichern("benutzer")


def systemadmin_anlegen_falls_noetig() -> None:
    """Legt das Betreiberkonto an und hält das Bootstrap-Passwort konsistent.

    Wichtig für bestehende Installationen: Die Bootstrap-Datei kann nach einem
    abgebrochenen ersten Start bereits vorhanden sein, während das Konto in der
    Datenbank noch fehlt oder einen anderen Hash besitzt. Solange der erzwungene
    Passwortwechsel noch offen ist, darf die Bootstrap-Datei daher einmalig als
    Quelle für die Zugangsdaten dienen. Nach dem Passwortwechsel wird die Datei
    gelöscht.
    """
    pw, bootstrap = _systemadmin_initialpasswort()
    fehler = passwort_regeln_verletzt(pw, SYSTEMADMIN_USERNAME)
    if fehler:
        raise RuntimeError(f"{SYSTEMADMIN_ENV} muss mindestens {MIN_PASSWORTLAENGE} Zeichen enthalten.")

    benutzer = st.session_state.get("benutzer")
    if benutzer is None:
        benutzer = laden("benutzer", SPALTEN_BENUTZER)
    if benutzer is None:
        benutzer = pd.DataFrame(columns=SPALTEN_BENUTZER)

    st.session_state.benutzer = benutzer
    maske = (
        st.session_state.benutzer["Benutzername"].astype(str).str.lower() == SYSTEMADMIN_USERNAME
    )

    if not maske.any():
        konto = neuer_benutzer_datensatz(
            SYSTEMADMIN_USERNAME, pw, "Systemadministrator", "", "de", wechsel_erzwingen=True
        )
        st.session_state.benutzer = zeile_anhaengen(st.session_state.benutzer, konto)
        speichern("benutzer")
        st.session_state.systemadmin_bootstrap_neu = bootstrap
        return

    # Bereits vorhandenes Betreiberkonto: Nur solange der Bootstrap-Passwortwechsel
    # noch offen ist synchronisieren. So wird ein vom Betreiber bereits gesetztes
    # eigenes Passwort niemals bei einem späteren App-Start überschrieben.
    idx = st.session_state.benutzer.index[maske][0]
    konto = st.session_state.benutzer.loc[idx]
    if bool(konto.get("Passwort_wechseln", False)) and (bootstrap or (SYSTEMADMIN_RECOVERY_PASSWORD and pw == SYSTEMADMIN_RECOVERY_PASSWORD)):
        salt = secrets.token_hex(16)
        st.session_state.benutzer.loc[idx, "Salt"] = salt
        st.session_state.benutzer.loc[idx, "Passwort_Hash"] = passwort_hash(pw, salt)
        st.session_state.benutzer.loc[idx, "Rolle"] = "Systemadministrator"
        st.session_state.benutzer.loc[idx, "Aktiv"] = True
        st.session_state.benutzer.loc[idx, "MA-ID"] = ""
        speichern("benutzer")


def rolle_erlaubt(*rollen: str) -> bool:
    return bool(st.session_state.get("logged_in")) and st.session_state.get("role") in set(rollen)

def require_role(*rollen: str) -> None:
    if not rolle_erlaubt(*rollen):
        raise PermissionError("Nicht ausreichende Berechtigung")

def systemadmin_kann_ausfuehren() -> bool:
    return rolle_erlaubt("Systemadministrator")


# ============================================================
# 5. SESSION-STATE INITIALISIEREN
# ============================================================

STANDARD_CONFIG = {
    "firmenname": "Musterbetrieb GmbH",
    "branche": "Handwerk / Bau",
    "pause_schwelle_1": 6.0,
    "pause_dauer_1": 30,
    "pause_schwelle_2": 9.0,
    "pause_dauer_2": 45,
    "urlaub_in_arbeitstagen": True,
    "feiertage_beruecksichtigen": True,
    "bundesland": "BY",
    "nachtschicht_erlaubt": True,
    "live_stempeln_aktiv": True,
    "passwort_mindestlaenge": 10,
    "max_login_versuche": 5,
    "sperrdauer_minuten": 5,
}


def _erstbefuellung() -> None:
    """Legt Tabellen und Beispieldaten an – nur wenn die Datenbank noch leer ist."""
    global START_PASSWORT
    if not START_PASSWORT:
        START_PASSWORT = secrets.token_urlsafe(12)
    if laden("mitarbeiter_stammdaten", SPALTEN_STAMM) is None:
        st.session_state.mitarbeiter_stammdaten = pd.DataFrame(
            [
                {"MA-ID": "ma-0001", "Mitarbeiter": "Anna Müller", "Personalnummer": "1001",
                 "Wochenstunden": 40.0, "Urlaub_Pro_Jahr": 30, "Resturlaub_Vorjahr": 2,
                 "Nachtrag_Std_Limit": STANDARD_NACHTRAGSLIMIT, "Aktiv": True},
                {"MA-ID": "ma-0002", "Mitarbeiter": "Ben Schmidt", "Personalnummer": "1002",
                 "Wochenstunden": 40.0, "Urlaub_Pro_Jahr": 30, "Resturlaub_Vorjahr": 0,
                 "Nachtrag_Std_Limit": 48.0, "Aktiv": True},
                {"MA-ID": "ma-0003", "Mitarbeiter": "Clara Meier", "Personalnummer": "1003",
                 "Wochenstunden": 30.0, "Urlaub_Pro_Jahr": 28, "Resturlaub_Vorjahr": 5,
                 "Nachtrag_Std_Limit": STANDARD_NACHTRAGSLIMIT, "Aktiv": True},
            ],
            columns=SPALTEN_STAMM,
        )
        speichern("mitarbeiter_stammdaten")

    if laden("vacation_requests", SPALTEN_URLAUB) is None:
        st.session_state.vacation_requests = pd.DataFrame(columns=SPALTEN_URLAUB)
        speichern("vacation_requests")

    if laden("arbeitszeitkalender", SPALTEN_ARBEITSZEITKALENDER) is None:
        st.session_state.arbeitszeitkalender = pd.DataFrame(columns=SPALTEN_ARBEITSZEITKALENDER)
        speichern("arbeitszeitkalender")

    if laden("benutzer", SPALTEN_BENUTZER) is None:
        datensaetze, vergeben = [], set()
        stamm = st.session_state.get("mitarbeiter_stammdaten", pd.DataFrame(columns=SPALTEN_STAMM))
        for _, person in stamm.iterrows():
            benutzername = benutzername_vorschlag(str(person["Mitarbeiter"]), vergeben)
            vergeben.add(benutzername)
            datensaetze.append(neuer_benutzer_datensatz(
                benutzername, START_PASSWORT, "Mitarbeiter", str(person["MA-ID"])))
        st.session_state.benutzer = pd.DataFrame(datensaetze, columns=SPALTEN_BENUTZER)
        speichern("benutzer")

    if laden("kunden", SPALTEN_KUNDEN) is None:
        st.session_state.kunden = pd.DataFrame(columns=SPALTEN_KUNDEN)
        speichern("kunden")
    if laden("projekte", SPALTEN_PROJEKTE) is None:
        st.session_state.projekte = pd.DataFrame(columns=SPALTEN_PROJEKTE)
        speichern("projekte")

    if not einstellungen_laden():
        einstellungen_speichern(STANDARD_CONFIG)

    indizes_anlegen()


def _stammdaten_nachziehen(df: pd.DataFrame) -> pd.DataFrame:
    """Ergänzt Felder, die in älteren Datenbeständen fehlen."""
    fehlend = df["MA-ID"].isna() | (df["MA-ID"].astype(str).str.strip() == "")
    if fehlend.any():
        df.loc[fehlend, "MA-ID"] = [f"ma-{uuid.uuid4().hex[:6]}" for _ in range(int(fehlend.sum()))]
    df["Nachtrag_Std_Limit"] = pd.to_numeric(
        df["Nachtrag_Std_Limit"], errors="coerce").fillna(STANDARD_NACHTRAGSLIMIT)
    return df


def _urlaub_nachziehen(df: pd.DataFrame) -> pd.DataFrame:
    df["Einheit"] = df["Einheit"].fillna("Tage").replace("", "Tage")
    df["Stunden"] = pd.to_numeric(df["Stunden"], errors="coerce").fillna(0.0)
    df["Tage"] = pd.to_numeric(df["Tage"], errors="coerce").fillna(0).astype(int)
    return df


def _benutzer_nachziehen(df: pd.DataFrame) -> pd.DataFrame:
    df["Sprache"] = df["Sprache"].fillna("de").replace("", "de")
    return df


def standard_arbeitszeitarten(branche_key: str | None = None) -> list[str]:
    key = branche_key or cfg("branche")
    return [de for de, _ in BRANCHEN.get(key, BRANCHEN["Allgemein / Büro"])["kategorien"]]


def standard_abwesenheitsarten() -> list[tuple[str, str, bool]]:
    return list(ABWESENHEITSARTEN)


def arbeitszeitarten() -> list[str]:
    """Vom Systemadmin ausgerollte und vom Kunden anpassbare Arbeitszeitarten."""
    werte = st.session_state.get("config", {}).get("arbeitszeitarten")
    if not isinstance(werte, list) or not werte:
        return standard_arbeitszeitarten()
    return [str(x).strip() for x in werte if str(x).strip()]


def abwesenheitsarten() -> list[tuple[str, str, bool]]:
    """Vom Systemadmin ausgerollte und vom Kunden anpassbare Abwesenheitsarten."""
    werte = st.session_state.get("config", {}).get("abwesenheitsarten")
    if not isinstance(werte, list) or not werte:
        return standard_abwesenheitsarten()
    result = []
    for item in werte:
        if isinstance(item, dict):
            name = str(item.get("name", "")).strip()
            erlaubt = bool(item.get("stundenweise", False))
        else:
            name = str(item).strip()
            erlaubt = False
        if name:
            result.append((name, name, erlaubt))
    return result or standard_abwesenheitsarten()


def arbeitszeitart_gebucht(name: str) -> bool:
    logs = st.session_state.get("time_logs", pd.DataFrame())
    return not logs.empty and (logs["Kategorie"].astype(str).str.strip() == str(name).strip()).any()


def abwesenheitsart_gebucht(name: str) -> bool:
    df = st.session_state.get("vacation_requests", pd.DataFrame())
    return not df.empty and (df["Art"].astype(str).str.strip() == str(name).strip()).any()


def konfig_arten_nachziehen() -> None:
    """Migriert ältere Konfigurationen auf die branchenspezifischen Listen."""
    cfgdata = st.session_state.setdefault("config", {})
    if not isinstance(cfgdata.get("arbeitszeitarten"), list) or not cfgdata.get("arbeitszeitarten"):
        cfgdata["arbeitszeitarten"] = standard_arbeitszeitarten(str(cfgdata.get("branche", "Allgemein / Büro")))
    if not isinstance(cfgdata.get("abwesenheitsarten"), list) or not cfgdata.get("abwesenheitsarten"):
        cfgdata["abwesenheitsarten"] = [
            {"name": de, "stundenweise": erlaubt} for de, _, erlaubt in ABWESENHEITSARTEN
        ]




def beschriftungen_neu_aufbauen() -> None:
    """Baut die Nachschlagetabellen für Kunden- und Projektnamen einmal je Seitenaufbau."""
    kunden_map = {}
    df_k = st.session_state.get("kunden")
    if df_k is not None and not df_k.empty:
        for kid, name, nummer in zip(df_k["Kunden-ID"].astype(str), df_k["Kunde"].astype(str),
                                     df_k.get("Kundennummer", pd.Series([""] * len(df_k))).astype(str)):
            kunden_map[kid] = f"{name} · {nummer}" if nummer.strip() and nummer != "nan" else name
    st.session_state["_kunden_beschriftung"] = kunden_map

    projekt_map = {}
    df_p = st.session_state.get("projekte")
    if df_p is not None and not df_p.empty:
        for pid, name, nummer in zip(df_p["Projekt-ID"].astype(str), df_p["Projekt"].astype(str),
                                     df_p.get("Projektnummer", pd.Series([""] * len(df_p))).astype(str)):
            projekt_map[pid] = f"{name} · {nummer}" if nummer.strip() and nummer != "nan" else name
    st.session_state["_projekt_beschriftung"] = projekt_map


def daten_aktualisieren() -> None:
    """Liest die gemeinsamen Tabellen bei JEDEM Seitenaufbau neu ein.

    Entscheidend im Mehrbenutzerbetrieb: Ohne das arbeitet jede Sitzung auf dem
    Stand ihres Anmeldezeitpunkts – ein Export für die Lohnabrechnung würde dann
    alle Buchungen übersehen, die seitdem auf den Handys entstanden sind.
    """
    stamm = laden("mitarbeiter_stammdaten", SPALTEN_STAMM)
    st.session_state.mitarbeiter_stammdaten = (
        _stammdaten_nachziehen(stamm) if stamm is not None
        else pd.DataFrame(columns=SPALTEN_STAMM))

    urlaub = laden("vacation_requests", SPALTEN_URLAUB)
    if urlaub is not None and not urlaub.empty:
        for spalte in ("Entscheidungsgrund", "Erfasst von"):
            urlaub[spalte] = urlaub[spalte].fillna("").astype(str).replace({"nan": "", "<NA>": ""})
    st.session_state.vacation_requests = (
        _urlaub_nachziehen(urlaub) if urlaub is not None
        else pd.DataFrame(columns=SPALTEN_URLAUB))

    kalender = laden("arbeitszeitkalender", SPALTEN_ARBEITSZEITKALENDER)
    if kalender is not None and not kalender.empty:
        # Altbestände ohne eindeutigen Schlüssel nachziehen
        fehlt = kalender["KAL-ID"].isna() | (kalender["KAL-ID"].astype(str).str.strip() == "")
        if fehlt.any():
            kalender.loc[fehlt, "KAL-ID"] = (
                kalender.loc[fehlt, "MA-ID"].astype(str) + "-"
                + pd.to_numeric(kalender.loc[fehlt, "Wochentag"], errors="coerce").fillna(0).astype(int).astype(str))
    st.session_state.arbeitszeitkalender = (
        kalender if kalender is not None
        else pd.DataFrame(columns=SPALTEN_ARBEITSZEITKALENDER))

    konten = laden("benutzer", SPALTEN_BENUTZER)
    st.session_state.benutzer = (
        _benutzer_nachziehen(konten) if konten is not None
        else pd.DataFrame(columns=SPALTEN_BENUTZER))

    kunden = laden("kunden", SPALTEN_KUNDEN)
    st.session_state.kunden = kunden if kunden is not None else pd.DataFrame(columns=SPALTEN_KUNDEN)
    projekte = laden("projekte", SPALTEN_PROJEKTE)
    st.session_state.projekte = projekte if projekte is not None else pd.DataFrame(columns=SPALTEN_PROJEKTE)

    # Nachschlagetabellen für Kunden- und Projektnamen. Ohne sie filtert die App
    # für jede einzelne Tabellenzeile den kompletten DataFrame – bei 800 Zeilen
    # sind das über 400 ms pro Seitenaufbau, mit den Tabellen unter 1 ms.
    beschriftungen_neu_aufbauen()
    st.session_state.pop("_abwesenheiten_cache", None)

    gespeichert = einstellungen_laden()
    st.session_state.config = {**STANDARD_CONFIG, **gespeichert}

    # Einmalige Angleichung: Personen mit Leitungs-/Adminkonto bekommen ein
    # unbegrenztes Nachtragsfenster. Das läuft bewusst nur EINMAL pro Datenbank –
    # sonst würde ein bewusst gesetztes kürzeres Fenster bei jedem Seitenaufbau
    # wieder überschrieben.
    if not st.session_state.config.get("migration_nachtrag_leitung"):
        stammdaten = st.session_state.mitarbeiter_stammdaten
        konten = st.session_state.benutzer
        if not stammdaten.empty and not konten.empty:
            leitung_ids = set(konten.loc[
                konten["Rolle"].astype(str).isin(["Leitung / Admin", "Systemadministrator"]),
                "MA-ID"].astype(str))
            if leitung_ids:
                limit = pd.to_numeric(stammdaten["Nachtrag_Std_Limit"], errors="coerce")
                anpassen = (stammdaten["MA-ID"].astype(str).isin(leitung_ids)
                            & (limit < NACHTRAG_UNBEGRENZT_AB))
                if anpassen.any():
                    stammdaten.loc[anpassen, "Nachtrag_Std_Limit"] = NACHTRAG_UNBEGRENZT
                    st.session_state.mitarbeiter_stammdaten = stammdaten
                    speichern("mitarbeiter_stammdaten")
            st.session_state.config["migration_nachtrag_leitung"] = True
            einstellungen_speichern({"migration_nachtrag_leitung": True})
    konfig_arten_nachziehen()


def arbeitszeiten_aktualisieren() -> None:
    """Lädt den Zeit-Datenausschnitt der angemeldeten Person – ebenfalls bei jedem Aufbau.

    Mitarbeitende bekommen nur ihre eigenen Einträge, die Leitung den vollen
    Bestand, weil sie freigeben und auswerten muss.
    """
    if st.session_state.get("role") == "Mitarbeiter":
        df = zeiten_abfragen(mitarbeiter=st.session_state.get("user"))
    else:
        df = zeiten_abfragen()
    st.session_state.time_logs = df
    st.session_state.setdefault("_db_snapshots", {})["time_logs"] = df.copy(deep=True)


if "_erstbefuellung_erledigt" not in st.session_state:
    _erstbefuellung()
    st.session_state._erstbefuellung_erledigt = True
    systemadmin_anlegen_falls_noetig()
    systemadmin_bootstrap_reparieren()
    login_sperre_tabelle_anlegen()
    backup_beim_app_start()

daten_aktualisieren()

# Falls der Systemadmin bereits existiert, aber aus einer älteren Version stammt,
# wird ein noch offener Bootstrap einmalig auf das tatsächlich angezeigte Passwort
# korrigiert. Danach bleibt der normale Passwortwechsel verpflichtend.
systemadmin_bootstrap_reparieren()

if "time_logs" not in st.session_state:
    st.session_state.time_logs = pd.DataFrame(columns=SPALTEN_ZEITEN)

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.role = None
    st.session_state.user = None
    st.session_state.username = None
    st.session_state.ma_id = None
    st.session_state.passwort_wechseln = False
    st.session_state.login_versuche = 0
    st.session_state.gesperrt_bis = None


def cfg(schluessel: str):
    return st.session_state.config[schluessel]


def branche() -> dict:
    return BRANCHEN.get(cfg("branche"), BRANCHEN["Allgemein / Büro"])


def branche_label(schluessel: str) -> str:
    eintrag = BRANCHEN.get(schluessel, BRANCHEN["Allgemein / Büro"])
    return eintrag["label"][1] if ist_englisch() else eintrag["label"][0]


def projekt_label() -> str:
    paar = branche()["projekt_label"]
    return paar[1] if ist_englisch() else paar[0]


def kunden_projekte_aktiv() -> bool:
    return cfg("branche") in {"Handwerk / Bau", "Dienstleistung / Beratung"}


def aktive_kunden_df() -> pd.DataFrame:
    df = st.session_state.get("kunden", pd.DataFrame(columns=SPALTEN_KUNDEN))
    if df.empty:
        return df
    return df[df["Aktiv"].apply(lambda x: bool(x))].copy()


def aktive_projekte_df(kunden_id: str | None = None) -> pd.DataFrame:
    df = st.session_state.get("projekte", pd.DataFrame(columns=SPALTEN_PROJEKTE))
    if df.empty:
        return df
    df = df[df["Aktiv"].apply(lambda x: bool(x))].copy()
    if kunden_id and kunden_id != "__ALLE__":
        df = df[df["Kunden-ID"].astype(str) == str(kunden_id)]
    return df


def projekt_optionen_fuer_kunde(kunden_id: str | None) -> list[str]:
    """Liefert nur Projekte des gewählten Kunden. Ohne Kunde ist kein Projekt auswählbar."""
    if not kunden_id or kunden_id == "__KEINER__":
        return ["__KEINER__"]
    pdf = aktive_projekte_df(kunden_id)
    return ["__KEINER__"] + (pdf["Projekt-ID"].astype(str).tolist() if not pdf.empty else [])


def projekt_widget_normalisieren(widget_key: str, optionen: list[str]) -> None:
    """Setzt eine alte Projektauswahl zurück, wenn sie nach dem Kundenwechsel nicht mehr gültig ist."""
    if st.session_state.get(widget_key) not in optionen:
        st.session_state[widget_key] = optionen[0]


def kunden_label(kunden_id: str) -> str:
    return st.session_state.get("_kunden_beschriftung", {}).get(str(kunden_id), "—")


def projekt_label_id(projekt_id: str) -> str:
    return st.session_state.get("_projekt_beschriftung", {}).get(str(projekt_id), "—")


def zeit_mit_kunden_projekten(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()
    if "Kunde-ID" not in out.columns: out["Kunde-ID"] = ""
    if "Projekt-ID" not in out.columns: out["Projekt-ID"] = ""
    if "Projekt" not in out.columns: out["Projekt"] = ""
    kmap = st.session_state.get("_kunden_beschriftung", {})
    pmap = st.session_state.get("_projekt_beschriftung", {})
    out["Kunde"] = out["Kunde-ID"].astype(str).map(lambda x: kmap.get(x, "—") if x and x != "nan" else "—")
    # Vektorisiert statt zeilenweise: fällt auf den gespeicherten Projektnamen zurück,
    # wenn keine Projekt-ID hinterlegt ist (z.B. bei Branchen ohne Projektmodul).
    projekt_ids = out["Projekt-ID"].astype(str)
    projekt_texte = out["Projekt"].astype(str).replace({"nan": "", "None": ""})
    out["Projekt"] = [
        pmap.get(pid, "—") if pid and pid != "nan" else (text or "—")
        for pid, text in zip(projekt_ids, projekt_texte)
    ]
    return out


def kategorien() -> list[str]:
    """Intern gespeicherte (deutsche) Kategoriewerte der aktuellen Branche."""
    return arbeitszeitarten()



# ============================================================
# 6. FACHLOGIK
# ============================================================

def regeln() -> Regeln:
    """Aktuelles Regelwerk aus den betriebsweiten Einstellungen."""
    return Regeln.aus_dict(st.session_state.get("config", {}))


def ostersonntag(jahr: int) -> date:
    return logik.ostersonntag(jahr)


def buss_und_bettag(jahr: int) -> date:
    return logik.buss_und_bettag(jahr)


def feiertage(jahr: int, bundesland: str = "BY") -> frozenset:
    return logik.feiertage(jahr, bundesland)


FEIERTAGSNAMEN = {
    "Neujahr": ("Neujahr", "New Year's Day"),
    "Heilige Drei Könige": ("Heilige Drei Könige", "Epiphany"),
    "Internationaler Frauentag": ("Internationaler Frauentag", "International Women's Day"),
    "Karfreitag": ("Karfreitag", "Good Friday"),
    "Ostersonntag": ("Ostersonntag", "Easter Sunday"),
    "Ostermontag": ("Ostermontag", "Easter Monday"),
    "Tag der Arbeit": ("Tag der Arbeit", "Labour Day"),
    "Christi Himmelfahrt": ("Christi Himmelfahrt", "Ascension Day"),
    "Pfingstsonntag": ("Pfingstsonntag", "Whit Sunday"),
    "Pfingstmontag": ("Pfingstmontag", "Whit Monday"),
    "Fronleichnam": ("Fronleichnam", "Corpus Christi"),
    "Mariä Himmelfahrt": ("Mariä Himmelfahrt", "Assumption Day"),
    "Weltkindertag": ("Weltkindertag", "World Children's Day"),
    "Tag der Deutschen Einheit": ("Tag der Deutschen Einheit", "German Unity Day"),
    "Reformationstag": ("Reformationstag", "Reformation Day"),
    "Allerheiligen": ("Allerheiligen", "All Saints' Day"),
    "Buß- und Bettag": ("Buß- und Bettag", "Day of Repentance"),
    "1. Weihnachtstag": ("1. Weihnachtstag", "Christmas Day"),
    "2. Weihnachtstag": ("2. Weihnachtstag", "Boxing Day"),
}


def feiertage_benannt(jahr: int, bundesland: str) -> list:
    """Liste (Datum, Name) der Feiertage – für die Vorschau in den Einstellungen."""
    return list(logik.feiertage_benannt(jahr, bundesland))


def ist_arbeitstag(tag: date) -> bool:
    return logik.ist_arbeitstag(tag, regeln())


def arbeitstage_zwischen(von: date, bis: date) -> int:
    return logik.arbeitstage_zwischen(von, bis, regeln())


def pause_gesetzlich(brutto_stunden: float) -> int:
    return logik.pause_gesetzlich(brutto_stunden, regeln())


def berechne_arbeitszeit(kommen: time, gehen: time, pause_manuell=None):
    """Wie logik.berechne_arbeitszeit, übersetzt die Fehlermeldung aber für die Oberfläche."""
    try:
        return logik.berechne_arbeitszeit(kommen, gehen, regeln(), pause_manuell)
    except ZeitFehler as fehler:
        if fehler.schluessel == "gehen_vor_kommen":
            raise ValueError(t("Die Gehen-Zeit muss nach der Kommen-Zeit liegen.",
                               "The end time must be after the start time.")) from fehler
        raise ValueError(t("Die erfasste Zeitspanne ist länger als 24 Stunden.",
                           "The recorded period is longer than 24 hours.")) from fehler


def parse_zeit(wert):
    return logik.parse_zeit(wert)


def aktive_mitarbeiter() -> list:
    df = st.session_state.mitarbeiter_stammdaten
    if df.empty:
        return []
    aktiv = df[df["Aktiv"].fillna(True).astype(bool)]
    return sorted(aktiv["Mitarbeiter"].astype(str).tolist())


def alle_mitarbeiter() -> pd.DataFrame:
    return st.session_state.mitarbeiter_stammdaten


def id_zu_name(ma_id) -> str:
    """Löst die stabile MA-ID in den aktuellen Klarnamen auf."""
    if ma_id is None or str(ma_id).strip() in ("", "nan", "<NA>"):
        return ""
    df = st.session_state.mitarbeiter_stammdaten
    treffer = df[df["MA-ID"].astype(str) == str(ma_id)]
    return "" if treffer.empty else str(treffer.iloc[0]["Mitarbeiter"])


def person_umbenennen(alt: str, neu: str) -> int:
    """Zieht eine Namenskorrektur durch alle Tabellen nach."""
    betroffen = 0
    for schluessel in ("time_logs", "vacation_requests"):
        df = st.session_state[schluessel]
        if df.empty:
            continue
        maske = df["Mitarbeiter"].astype(str) == alt
        betroffen += int(maske.sum())
        if maske.any():
            df.loc[maske, "Mitarbeiter"] = neu
            st.session_state[schluessel] = df
            speichern(schluessel)
    return betroffen


def demo_zuruecksetzen(branche_key: str, firmenname: str) -> None:
    """Füllt die App mit branchenpassenden Beispieldaten für eine Kundenvorführung.

    Eigene Admin-Konten bleiben unangetastet, damit die Vorführende Person eingeloggt
    bleibt. Nur Mitarbeitende, deren Zeiten und Anträge werden ausgetauscht.
    """
    heute = date.today()
    branchendaten = BRANCHEN[branche_key]
    kategorie_haupt = branchendaten["kategorien"][0][0]
    kategorie_zweit = branchendaten["kategorien"][1][0] if len(branchendaten["kategorien"]) > 1 \
        else kategorie_haupt

    # 1) Neue Stammdaten
    neue_stamm = []
    for person in DEMO_MITARBEITER[branche_key]:
        neue_stamm.append({
            "MA-ID": f"ma-{uuid.uuid4().hex[:6]}", "Mitarbeiter": person["name"],
            "Personalnummer": str(1000 + len(neue_stamm) + 1),
            "Wochenstunden": person["wochenstunden"], "Urlaub_Pro_Jahr": person["urlaub"],
            "Resturlaub_Vorjahr": person["rest"], "Nachtrag_Std_Limit": STANDARD_NACHTRAGSLIMIT,
            "Aktiv": True,
        })
    st.session_state.mitarbeiter_stammdaten = pd.DataFrame(neue_stamm, columns=SPALTEN_STAMM)
    st.session_state.arbeitszeitkalender = pd.DataFrame(columns=SPALTEN_ARBEITSZEITKALENDER)

    # 2) Benutzerkonten: eigene Admin-Konten bleiben, Mitarbeiterkonten werden ersetzt
    admins = st.session_state.benutzer[st.session_state.benutzer["Rolle"] == "Leitung / Admin"]
    vergeben = set(admins["Benutzername"].astype(str))
    neue_konten = [admins]
    for stamm, demo in zip(neue_stamm, DEMO_MITARBEITER[branche_key]):
        benutzername = benutzername_vorschlag(demo["name"], vergeben)
        vergeben.add(benutzername)
        neue_konten.append(pd.DataFrame([
            neuer_benutzer_datensatz(benutzername, START_PASSWORT, "Mitarbeiter",
                                     stamm["MA-ID"], st.session_state.sprache,
                                     wechsel_erzwingen=False)
        ]))
    st.session_state.benutzer = pd.concat(neue_konten, ignore_index=True)

    # 3) Kunden und Projekte für auftragsbezogene Branchen
    if branche_key in {"Handwerk / Bau", "Dienstleistung / Beratung"}:
        kunden_demo = [
            {"Kunden-ID": "kd-demo-01", "Kundennummer": "K-1001", "Kunde": "Musterkunde GmbH", "Ansprechpartner": "Thomas Muster", "Telefon": "089 123456", "E-Mail": "kontakt@musterkunde.de", "Straße": "Musterstraße 12", "PLZ": "80331", "Ort": "München", "Aktiv": True, "Notiz": "Demo-Kunde"},
            {"Kunden-ID": "kd-demo-02", "Kundennummer": "K-1002", "Kunde": "Beispiel Immobilien GmbH", "Ansprechpartner": "Anna Beispiel", "Telefon": "089 654321", "E-Mail": "info@beispiel-immobilien.de", "Straße": "Hauptstraße 8", "PLZ": "80802", "Ort": "München", "Aktiv": True, "Notiz": "Demo-Kunde"},
            {"Kunden-ID": "kd-demo-03", "Kundennummer": "K-1003", "Kunde": "Stadt & Partner", "Ansprechpartner": "Max Stadt", "Telefon": "089 987654", "E-Mail": "office@stadt-partner.de", "Straße": "Rathausplatz 1", "PLZ": "80333", "Ort": "München", "Aktiv": True, "Notiz": "Demo-Kunde"},
        ]
        projekte_demo = [
            {"Projekt-ID": "pr-demo-01", "Projektnummer": "P-2001", "Projekt": "Neubau Musterstraße 12", "Kunden-ID": "kd-demo-01", "Status": "Laufend", "Startdatum": heute - timedelta(days=30), "Enddatum": heute + timedelta(days=120), "Stundensatz": 75.0, "Aktiv": True, "Notiz": "Demo-Projekt"},
            {"Projekt-ID": "pr-demo-02", "Projektnummer": "P-2002", "Projekt": "Sanierung Rathausplatz", "Kunden-ID": "kd-demo-03", "Status": "Laufend", "Startdatum": heute - timedelta(days=14), "Enddatum": heute + timedelta(days=90), "Stundensatz": 82.5, "Aktiv": True, "Notiz": "Demo-Projekt"},
            {"Projekt-ID": "pr-demo-03", "Projektnummer": "P-2003", "Projekt": "Bürogebäude Nord", "Kunden-ID": "kd-demo-02", "Status": "Offen", "Startdatum": heute, "Enddatum": None, "Stundensatz": 75.0, "Aktiv": True, "Notiz": "Demo-Projekt"},
        ]
        st.session_state.kunden = pd.DataFrame(kunden_demo, columns=SPALTEN_KUNDEN)
        st.session_state.projekte = pd.DataFrame(projekte_demo, columns=SPALTEN_PROJEKTE)
    else:
        st.session_state.kunden = pd.DataFrame(columns=SPALTEN_KUNDEN)
        st.session_state.projekte = pd.DataFrame(columns=SPALTEN_PROJEKTE)

    # 4) Beispiel-Zeiten der letzten Tage
    zeilen = []
    for i, (stamm, demo) in enumerate(zip(neue_stamm, DEMO_MITARBEITER[branche_key])):
        for tag_offset, (kommen, gehen, kategorie, status) in enumerate([
            (time(8, 0), time(16, 30), kategorie_haupt, "Freigegeben"),
            (time(7, 45), time(16, 15), kategorie_haupt, "Erfasst"),
            (time(8, 15), time(12, 0), kategorie_zweit, "Erfasst"),
        ]):
            tag = heute - timedelta(days=1 + i + tag_offset * 2)
            if tag.weekday() >= 5:
                continue
            brutto, pause, netto = berechne_arbeitszeit(kommen, gehen)
            zeilen.append({
                "ID": neue_id(), "Mitarbeiter": stamm["Mitarbeiter"], "Datum": tag,
                "Kommen": kommen.strftime(ZEITFORMAT), "Gehen": gehen.strftime(ZEITFORMAT),
                "Brutto (Std)": brutto, "Pause (Min)": pause, "Netto (Std)": netto,
                "Kategorie": kategorie,
                "Kunde-ID": ("kd-demo-01" if i == 0 else "kd-demo-03" if i == 1 else "kd-demo-02") if branche_key in {"Handwerk / Bau", "Dienstleistung / Beratung"} else "",
                "Projekt-ID": ("pr-demo-01" if i == 0 else "pr-demo-02" if i == 1 else "pr-demo-03") if branche_key in {"Handwerk / Bau", "Dienstleistung / Beratung"} else "",
                "Projekt": demo["projekt"], "Notiz": "",
                "Typ": "Manuell", "Status": status,
            })
    st.session_state.time_logs = pd.DataFrame(zeilen, columns=SPALTEN_ZEITEN)

    # 5) Ein Beispiel-Urlaubsantrag zur Veranschaulichung
    erste = neue_stamm[0]
    st.session_state.vacation_requests = pd.DataFrame([{
        "ID": neue_id(), "Mitarbeiter": erste["Mitarbeiter"],
        "Startdatum": heute + timedelta(days=10), "Enddatum": heute + timedelta(days=14),
        "Einheit": "Tage", "Tage": arbeitstage_zwischen(heute + timedelta(days=10), heute + timedelta(days=14)),
        "Stunden": 0.0, "Art": "Urlaub", "Kommentar": "", "Status": "Ausstehend",
        "Entscheidungsgrund": "", "Erfasst von": "",
        "Eingereicht am": heute,
    }], columns=SPALTEN_URLAUB)

    # 6) Branche und Firmenname übernehmen
    st.session_state.config.update({"branche": branche_key, "firmenname": firmenname.strip() or firmenname})

    for schluessel in ("mitarbeiter_stammdaten", "benutzer", "kunden", "projekte", "time_logs", "vacation_requests"):
        speichern(schluessel)
    einstellungen_speichern(st.session_state.config)


def stammdaten_zeile(name: str):
    df = st.session_state.mitarbeiter_stammdaten
    treffer = df[df["Mitarbeiter"] == name]
    return None if treffer.empty else treffer.iloc[0]


def nachtrag_unbegrenzt(stunden: float) -> bool:
    return float(stunden or 0) >= NACHTRAG_UNBEGRENZT_AB


def nachtragslimit_text(stunden: float) -> str:
    """Zeigt sehr große Werte als Unendlich-Zeichen statt als unleserliche Zahl."""
    if nachtrag_unbegrenzt(stunden):
        return "∞"
    return f"{stunden:.0f} " + t("Std.", "h")


def nachtragslimit_stunden(ma_id: str) -> float:
    """Wie weit darf diese Person Zeiten rückwirkend ändern? Vorgabe: 24 Std."""
    df = st.session_state.mitarbeiter_stammdaten
    treffer = df[df["MA-ID"].astype(str) == str(ma_id)]
    if treffer.empty:
        return STANDARD_NACHTRAGSLIMIT
    wert = pd.to_numeric(treffer.iloc[0]["Nachtrag_Std_Limit"], errors="coerce")
    return float(wert) if pd.notna(wert) and wert > 0 else STANDARD_NACHTRAGSLIMIT


def nachtrag_grenze(ma_id: str) -> datetime:
    return logik.nachtrag_grenze(nachtragslimit_stunden(ma_id))


def arbeitszeitkalender_von(name: str) -> pd.DataFrame:
    """Liest den wiederkehrenden Wochenkalender einer Person."""
    ma_id = stammdaten_zeile(name)["MA-ID"] if stammdaten_zeile(name) is not None else ""
    df = st.session_state.get("arbeitszeitkalender", pd.DataFrame(columns=SPALTEN_ARBEITSZEITKALENDER)).copy()
    if df.empty or not ma_id:
        return df.iloc[0:0].copy()
    return df[df["MA-ID"].astype(str) == str(ma_id)].copy()


def wochenplan_soll(arbeitstag, von, bis, pause_minuten=0) -> float:
    """Sollstunden eines Wochentags – Berechnung liegt in logik.py."""
    return logik.wochenplan_soll(bool(arbeitstag), von, bis, pause_minuten)


def buchungen_von(name: str, ausser_id: str = "") -> list:
    """Alle Zeitbuchungen einer Person als Prüfobjekte für die Überschneidungsprüfung."""
    df = zeiten_abfragen(mitarbeiter=name)
    if df.empty:
        return []
    liste = []
    for _, zeile in df.iterrows():
        if ausser_id and str(zeile["ID"]) == str(ausser_id):
            continue
        if not isinstance(zeile["Datum"], date):
            continue
        kommen = parse_zeit(zeile["Kommen"])
        if kommen is None:
            continue
        liste.append(Buchung(id=str(zeile["ID"]), datum=zeile["Datum"], kommen=kommen,
                             gehen=parse_zeit(zeile["Gehen"])))
    return liste


def pruefe_ueberschneidung(name: str, datum: date, kommen: time, gehen: time | None,
                           eigene_id: str = "", bestand: list | None = None) -> str | None:
    """Gibt eine fertige Fehlermeldung zurück, wenn sich die Buchung überschneidet.

    Doppelte oder überlappende Stempelungen führen sonst zu falschen Monatssummen,
    ohne dass es jemandem auffällt.
    """
    neu = Buchung(id=str(eigene_id or "__neu__"), datum=datum, kommen=kommen, gehen=gehen)
    vorhandene = bestand if bestand is not None else buchungen_von(name, eigene_id)
    treffer = logik.ueberschneidung(neu, vorhandene, cfg("nachtschicht_erlaubt"))
    if treffer is None:
        return None
    zeitraum = (f"{treffer.kommen.strftime(ZEITFORMAT)}–{treffer.gehen.strftime(ZEITFORMAT)}"
                if treffer.gehen else f"{treffer.kommen.strftime(ZEITFORMAT)} "
                + t("(läuft noch)", "(still running)"))
    return t(f"Überschneidung mit einer vorhandenen Buchung am "
             f"{treffer.datum.strftime(DATUMSFORMAT)} ({zeitraum}).",
             f"Overlaps an existing entry on "
             f"{treffer.datum.strftime(DATUMSFORMAT)} ({zeitraum}).")


def ist_leitungskonto(ma_id: str) -> bool:
    """Gibt es zu dieser Person ein Konto mit Leitungs-/Adminrechten?"""
    df = st.session_state.get("benutzer")
    if df is None or df.empty or not ma_id:
        return False
    treffer = df[df["MA-ID"].astype(str) == str(ma_id)]
    return bool((treffer["Rolle"].astype(str).isin(["Leitung / Admin", "Systemadministrator"])).any())


def standard_nachtragslimit(ma_id: str) -> float:
    return NACHTRAG_UNBEGRENZT if ist_leitungskonto(ma_id) else STANDARD_NACHTRAGSLIMIT


def wochensoll_aus_kalender(ma_id: str) -> float | None:
    """Summe der Sollstunden aus dem Wochenplan; None, wenn kein Plan hinterlegt ist."""
    df = st.session_state.get("arbeitszeitkalender", pd.DataFrame(columns=SPALTEN_ARBEITSZEITKALENDER))
    if df.empty:
        return None
    eigene = df[df["MA-ID"].astype(str) == str(ma_id)]
    if eigene.empty:
        return None
    summe = 0.0
    for _, zeile in eigene.iterrows():
        summe += wochenplan_soll(zeile.get("Arbeitstag", False), zeile.get("Von"),
                                 zeile.get("Bis"), zeile.get("Pause_Min", 0))
    return round(summe, 2)


def tagesplan(name: str, wochentag: int) -> dict | None:
    """Wochenplan-Eintrag für einen Wochentag – Grundlage der automatischen Vorbelegung."""
    kalender = arbeitszeitkalender_von(name)
    if kalender.empty:
        return None
    treffer = kalender[pd.to_numeric(kalender["Wochentag"], errors="coerce") == int(wochentag)]
    if treffer.empty:
        return None
    zeile = treffer.iloc[0]
    if not bool(zeile.get("Arbeitstag", False)):
        return None
    return {
        "von": parse_zeit(zeile.get("Von")) or time(8, 0),
        "bis": parse_zeit(zeile.get("Bis")) or time(16, 30),
        "pause": int(pd.to_numeric(zeile.get("Pause_Min"), errors="coerce") or 0),
        "soll": float(pd.to_numeric(zeile.get("Soll_Std"), errors="coerce") or 0.0),
    }


def tagessoll(name: str, wochentag: int | None = None) -> float:
    """Tägliches Soll aus dem Arbeitszeitkalender; ohne Wochentag als Durchschnitt."""
    kalender = arbeitszeitkalender_von(name)
    if not kalender.empty:
        kalender["Soll_Std"] = pd.to_numeric(kalender["Soll_Std"], errors="coerce").fillna(0.0)
        arbeitstage = kalender[kalender["Arbeitstag"].fillna(False).astype(bool)]
        if wochentag is not None:
            treffer = arbeitstage[arbeitstage["Wochentag"].astype(int) == int(wochentag)]
            return float(treffer.iloc[0]["Soll_Std"]) if not treffer.empty else 0.0
        if not arbeitstage.empty:
            return float(arbeitstage["Soll_Std"].sum()) / len(arbeitstage)
    zeile = stammdaten_zeile(name)
    wochenstunden = float(zeile["Wochenstunden"]) if zeile is not None else branche()["wochenstunden"]
    return wochenstunden / 5.0


def abwesenheiten_cache() -> dict:
    """Wandelt die Anträge einmal je Seitenaufbau in Fachlogik-Objekte um.

    Die Auswertung ruft berechne_saldo je Mitarbeiter auf, und jeder Aufruf brauchte
    zuvor einen eigenen Durchlauf durch alle Anträge – bei vielen Mitarbeitenden
    wächst das quadratisch. Mit dem Zwischenspeicher bleibt es linear.
    """
    cache = st.session_state.get("_abwesenheiten_cache")
    if cache is not None:
        return cache
    cache = {}
    df = st.session_state.get("vacation_requests")
    if df is not None and not df.empty:
        for _, zeile in df.iterrows():
            start, ende = zeile["Startdatum"], zeile["Enddatum"]
            if not isinstance(start, date) or not isinstance(ende, date):
                continue
            cache.setdefault(str(zeile["Mitarbeiter"]), []).append(Abwesenheit(
                start=start, ende=ende,
                einheit=str(zeile.get("Einheit") or "Tage"),
                tage=int(pd.to_numeric(zeile.get("Tage"), errors="coerce") or 0),
                stunden=float(pd.to_numeric(zeile.get("Stunden"), errors="coerce") or 0.0),
                art=str(zeile.get("Art") or "Urlaub"),
                status=str(zeile.get("Status") or "Ausstehend")))
    st.session_state["_abwesenheiten_cache"] = cache
    return cache


def abwesenheiten_von(name: str) -> list:
    """Abwesenheiten einer Person im Format der Fachlogik."""
    return abwesenheiten_cache().get(str(name), [])


def _abwesenheiten_alt(name: str) -> list:
    df = st.session_state.vacation_requests
    if df is None or df.empty:
        return []
    eigene = df[df["Mitarbeiter"] == name]
    liste = []
    for _, zeile in eigene.iterrows():
        start, ende = zeile["Startdatum"], zeile["Enddatum"]
        if not isinstance(start, date) or not isinstance(ende, date):
            continue
        liste.append(Abwesenheit(
            start=start, ende=ende,
            einheit=str(zeile.get("Einheit") or "Tage"),
            tage=int(pd.to_numeric(zeile.get("Tage"), errors="coerce") or 0),
            stunden=float(pd.to_numeric(zeile.get("Stunden"), errors="coerce") or 0.0),
            art=str(zeile.get("Art") or "Urlaub"),
            status=str(zeile.get("Status") or "Ausstehend"),
        ))
    return liste


def get_urlaubs_konto(name: str):
    """(Anspruch, genehmigt, ausstehend, verfügbar) – nur tageweiser Urlaub."""
    zeile = stammdaten_zeile(name)
    if zeile is None:
        return 0, 0, 0, 0
    konto = logik.urlaubskonto(
        int(zeile["Urlaub_Pro_Jahr"] or 0),
        int(zeile["Resturlaub_Vorjahr"] or 0),
        abwesenheiten_von(name),
    )
    return konto.als_tupel()


def stundenabwesenheiten(name: str, von: date = None, bis: date = None,
                         nur_genehmigt: bool = True) -> float:
    """Summe der stundenweisen Abwesenheiten (Freizeitausgleich, Überstundenabbau …)."""
    liste = abwesenheiten_von(name)
    if not nur_genehmigt:
        liste = [Abwesenheit(a.start, a.ende, a.einheit, a.tage, a.stunden, a.art, "Genehmigt")
                 for a in liste]
    von = von or date.min
    bis = bis or date.max
    return logik.abwesenheitsstunden_im_zeitraum(liste, von, bis)


def zeiten_von(name=None, von: date = None, bis: date = None) -> pd.DataFrame:
    df = st.session_state.time_logs.copy()
    if df.empty:
        return df
    if name:
        df = df[df["Mitarbeiter"] == name]
    if von is not None:
        df = df[df["Datum"].apply(lambda d: isinstance(d, date) and d >= von)]
    if bis is not None:
        df = df[df["Datum"].apply(lambda d: isinstance(d, date) and d <= bis)]
    return df


def berechne_saldo(name: str, von: date, bis: date):
    """Ist-Stunden, Soll-Stunden und Saldo. Abwesenheiten senken das Soll."""
    df = zeiten_von(name, von, bis)
    ist = float(pd.to_numeric(df["Netto (Std)"], errors="coerce").sum()) if not df.empty else 0.0
    zeile = stammdaten_zeile(name)
    wochenstunden = float(zeile["Wochenstunden"]) if zeile is not None else branche()["wochenstunden"]
    saldo = logik.berechne_saldo(ist, von, bis, wochenstunden, abwesenheiten_von(name), regeln())
    return saldo.als_tupel()


# ============================================================
# 7. ANZEIGE-HELFER
# ============================================================

STATUS_FARBEN = {
    "Läuft": "#E3F2FD", "Erfasst": "#F5F5F5", "Freigegeben": "#E8F5E9",
    "Ausstehend": "#FFF3E0", "Genehmigt": "#E8F5E9", "Abgelehnt": "#FFEBEE",
    "Storniert": "#F3E8FF",
}
UEBERSETZTE_WERTSPALTEN = ("Status", "Art", "Kategorie", "Typ", "Einheit", "Rolle")


def anzeige_df(df: pd.DataFrame) -> pd.DataFrame:
    """Kopie mit Datumswerten und – bei englischer Oberfläche – übersetzten Inhalten."""
    aus = df.copy()
    for spalte in aus.columns:
        if spalte in DATUMSSPALTEN:
            aus[spalte] = pd.to_datetime(aus[spalte], errors="coerce")
    if ist_englisch():
        for spalte in UEBERSETZTE_WERTSPALTEN:
            if spalte in aus.columns:
                aus[spalte] = aus[spalte].apply(lambda w: wert_label(w) if pd.notna(w) else w)
        aus = aus.rename(columns={s: spalten_label(s) for s in aus.columns})
    return aus


ZAHLENFORMATE = {
    "Brutto (Std)": "%.2f", "Netto (Std)": "%.2f", "Stunden": "%.1f",
    "Pause (Min)": "%d", "Tage": "%d", "Wochenstunden": "%.1f",
    "Urlaub_Pro_Jahr": "%d", "Resturlaub_Vorjahr": "%d", "Nachtrag_Std_Limit": "%.0f",
}
SPALTENBREITEN = {
    "Mitarbeiter": "medium", "Person": "medium", "Datum": "small", "Kommen": "small",
    "Gehen": "small", "Status": "small", "Typ": "small", "Einheit": "small",
    "Kategorie": "medium", "Projekt": "medium", "Notiz": "large", "Art": "medium",
    "Kommentar": "large", "Benutzername": "medium", "Rolle": "medium",
}


def spalten_config(df: pd.DataFrame) -> dict:
    """Baut Datums-, Zahlen- und Breitenformate – Schlüssel sind die angezeigten Spaltennamen."""
    config = {}
    for spalte in df.columns:
        label = spalten_label(spalte)
        if spalte in DATUMSSPALTEN:
            config[label] = st.column_config.DateColumn(label, format=DATUMSFORMAT_UI, width="small")
        elif spalte in ZAHLENFORMATE:
            config[label] = st.column_config.NumberColumn(
                label, format=ZAHLENFORMATE[spalte], width="small")
        elif spalte in SPALTENBREITEN:
            config[label] = st.column_config.TextColumn(label, width=SPALTENBREITEN[spalte])
    return config


def tabelle(df: pd.DataFrame, status_spalte="Status", **kwargs) -> None:
    config = spalten_config(df)
    anzeige = anzeige_df(df)
    spalte = spalten_label(status_spalte) if status_spalte else None
    if spalte and spalte in anzeige.columns and not anzeige.empty:
        farben = {wert_label(k): v for k, v in STATUS_FARBEN.items()}

        def _faerben(wert):
            farbe = farben.get(str(wert))
            return f"background-color: {farbe}" if farbe else ""

        styler = anzeige.style
        faerbe = getattr(styler, "map", None) or styler.applymap
        anzeige = faerbe(_faerben, subset=[spalte])
    st.dataframe(anzeige, use_container_width=True, hide_index=True,
                 column_config=config, **kwargs)


def konvertiere_zu_excel(df: pd.DataFrame) -> bytes:
    # Ohne Kunden-/Projektmodul würden zwei leere Spalten im Export landen
    aufbereitet = zeit_mit_kunden_projekten(df) if kunden_projekte_aktiv() else df
    export = anzeige_df(aufbereitet)
    for spalte in export.columns:
        if pd.api.types.is_datetime64_any_dtype(export[spalte]):
            export[spalte] = export[spalte].dt.strftime(DATUMSFORMAT)

    zusammenfassung = pd.DataFrame()
    if not df.empty and "Mitarbeiter" in df.columns:
        tmp = df.copy()
        tmp["Netto (Std)"] = pd.to_numeric(tmp["Netto (Std)"], errors="coerce")
        zusammenfassung = (
            tmp.groupby("Mitarbeiter", as_index=False)
            .agg(**{"Einträge": ("ID", "count"), "Netto-Stunden": ("Netto (Std)", "sum")})
            .round(2)
            .rename(columns={s: spalten_label(s) for s in ("Mitarbeiter", "Einträge", "Netto-Stunden")})
        )

    puffer = io.BytesIO()
    with pd.ExcelWriter(puffer, engine="openpyxl") as writer:
        export.to_excel(writer, index=False, sheet_name=t("Arbeitszeiten", "Working times")[:31])
        if not zusammenfassung.empty:
            zusammenfassung.to_excel(writer, index=False,
                                     sheet_name=t("Zusammenfassung", "Summary")[:31])
    return puffer.getvalue()


def konvertiere_zu_csv(df: pd.DataFrame) -> bytes:
    export = anzeige_df(df)
    for spalte in export.columns:
        if pd.api.types.is_datetime64_any_dtype(export[spalte]):
            export[spalte] = export[spalte].dt.strftime(DATUMSFORMAT)
    return export.to_csv(index=False, sep=";", decimal=",").encode("utf-8-sig")


# ============================================================
# 8. ANMELDUNG
# ============================================================

def finde_benutzer(benutzername: str):
    df = st.session_state.benutzer
    if df.empty or not benutzername:
        return None
    treffer = df[df["Benutzername"].astype(str).str.lower() == str(benutzername).strip().lower()]
    return None if treffer.empty else treffer.iloc[0]


def pruefe_anmeldung(benutzername: str, passwort: str):
    gesperrt, _, _ = _login_sperrstatus(benutzername)
    if gesperrt:
        return None
    zeile = finde_benutzer(benutzername)
    if zeile is None:
        passwort_hash(passwort, secrets.token_hex(16))
        login_fehlversuch(benutzername)
        return None
    if not bool(zeile["Aktiv"]):
        login_fehlversuch(benutzername)
        return None
    algorithmus = str(zeile.get("Passwort_Algorithmus", "pbkdf2-sha256") or "pbkdf2-sha256")
    if not passwort_pruefen(passwort, str(zeile["Salt"]), str(zeile["Passwort_Hash"]), algorithmus):
        login_fehlversuch(benutzername)
        return None
    if algorithmus.lower() != PASSWORT_ALGORITHMUS:
        salt, digest, neu_alg = passwort_neu_berechnen(passwort)
        df = st.session_state.benutzer
        maske = df["Benutzername"].astype(str).str.lower() == str(benutzername).strip().lower()
        df.loc[maske, "Salt"] = salt
        df.loc[maske, "Passwort_Hash"] = digest
        df.loc[maske, "Passwort_Algorithmus"] = neu_alg
        st.session_state.benutzer = df
        speichern("benutzer")
    login_erfolg(benutzername)
    return zeile

def passwort_setzen(benutzername: str, neues_passwort: str, wechsel_erzwingen: bool = False) -> None:
    df = st.session_state.benutzer
    maske = df["Benutzername"].astype(str).str.lower() == benutzername.strip().lower()
    salt, digest, algorithmus = passwort_neu_berechnen(neues_passwort)
    df.loc[maske, "Salt"] = salt
    df.loc[maske, "Passwort_Hash"] = digest
    df.loc[maske, "Passwort_Algorithmus"] = algorithmus
    df.loc[maske, "Passwort_wechseln"] = wechsel_erzwingen
    st.session_state.benutzer = df
    speichern("benutzer")


def sprache_speichern(benutzername: str, sprache: str) -> None:
    df = st.session_state.benutzer
    maske = df["Benutzername"].astype(str).str.lower() == str(benutzername).strip().lower()
    df.loc[maske, "Sprache"] = sprache
    st.session_state.benutzer = df
    speichern("benutzer")


def aktive_admins() -> pd.DataFrame:
    df = st.session_state.benutzer
    if df.empty:
        return df
    return df[(df["Rolle"] == "Leitung / Admin") & (df["Aktiv"].astype(bool))]


def benutzer_ohne_geheimnisse() -> pd.DataFrame:
    return st.session_state.benutzer.drop(columns=["Salt", "Passwort_Hash"], errors="ignore")


def initialen(name: str) -> str:
    teile = [x for x in str(name).split() if x]
    if not teile:
        return "?"
    return (teile[0][:2] if len(teile) == 1 else teile[0][0] + teile[-1][0]).upper()


def gruss(zeitpunkt: datetime = None) -> str:
    stunde = (zeitpunkt or datetime.now()).hour
    if stunde < 11:
        return t("Guten Morgen", "Good morning")
    if stunde < 18:
        return t("Guten Tag", "Hello")
    return t("Guten Abend", "Good evening")


# ============================================================
# 9. DESIGN
# ============================================================

st.markdown(
    """
    <style>
    /* ============================================================
       Liquid Glass – durchscheinende Flächen über weichem Farbverlauf.
       Alles skaliert mit relativen Einheiten, damit es auf dem Handy passt.
       ============================================================ */
    :root {
        --glas-hell: rgba(255, 255, 255, 0.62);
        --glas-heller: rgba(255, 255, 255, 0.78);
        --glas-rand: rgba(255, 255, 255, 0.85);
        --glas-schatten: 0 8px 32px rgba(31, 46, 74, 0.10);
        --primary: #1E7A46;
        --primary-hell: #2E9D5B;
        --gefahr: #C6362F;
        --text: #16253B;
        --text-mild: #5A6B84;
        --radius: 18px;
    }

    /* Hintergrund: weicher Verlauf mit zwei farbigen Lichtern */
    .stApp {
        background:
            radial-gradient(120vh 80vh at 8% -10%, rgba(120, 200, 160, 0.40), transparent 60%),
            radial-gradient(100vh 70vh at 105% 10%, rgba(140, 180, 240, 0.38), transparent 60%),
            linear-gradient(160deg, #EEF3F8 0%, #E6EEF6 45%, #EAF2EC 100%);
        background-attachment: fixed;
    }
    * { font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
    .stApp, .stApp p, .stApp span, .stApp label, .stApp li,
    .stApp h1, .stApp h2, .stApp h3, .stApp h4, .stApp h5, .stApp h6 { color: var(--text); }
    .stApp [data-testid="stCaptionContainer"],
    .stApp [data-testid="stCaptionContainer"] p { color: var(--text-mild) !important; }

    /* --- Glaskarten --- */
    div[data-testid="stVerticalBlockBorderWrapper"],
    div[data-testid="stMetric"],
    div[data-testid="stExpander"] details,
    div[data-testid="stDataFrame"],
    div[data-testid="stDataEditor"] {
        background: var(--glas-hell) !important;
        -webkit-backdrop-filter: blur(18px) saturate(160%);
        backdrop-filter: blur(18px) saturate(160%);
        border: 1px solid var(--glas-rand) !important;
        border-radius: var(--radius) !important;
        box-shadow: var(--glas-schatten);
    }
    div[data-testid="stMetric"] { padding: 14px 16px; }
    div[data-testid="stMetricLabel"] { color: var(--text-mild); }
    div[data-testid="stMetricValue"] { color: var(--text) !important; font-weight: 700; }
    div[data-testid="stExpander"] details { overflow: hidden; }
    div[data-testid="stExpander"] summary { font-weight: 600; }

    /* --- Schaltflächen: Glas mit sanfter Tiefe --- */
    div.stButton > button, div.stFormSubmitButton > button, div.stDownloadButton > button {
        background: var(--glas-heller);
        -webkit-backdrop-filter: blur(12px);
        backdrop-filter: blur(12px);
        border: 1px solid var(--glas-rand);
        border-radius: 14px; font-weight: 600; color: var(--text);
        min-height: 2.9em;
        box-shadow: 0 2px 10px rgba(31, 46, 74, 0.08);
        transition: transform .08s ease, box-shadow .2s ease, background .2s ease;
    }
    div.stButton > button:hover, div.stFormSubmitButton > button:hover,
    div.stDownloadButton > button:hover {
        background: rgba(255, 255, 255, 0.92);
        box-shadow: 0 6px 18px rgba(31, 46, 74, 0.14);
    }
    div.stButton > button:active { transform: scale(.985); }
    div.stButton > button[kind="primary"], div.stFormSubmitButton > button[kind="primary"] {
        background: linear-gradient(135deg, var(--primary-hell), var(--primary)) !important;
        color: #fff !important; border: 1px solid rgba(255,255,255,.35) !important;
        box-shadow: 0 6px 18px rgba(30, 122, 70, 0.28);
    }
    .st-key-btn_kommen button {
        background: linear-gradient(135deg, var(--primary-hell), var(--primary)) !important;
        color: #fff !important; border: 1px solid rgba(255,255,255,.35) !important;
        min-height: 3.4em; font-size: 1.05rem;
    }
    .st-key-btn_gehen button {
        background: linear-gradient(135deg, #E05B4F, var(--gefahr)) !important;
        color: #fff !important; border: 1px solid rgba(255,255,255,.35) !important;
        min-height: 3.4em; font-size: 1.05rem;
    }

    /* --- Eingabefelder --- */
    .stApp input, .stApp textarea,
    .stApp div[data-baseweb="select"] > div,
    .stApp div[data-baseweb="input"] {
        background: var(--glas-heller) !important;
        color: var(--text) !important;
        border-radius: 12px !important;
        border: 1px solid var(--glas-rand) !important;
    }
    div[data-baseweb="popover"] li, div[data-baseweb="popover"] div { color: var(--text); }

    /* --- Reiter --- */
    div[data-baseweb="tab-list"] {
        background: var(--glas-hell);
        -webkit-backdrop-filter: blur(14px);
        backdrop-filter: blur(14px);
        border: 1px solid var(--glas-rand);
        border-radius: 14px; padding: 4px; gap: 2px;
    }
    button[data-baseweb="tab"] { font-weight: 600; border-radius: 10px; }
    button[data-baseweb="tab"][aria-selected="true"] {
        background: rgba(255,255,255,.85); color: var(--primary);
        box-shadow: 0 2px 8px rgba(31,46,74,.08);
    }
    div[data-baseweb="tab-highlight"], div[data-baseweb="tab-border"] { display: none; }

    /* --- Statusanzeigen --- */
    .badge {
        display: inline-flex; align-items: center; gap: 8px; padding: 12px 16px;
        border-radius: 14px; font-weight: 600; width: 100%; box-sizing: border-box;
        -webkit-backdrop-filter: blur(12px); backdrop-filter: blur(12px);
        border: 1px solid var(--glas-rand); box-shadow: var(--glas-schatten);
    }
    .badge-gruen { background: rgba(214, 245, 226, .75); color: #12572F; }
    .badge-grau  { background: rgba(240, 244, 249, .75); color: #47576F; }
    .badge-rot   { background: rgba(253, 226, 223, .75); color: #8C2A24; }

    /* Streamlits "Running…"-Anzeige stört den ruhigen Eindruck */
    div[data-testid="stStatusWidget"] { display: none !important; }
    div[data-testid="stAppViewContainer"] .block-container { animation: sanft-rein .2s ease-out; }
    @keyframes sanft-rein { from { opacity: 0; transform: translateY(4px); } to { opacity: 1; } }

    .avatar-kreis {
        width: 42px; height: 42px; border-radius: 50%;
        background: linear-gradient(135deg, var(--primary-hell), var(--primary));
        color: #fff; display: flex; align-items: center; justify-content: center;
        font-weight: 700; box-shadow: 0 4px 12px rgba(30,122,70,.3);
    }

    /* ============================================================
       Handy: eine Spalte, große Tippflächen, nichts abgeschnitten
       ============================================================ */
    @media (max-width: 820px) {
        div[data-testid="stAppViewContainer"] .block-container {
            padding: .8rem .7rem 3.5rem .7rem; max-width: 100%;
        }
        div[data-testid="stHorizontalBlock"] { flex-direction: column; gap: .5rem; }
        div[data-testid="stHorizontalBlock"] > div[data-testid="column"] {
            width: 100% !important; flex: 1 1 100% !important; min-width: 100% !important;
        }
        /* Kennzahlen bleiben nebeneinander, sonst scrollt man ewig */
        div[data-testid="stHorizontalBlock"]:has(div[data-testid="stMetric"]) {
            flex-direction: row; gap: .4rem;
        }
        div[data-testid="stHorizontalBlock"]:has(div[data-testid="stMetric"]) > div[data-testid="column"] {
            width: auto !important; flex: 1 1 0 !important; min-width: 0 !important;
        }
        div[data-testid="stMetric"] { padding: 10px 8px; }
        div[data-testid="stMetricValue"] { font-size: 1.25rem; }
        div[data-testid="stMetricLabel"] p { font-size: .75rem; }

        div.stButton > button, div.stFormSubmitButton > button, div.stDownloadButton > button {
            min-height: 3.2em; font-size: 1rem;
        }
        div[data-baseweb="tab-list"] { overflow-x: auto; flex-wrap: nowrap; scrollbar-width: none; }
        div[data-baseweb="tab-list"]::-webkit-scrollbar { display: none; }
        button[data-baseweb="tab"] { white-space: nowrap; font-size: .92rem; padding: .4rem .7rem; }

        .stApp h2 { font-size: 1.3rem; }
        .stApp h4, .stApp h5 { font-size: 1rem; }
        div[data-testid="stDataFrame"], div[data-testid="stDataEditor"] { overflow-x: auto; }
        .badge { font-size: .95rem; padding: 12px; }

        /* --- Platz sparen, wo er auf dem Telefon wirklich fehlt --- */
        /* Streamlits eigene Kopfleiste kostet rund 50 Pixel ohne Nutzen */
        header[data-testid="stHeader"] { height: 0; min-height: 0; visibility: hidden; }
        div[data-testid="stAppViewContainer"] .block-container { padding-top: .4rem; }

        /* Begrüßung kleiner, Datumszeile weg – beides steht ohnehin im Konto-Menü */
        .kopf-gruss { font-size: 1.05rem !important; margin: 0 !important; }
        .kopf-zeile { display: none !important; }

        /* Abstände zwischen den Elementen straffen */
        div[data-testid="stVerticalBlock"] { gap: .5rem; }
        div[data-testid="stElementContainer"] { margin-bottom: 0; }
        .stApp hr { margin: .5rem 0; }
        div[data-testid="stExpander"] summary { padding: .4rem .6rem; font-size: .92rem; }

        /* Eingabefelder kompakter, Beschriftungen kleiner */
        .stApp label p { font-size: .82rem; margin-bottom: 2px; }
        .stApp input { padding: .45rem .6rem !important; }
        div[data-testid="stCaptionContainer"] p { font-size: .78rem; }

        /* Das Konto-Menü braucht oben rechts keine volle Breite */
        div[data-testid="stPopover"] button { font-size: .85rem; min-height: 2.4em; }

        /* Kennzahlenleiste enger */
        .kennzahl-leiste { padding: 6px 2px; }
        .kennzahl-wert { font-size: 1.05rem; }
        .kennzahl-label { font-size: .65rem; }

        /* Tabellen: kleinere Schrift, damit mehr Spalten sichtbar bleiben */
        div[data-testid="stDataEditor"] * { font-size: .82rem; }
    }

    /* Kompakte Kennzahlenleiste – ersetzt drei große Kacheln */
    .kennzahl-leiste {
        display: flex; gap: 6px; margin: 2px 0 10px 0;
        background: var(--glas-hell);
        -webkit-backdrop-filter: blur(16px) saturate(160%);
        backdrop-filter: blur(16px) saturate(160%);
        border: 1px solid var(--glas-rand); border-radius: 14px;
        box-shadow: var(--glas-schatten); padding: 8px 4px;
    }
    .kennzahl { flex: 1 1 0; text-align: center; min-width: 0; }
    .kennzahl-wert { display: block; font-size: 1.15rem; font-weight: 700; line-height: 1.2; }
    .kennzahl-label {
        display: block; font-size: .7rem; color: var(--text-mild);
        text-transform: uppercase; letter-spacing: .03em;
    }

    /* Sehr schmale Geräte */
    @media (max-width: 380px) {
        div[data-testid="stMetricValue"] { font-size: 1.05rem; }
        .stApp h2 { font-size: 1.15rem; }
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# 10. LOGIN
# ============================================================

if not st.session_state.logged_in:
    links, mitte, rechts = st.columns([1, 2, 1])
    with mitte:
        kopf_l, kopf_r = st.columns([3, 1])
        with kopf_r:
            gewaehlt = st.selectbox(
                "🌐", list(SPRACHEN.keys()),
                index=list(SPRACHEN.keys()).index(st.session_state.sprache),
                format_func=lambda s: SPRACHEN[s], label_visibility="collapsed",
                key="login_sprache",
            )
            if gewaehlt != st.session_state.sprache:
                st.session_state.sprache = gewaehlt
                st.rerun()

        st.markdown(
            "<div style='text-align:center;font-size:2.6em;'>⏱️</div>"
            f"<h2 style='text-align:center;color:#1B2430;margin:4px 0 0 0;'>{cfg('firmenname')}</h2>"
            f"<p style='text-align:center;color:#64748B;margin-top:2px;'>"
            f"{t('Zeiterfassung &amp; Urlaubsverwaltung', 'Time tracking &amp; absence management')}</p>",
            unsafe_allow_html=True,
        )
        gesperrt_bis = st.session_state.get("gesperrt_bis")
        gesperrt = isinstance(gesperrt_bis, datetime) and datetime.now() < gesperrt_bis

        with st.container(border=True):
            st.markdown(f"###### {t('Willkommen zurück', 'Welcome back')}")
            with st.form("login"):
                eingabe_name = st.text_input(t("Benutzername", "Username"),
                                             placeholder=t("z. B. a.mueller", "e.g. a.mueller")).strip()
                eingabe_passwort = st.text_input(t("Passwort", "Password"), type="password",
                                                 placeholder="••••••••")
                angemeldet = st.form_submit_button(t("Anmelden", "Sign in"),
                                                   use_container_width=True,
                                                   disabled=gesperrt, type="primary")

            if gesperrt:
                verbleibend = int((gesperrt_bis - datetime.now()).total_seconds() // 60) + 1
                st.error(t(f"Zu viele Fehlversuche. Bitte in ca. {verbleibend} Minuten erneut versuchen.",
                           f"Too many failed attempts. Please try again in about {verbleibend} minutes."))
            elif angemeldet:
                with st.spinner(t("Anmeldung wird geprüft …", "Checking credentials …")):
                    konto = pruefe_anmeldung(eingabe_name, eingabe_passwort)
                if konto is None:
                    gesperrt_neu, gesperrt_bis_neu, _ = _login_sperrstatus(eingabe_name)
                    if gesperrt_neu and gesperrt_bis_neu:
                        st.error(t("Zu viele Fehlversuche. Das Konto ist vorübergehend gesperrt.", "Too many failed attempts. The account is temporarily locked."))
                    else:
                        st.error(t("Benutzername oder Passwort ist falsch.", "Username or password is incorrect."))
                elif konto["Rolle"] == "Mitarbeiter" and id_zu_name(konto["MA-ID"]) not in aktive_mitarbeiter():
                    st.error(t("Dem Konto ist kein aktiver Mitarbeiterdatensatz zugeordnet. Bitte an die Leitung wenden.",
                               "This account is not linked to an active employee record. Please contact management."))
                else:
                    df_benutzer = st.session_state.benutzer
                    maske = df_benutzer["Benutzername"] == konto["Benutzername"]
                    df_benutzer.loc[maske, "Letzter Login"] = pd.Timestamp(date.today())
                    st.session_state.benutzer = df_benutzer
                    speichern("benutzer")
                    st.session_state.update(
                        logged_in=True,
                        role=konto["Rolle"],
                        user=id_zu_name(konto["MA-ID"]) or konto["Benutzername"],
                        username=konto["Benutzername"],
                        ma_id=str(konto["MA-ID"] or ""),
                        sprache=str(konto["Sprache"] or "de"),
                        passwort_wechseln=bool(konto["Passwort_wechseln"]),
                        login_versuche=0,
                        gesperrt_bis=None,
                    )
                    st.rerun()

        if st.session_state.benutzer.empty:
            st.warning(t("Es existiert kein Benutzerkonto. Bitte daten/zeiterfassung.db löschen, um neu zu starten.",
                         "No user account exists. Delete daten/zeiterfassung.db to start over."))

        st.markdown(
            f"<p style='text-align:center;color:#94A3B8;font-size:.8rem;margin-top:1.2rem;'>"
            f"Version {APP_VERSION}</p>",
            unsafe_allow_html=True,
        )
    st.stop()


# --- Erzwungener Passwortwechsel beim ersten Login ---
if st.session_state.get("passwort_wechseln"):
    links, mitte, rechts = st.columns([1, 2, 1])
    with mitte:
        st.markdown(f"### {t('Passwort festlegen', 'Set your password')}")
        st.info(t("Beim ersten Login muss das Startpasswort geändert werden.",
                  "The initial password must be changed at first sign-in."))
        with st.container(border=True):
            with st.form("erstpasswort"):
                neu1 = st.text_input(t("Neues Passwort", "New password"), type="password")
                neu2 = st.text_input(t("Neues Passwort wiederholen", "Repeat new password"), type="password")
                gesetzt = st.form_submit_button(t("Passwort speichern", "Save password"),
                                                use_container_width=True, type="primary")
            if gesetzt:
                fehler = passwort_regeln_verletzt(neu1, st.session_state.username)
                if neu1 != neu2:
                    st.error(t("Die beiden Eingaben stimmen nicht überein.", "The entries do not match."))
                elif fehler:
                    st.error(fehler)
                else:
                    passwort_setzen(st.session_state.username, neu1)
                    if st.session_state.username == SYSTEMADMIN_USERNAME:
                        bootstrap = DATEN_DIR / "systemadmin_initial.txt"
                        try:
                            if bootstrap.exists():
                                bootstrap.unlink()
                        except OSError:
                            pass
                    st.session_state.passwort_wechseln = False
                    melde("Passwort gespeichert.", "Password saved.")
                    st.rerun()
            if st.button(t("Abmelden", "Sign out"), use_container_width=True):
                st.session_state.update(logged_in=False, role=None, user=None, username=None,
                                        ma_id=None, passwort_wechseln=False)
                st.rerun()
    st.stop()


# ============================================================
# 11. KOPFBEREICH
# ============================================================

meldungen_anzeigen()

# Namen frisch aus den Stammdaten auflösen, damit immer der vollständige
# Klarname angezeigt wird (auch bei Leitung / Admin).
if st.session_state.get("ma_id"):
    st.session_state.user = id_zu_name(st.session_state.ma_id) or st.session_state.user

# Zeiteinträge des angemeldeten Kontos frisch aus der Datenbank holen.
# Muss nach der Namensauflösung stehen, weil der Ausschnitt am Namen hängt.
arbeitszeiten_aktualisieren()

jetzt = datetime.now()
kopf_links, kopf_rechts = st.columns([4, 1])
with kopf_links:
    voller_name = str(st.session_state.user).strip() or str(st.session_state.username)
    st.markdown(
        f"<h2 class='kopf-gruss' style='margin-bottom:0;'>{gruss(jetzt)}, {voller_name} 👋</h2>"
        f"<p class='kopf-zeile' style='color:#64748B;'>"
        f"{WOCHENTAGE[st.session_state.sprache][jetzt.weekday()]}, "
        f"{jetzt.strftime(DATUMSFORMAT)} · {jetzt.strftime('%H:%M')} "
        f"{t('Uhr', '')} &nbsp;·&nbsp; {cfg('firmenname')}</p>",
        unsafe_allow_html=True,
    )

with kopf_rechts:
    with st.popover(f"👤 {st.session_state.username}", use_container_width=True):
        a1, a2 = st.columns([1, 3])
        a1.markdown(f"<div class='avatar-kreis'>{initialen(st.session_state.user)}</div>",
                    unsafe_allow_html=True)
        with a2:
            st.markdown(f"**{st.session_state.user}**")
            st.caption(wert_label(st.session_state.role))

        neue_sprache = st.selectbox(
            t("Sprache", "Language"), list(SPRACHEN.keys()),
            index=list(SPRACHEN.keys()).index(st.session_state.sprache),
            format_func=lambda s: SPRACHEN[s], key="konto_sprache",
        )
        if neue_sprache != st.session_state.sprache:
            st.session_state.sprache = neue_sprache
            sprache_speichern(st.session_state.username, neue_sprache)
            st.rerun()

        with st.expander(t("🔑 Passwort ändern", "🔑 Change password")):
            with st.form("pw_aendern"):
                alt = st.text_input(t("Aktuelles Passwort", "Current password"), type="password")
                neu1 = st.text_input(t("Neues Passwort", "New password"), type="password")
                neu2 = st.text_input(t("Wiederholen", "Repeat"), type="password")
                geaendert = st.form_submit_button(t("Ändern", "Change"), use_container_width=True)
            if geaendert:
                fehler = passwort_regeln_verletzt(neu1, st.session_state.username)
                if pruefe_anmeldung(st.session_state.username, alt) is None:
                    st.error(t("Aktuelles Passwort ist falsch.", "Current password is incorrect."))
                elif neu1 != neu2:
                    st.error(t("Die Eingaben stimmen nicht überein.", "The entries do not match."))
                elif fehler:
                    st.error(fehler)
                else:
                    passwort_setzen(st.session_state.username, neu1)
                    melde("Passwort geändert.", "Password changed.", "🔑")
                    st.rerun()

        if st.button(t("🔒 Abmelden", "🔒 Sign out"), use_container_width=True):
            st.session_state.update(logged_in=False, role=None, user=None, username=None,
                                    ma_id=None, passwort_wechseln=False)
            st.rerun()

B = branche()


# ============================================================
# 12. MITARBEITER-ANSICHT
# ============================================================

def letzte_buchung_kunde_projekt(name: str) -> tuple:
    """Kunde und Projekt der letzten Buchung – als Vorbelegung für die Erfassung.

    Wer drei Wochen auf derselben Baustelle ist, soll das nicht dreißigmal neu
    auswählen müssen. Das spart auf dem Handy die meisten Klicks.
    """
    df = st.session_state.get("time_logs")
    if df is None or df.empty:
        return "", ""
    eigene = df[df["Mitarbeiter"] == name]
    if eigene.empty:
        return "", ""
    eigene = eigene.sort_values("Datum")
    letzte = eigene.iloc[-1]
    kunde = str(letzte.get("Kunde-ID") or "").strip()
    projekt = str(letzte.get("Projekt-ID") or "").strip()
    return ("" if kunde in ("nan", "None") else kunde,
            "" if projekt in ("nan", "None") else projekt)


def vorauswahl_index(optionen: list, wert: str) -> int:
    """Index der Vorbelegung in einer Auswahlliste; 0, wenn nicht enthalten."""
    return optionen.index(wert) if wert and wert in optionen else 0


def kennzahlen_leiste(werte: list) -> None:
    """Drei Zahlen in einer schmalen Glasleiste statt in drei großen Kacheln.

    Auf einem Telefon sparen die Kacheln von st.metric sonst fast einen halben
    Bildschirm – die Leiste braucht rund ein Viertel davon.
    """
    felder = "".join(
        f"<div class='kennzahl'><span class='kennzahl-wert' style='color:{farbe}'>{wert}</span>"
        f"<span class='kennzahl-label'>{label}</span></div>"
        for label, wert, farbe in werte
    )
    st.markdown(f"<div class='kennzahl-leiste'>{felder}</div>", unsafe_allow_html=True)


def alle_abwesenheiten(nur_relevante: bool = True) -> list:
    """Alle Abwesenheiten als Paare (Name, Abwesenheit) für Kalender und Übersichten."""
    df = st.session_state.vacation_requests
    if df is None or df.empty:
        return []
    paare = []
    for _, zeile in df.iterrows():
        if nur_relevante and str(zeile["Status"]) in logik.STATUS_UNWIRKSAM:
            continue
        start, ende = zeile["Startdatum"], zeile["Enddatum"]
        if not isinstance(start, date) or not isinstance(ende, date):
            continue
        paare.append((str(zeile["Mitarbeiter"]), Abwesenheit(
            start=start, ende=ende, einheit=str(zeile.get("Einheit") or "Tage"),
            tage=int(pd.to_numeric(zeile.get("Tage"), errors="coerce") or 0),
            stunden=float(pd.to_numeric(zeile.get("Stunden"), errors="coerce") or 0.0),
            art=str(zeile.get("Art") or ""), status=str(zeile.get("Status") or ""))))
    return paare


def abwesenheitskalender(von: date, bis: date, als_wochen: bool = False) -> pd.DataFrame:
    """Matrix Mitarbeiter x Zeitraum – zeigt Überschneidungen auf einen Blick.

    Bei kurzen Zeiträumen eine Spalte je Tag. Bei langen Zeiträumen wird je
    Kalenderwoche zusammengefasst, weil mehrere hundert Tagesspalten niemand mehr
    überblickt. Die Spaltenköpfe enthalten immer den Monat – sonst fielen bei
    langen Zeiträumen gleiche Wochentag-/Tagkombinationen aufeinander und Spalten
    gingen still verloren (bei einem Jahr betraf das 148 Spalten).
    """
    namen = aktive_mitarbeiter()
    if not namen:
        return pd.DataFrame()
    paare = alle_abwesenheiten()

    tage = []
    tag = von
    while tag <= bis:
        tage.append(tag)
        tag += timedelta(days=1)

    zeilen = []
    if als_wochen:
        wochen: dict = {}
        for tag in tage:
            jahr, kw, _ = tag.isocalendar()
            wochen.setdefault((jahr, kw), []).append(tag)
        for name in namen:
            eigene = [abw for n, abw in paare if n == name]
            zeile = {t("Mitarbeiter", "Employee"): name}
            for (jahr, kw), wochentage in wochen.items():
                betroffen = [tg for tg in wochentage
                             if ist_arbeitstag(tg) and logik.abwesend_an(eigene, tg)]
                offen = any(any(a.status != "Genehmigt" for a in logik.abwesend_an(eigene, tg))
                            for tg in betroffen)
                kopf = f"KW{kw:02d}"
                zeile[kopf] = "" if not betroffen else ("🟨 " if offen else "🟩 ") + str(len(betroffen))
            zeilen.append(zeile)
    else:
        for name in namen:
            eigene = [abw for n, abw in paare if n == name]
            zeile = {t("Mitarbeiter", "Employee"): name}
            for tag in tage:
                kopf = (f"{WOCHENTAGE[st.session_state.sprache][tag.weekday()][:2]} "
                        f"{tag.strftime('%d.%m.')}")
                treffer = logik.abwesend_an(eigene, tag)
                if not treffer:
                    zeile[kopf] = "·" if ist_arbeitstag(tag) else ""
                elif any(a.status == "Genehmigt" for a in treffer):
                    zeile[kopf] = "🟩"
                else:
                    zeile[kopf] = "🟨"
            zeilen.append(zeile)
    return pd.DataFrame(zeilen)


def kommende_abwesenheiten(tage_voraus: int = 21) -> pd.DataFrame:
    """Aktuelle und kommende Abwesenheiten – ohne Angabe des Grundes.

    Für die Teamübersicht der Mitarbeitenden: Wer ist wann nicht da? Der Grund
    (Urlaub, Krankheit, …) geht die Kolleginnen und Kollegen nichts an.
    """
    heute_ = date.today()
    ende_fenster = heute_ + timedelta(days=tage_voraus)
    zeilen = []
    for name, abw in alle_abwesenheiten():
        if abw.status != "Genehmigt":
            continue
        if abw.ende < heute_ or abw.start > ende_fenster:
            continue
        if abw.start <= heute_ <= abw.ende:
            status = t("heute abwesend", "away today")
        else:
            tage_bis = (abw.start - heute_).days
            status = t(f"ab in {tage_bis} Tagen", f"in {tage_bis} days")
        zeilen.append({
            t("Mitarbeiter", "Employee"): name,
            t("Von", "From"): abw.start,
            t("Bis", "To"): abw.ende,
            t("Status", "Status"): status,
        })
    if not zeilen:
        return pd.DataFrame()
    df = pd.DataFrame(zeilen).sort_values(t("Von", "From")).reset_index(drop=True)
    return df


def _felder_anderer_auswahl_verwerfen(praefix: str, aktuelle_id: str, felder) -> None:
    """Entfernt die Formularfelder einer zuvor gewählten Zeile.

    Die Widget-Schlüssel enthalten die Datensatz-ID. Ohne das Aufräumen bliebe eine
    nicht gespeicherte Änderung erhalten und würde beim Zurückwechseln fälschlich
    als gespeicherter Stand erscheinen. Die Felder der aktuellen Auswahl werden in
    diesem Durchlauf erst danach erzeugt, das Löschen ist also unbedenklich.
    """
    behalten = {f"{praefix}{feld}_{aktuelle_id}" for feld in felder}
    for schluessel in [k for k in list(st.session_state.keys())
                       if isinstance(k, str) and k.startswith(praefix) and k not in behalten]:
        if any(schluessel.startswith(f"{praefix}{feld}_") for feld in felder):
            st.session_state.pop(schluessel, None)


def _ende_nachziehen(start_key: str, ende_key: str):
    """Zieht das Bis-Datum auf den Folgetag, sobald das Von-Datum verschoben wird.

    Läuft als on_change-Rückruf. Nur dort ist es erlaubt, den Wert eines anderen
    Widgets über den Sitzungszustand zu setzen.
    """
    def rueckruf():
        start = st.session_state.get(start_key)
        ende = st.session_state.get(ende_key)
        if not isinstance(start, date):
            return
        if not isinstance(ende, date) or ende <= start:
            st.session_state[ende_key] = start + timedelta(days=1)
    return rueckruf


if st.session_state.role == "Mitarbeiter":
    # ------------------------------------------------------------------
    # Mitarbeiter-Ansicht: bewusst schlank gehalten, weil sie fast
    # ausschließlich auf dem Handy benutzt wird. Alles, was nicht täglich
    # gebraucht wird, liegt hinter einem Aufklapper statt in einem Tab.
    # ------------------------------------------------------------------
    benutzer = st.session_state.user
    heute = date.today()
    limit_stunden = nachtragslimit_stunden(st.session_state.ma_id)
    grenze = nachtrag_grenze(st.session_state.ma_id)
    live_aktiv = cfg("live_stempeln_aktiv")
    alle_zeiten = st.session_state.time_logs
    offen = (alle_zeiten[(alle_zeiten["Mitarbeiter"] == benutzer) & (alle_zeiten["Status"] == "Läuft")]
             if not alle_zeiten.empty else alle_zeiten)

    # --- Wochenüberblick: eine Zeile, drei Zahlen -------------------
    wochenstart = heute - timedelta(days=heute.weekday())
    w_ist, w_soll, w_saldo = berechne_saldo(benutzer, wochenstart, heute)
    kennzahlen_leiste([
        (t("Ist", "Actual"), f"{w_ist:.1f}", "inherit"),
        (t("Soll", "Target"), f"{w_soll:.1f}", "inherit"),
        (t("Saldo", "Balance"), f"{w_saldo:+.1f}",
         "#1E7A46" if w_saldo >= 0 else "#C6362F"),
    ])

    # Ein-/Ausgestempelt-Status nur anzeigen, wenn Live-Stempeln aktiviert ist.
    if live_aktiv:
        status_text = (t("🟢 Eingestempelt", "🟢 Clocked in")
                       if not offen.empty
                       else t("⚪ Nicht eingestempelt", "⚪ Not clocked in"))
        st.markdown(
            f"<div class='badge {'badge-gruen' if not offen.empty else 'badge-grau'}' "
            f"style='margin-bottom:12px'>{status_text}</div>",
            unsafe_allow_html=True)

    if st.session_state.get("_zeit_kollisionsmeldung"):
        c_err, c_close = st.columns([10, 1])
        c_err.error(st.session_state["_zeit_kollisionsmeldung"])
        if c_close.button("✕", key="zeit_kollisionsmeldung_schliessen", help="Meldung schließen"):
            st.session_state.pop("_zeit_kollisionsmeldung", None)
            st.rerun()

    tab_erfassen, tab_uebersicht, tab_abwesenheit = st.tabs([
        t("⏱️ Erfassen", "⏱️ Record"),
        t("📋 Meine Zeiten", "📋 My times"),
        t("🌴 Abwesenheit", "🌴 Absence"),
    ])

    # ================= Erfassen =================
    with tab_erfassen:
        if live_aktiv:
            if not offen.empty:
                laufend = offen.iloc[-1]
                start_datum = laufend["Datum"]
                st.markdown(
                    f"<div class='badge badge-gruen'>🟢 {t('Läuft seit', 'Running since')} "
                    f"{laufend['Kommen']} · "
                    f"{start_datum.strftime(DATUMSFORMAT) if isinstance(start_datum, date) else start_datum}"
                    "</div>", unsafe_allow_html=True)
                if st.button(t("⏹️ FEIERABEND", "⏹️ CLOCK OUT"), key="btn_gehen",
                             use_container_width=True):
                    jetzt_zeit = datetime.now()
                    idx = offen.index[-1]
                    kommen = parse_zeit(st.session_state.time_logs.at[idx, "Kommen"])
                    try:
                        brutto, pause, netto = berechne_arbeitszeit(kommen, jetzt_zeit.time())
                    except ValueError as fehler:
                        st.error(str(fehler))
                    else:
                        st.session_state.time_logs.loc[
                            idx, ["Gehen", "Brutto (Std)", "Pause (Min)", "Netto (Std)", "Status"]
                        ] = [jetzt_zeit.strftime(ZEITFORMAT), brutto, pause, netto, "Erfasst"]
                        speichern("time_logs")
                        melde(f"Feierabend – {netto:.2f} Std. erfasst.",
                              f"Clocked out – {netto:.2f} h recorded.", "⏹️")
                        st.rerun()
            else:
                st.markdown(f"<div class='badge badge-grau'>⚪ "
                            f"{t('Nicht eingestempelt', 'Not clocked in')}</div>",
                            unsafe_allow_html=True)
                kategorie_live = kategorien()[0]
                if len(kategorien()) > 1:
                    kategorie_live = st.selectbox(t("Tätigkeit", "Activity"), kategorien(),
                                                  format_func=wert_label, key="live_kat")
                kunde_live_id, projekt_live_id, projekt_live_name = "", "", ""
                if B["projekt_aktiv"]:
                    if kunden_projekte_aktiv():
                        # Letzte Buchung vorbelegen – spart auf der Baustelle jeden Tag zwei Klicks
                        letzter_kunde, letztes_projekt = letzte_buchung_kunde_projekt(benutzer)
                        kdf = aktive_kunden_df(); kopt = ["__KEINER__"] + (kdf["Kunden-ID"].astype(str).tolist() if not kdf.empty else [])
                        kunde_live_id = st.selectbox(t("Kunde", "Customer"), kopt,
                                                     index=vorauswahl_index(kopt, letzter_kunde),
                                                     format_func=lambda x: t("Kein Kunde", "No customer") if x == "__KEINER__" else kunden_label(x), key="live_kunde")
                        if kunde_live_id == "__KEINER__": kunde_live_id = ""
                        popt = projekt_optionen_fuer_kunde(kunde_live_id)
                        projekt_widget_normalisieren("live_projekt_id", popt)
                        projekt_live_id = st.selectbox(t("Projekt (optional)", "Project (optional)"), popt,
                                                       index=vorauswahl_index(popt, letztes_projekt),
                                                       format_func=lambda x: t("— ohne Projekt —", "— no project —") if x == "__KEINER__" else projekt_label_id(x), key="live_projekt_id")
                        if projekt_live_id == "__KEINER__": projekt_live_id = ""
                        projekt_live_name = projekt_label_id(projekt_live_id) if projekt_live_id else ""
                        if kunde_live_id and not projekt_live_id:
                            st.caption(t("Wird nur auf den Kunden gebucht.",
                                         "Booked to the customer only."))
                    else:
                        projekt_live_name = st.text_input(projekt_label(), key="live_projekt")
                if st.button(t("▶️ ARBEIT STARTEN", "▶️ START WORK"), key="btn_kommen",
                             use_container_width=True):
                    jetzt_zeit = datetime.now()
                    kollision = pruefe_ueberschneidung(
                        benutzer, jetzt_zeit.date(), jetzt_zeit.time(), None)
                    if kollision:
                        st.session_state["_zeit_kollisionsmeldung"] = kollision
                        st.rerun()
                    st.session_state.time_logs = zeile_anhaengen(
                        st.session_state.time_logs,
                        {"ID": neue_id(), "Mitarbeiter": benutzer, "Datum": jetzt_zeit.date(),
                         "Kommen": jetzt_zeit.strftime(ZEITFORMAT), "Gehen": "",
                         "Brutto (Std)": pd.NA, "Pause (Min)": pd.NA, "Netto (Std)": pd.NA,
                         "Kategorie": kategorie_live, "Kunde-ID": str(kunde_live_id), "Projekt-ID": str(projekt_live_id), "Projekt": str(projekt_live_name).strip(),
                         "Notiz": "", "Typ": "Live", "Status": "Läuft"})
                    speichern("time_logs")
                    melde("Zeiterfassung gestartet.", "Time tracking started.", "▶️")
                    st.rerun()
            st.markdown("---")

        # --- Zeit eintragen: Werte kommen automatisch aus dem Wochenplan ---
        # Verkürzt die Leitung das Nachtragsfenster, kann ein bereits gemerktes Datum
        # unter min_value rutschen – Streamlit bricht dann ab. Deshalb vorher einfangen.
        # Wichtig: Der Sitzungswert wird nur angefasst, wenn er wirklich existiert und
        # außerhalb des erlaubten Bereichs liegt. Beim ersten Aufruf gibt es ihn noch
        # gar nicht, dann zählt allein der hier berechnete Vorgabewert.
        nachtrag_min = grenze.date()
        gemerktes_datum = st.session_state.get("ma_nachtrag_datum")
        if isinstance(gemerktes_datum, date):
            if not (nachtrag_min <= gemerktes_datum <= heute):
                gemerktes_datum = min(max(gemerktes_datum, nachtrag_min), heute)
                st.session_state["ma_nachtrag_datum"] = gemerktes_datum
            vorgabe_datum = gemerktes_datum
        else:
            vorgabe_datum = min(max(heute, nachtrag_min), heute)
        m_datum = st.date_input(t("Tag", "Day"), vorgabe_datum,
                                min_value=nachtrag_min, max_value=heute,
                                format=DATUMSFORMAT_UI, key="ma_nachtrag_datum")

        plan = tagesplan(benutzer, m_datum.weekday())
        if plan:
            st.caption(t(f"Wochenplan: {plan['soll']:.2f} Std.",
                         f"Weekly plan: {plan['soll']:.2f} h"))
        vorgabe_von = plan["von"] if plan else time(8, 0)
        vorgabe_bis = plan["bis"] if plan else time(16, 30)
        vorgabe_pause = plan["pause"] if plan else 0

        z1, z2 = st.columns(2)
        m_kommen = z1.time_input(t("Von", "From"), vorgabe_von, step=300, key="ma_von")
        m_gehen = z2.time_input(t("Bis", "To"), vorgabe_bis, step=300, key="ma_bis")

        # Ergebnis sofort sichtbar, noch vor dem Speichern
        try:
            v_brutto, v_pause, v_netto = berechne_arbeitszeit(m_kommen, m_gehen, vorgabe_pause)
            st.markdown(
                f"<div class='badge badge-gruen'>= {v_netto:.2f} {t('Std.', 'h')} "
                f"({t('Pause', 'break')} {v_pause} {t('Min.', 'min')})</div>",
                unsafe_allow_html=True)
            vorschau_ok = True
        except ValueError as fehler:
            st.markdown(f"<div class='badge badge-rot'>⚠️ {fehler}</div>", unsafe_allow_html=True)
            vorschau_ok = False

        with st.expander(t("Weitere Angaben", "More details")):
            m_pause = st.number_input(t("Pause (Min.)", "Break (min)"), 0, 480, int(vorgabe_pause), 5,
                                      key="ma_pause",
                                      help=t("Die gesetzliche Mindestpause wird automatisch abgezogen.",
                                             "The statutory minimum break is deducted automatically."))
            m_kategorie = st.selectbox(t("Tätigkeit", "Activity"), kategorien(),
                                       format_func=wert_label, key="ma_kat")
            m_kunde_id, m_projekt_id, m_projekt_name = "", "", ""
            if B["projekt_aktiv"]:
                if kunden_projekte_aktiv():
                    kdf = aktive_kunden_df(); kopt = ["__KEINER__"] + (kdf["Kunden-ID"].astype(str).tolist() if not kdf.empty else [])
                    letzter_kunde_m, letztes_projekt_m = letzte_buchung_kunde_projekt(benutzer)
                    m_kunde_id = st.selectbox(t("Kunde", "Customer"), kopt,
                                              index=vorauswahl_index(kopt, letzter_kunde_m),
                                              format_func=lambda x: t("Kein Kunde", "No customer") if x == "__KEINER__" else kunden_label(x), key="ma_kunde")
                    if m_kunde_id == "__KEINER__": m_kunde_id = ""
                    popt = projekt_optionen_fuer_kunde(m_kunde_id)
                    projekt_widget_normalisieren("ma_projekt_id", popt)
                    m_projekt_id = st.selectbox(t("Projekt (optional)", "Project (optional)"), popt,
                                                index=vorauswahl_index(popt, letztes_projekt_m),
                                                format_func=lambda x: t("— ohne Projekt —", "— no project —") if x == "__KEINER__" else projekt_label_id(x), key="ma_projekt_id")
                    if m_projekt_id == "__KEINER__": m_projekt_id = ""
                    m_projekt_name = projekt_label_id(m_projekt_id) if m_projekt_id else ""
                else:
                    m_projekt_name = st.text_input(projekt_label(), key="ma_projekt")
            m_notiz = st.text_input(t("Notiz", "Note"), key="ma_notiz")

        if st.button(t("💾 Speichern", "💾 Save"), use_container_width=True, type="primary",
                     key="ma_speichern", disabled=not vorschau_ok):
            kommen_zeitpunkt = datetime.combine(m_datum, m_kommen)
            if kommen_zeitpunkt < grenze:
                st.error(t(f"Nur bis {grenze.strftime(DATUMSFORMAT)} {grenze.strftime('%H:%M')} "
                           "Uhr rückwirkend möglich.",
                           f"Backdating only possible until {grenze.strftime(DATUMSFORMAT)} "
                           f"{grenze.strftime('%H:%M')}."))
            else:
                kollision = pruefe_ueberschneidung(benutzer, m_datum, m_kommen, m_gehen)
                if kollision:
                    st.session_state["_zeit_kollisionsmeldung"] = kollision
                    st.rerun()
                try:
                    brutto, pause, netto = berechne_arbeitszeit(m_kommen, m_gehen, m_pause)
                except ValueError as fehler:
                    st.error(str(fehler))
                else:
                    st.session_state.time_logs = zeile_anhaengen(
                        st.session_state.time_logs,
                        {"ID": neue_id(), "Mitarbeiter": benutzer, "Datum": m_datum,
                         "Kommen": m_kommen.strftime(ZEITFORMAT), "Gehen": m_gehen.strftime(ZEITFORMAT),
                         "Brutto (Std)": brutto, "Pause (Min)": pause, "Netto (Std)": netto,
                         "Kategorie": m_kategorie, "Kunde-ID": str(m_kunde_id), "Projekt-ID": str(m_projekt_id), "Projekt": str(m_projekt_name).strip(),
                         "Notiz": str(m_notiz).strip(), "Typ": "Manuell", "Status": "Erfasst"})
                    speichern("time_logs")
                    melde(f"Gespeichert: {netto:.2f} Std.", f"Saved: {netto:.2f} h", "💾")
                    st.rerun()

    # ================= Meine Zeiten =================
    with tab_uebersicht:
        zeitraum = st.radio(t("Zeitraum", "Period"),
                            ["woche", "monat", "frei"], label_visibility="collapsed",
                            format_func=lambda x: {"woche": t("Diese Woche", "This week"),
                                                   "monat": t("Dieser Monat", "This month"),
                                                   "frei": t("Zeitraum wählen", "Custom")}[x],
                            horizontal=True, key="ma_zeitraum")
        if zeitraum == "woche":
            von, bis = wochenstart, heute
        elif zeitraum == "monat":
            von, bis = heute.replace(day=1), heute
        else:
            f1, f2 = st.columns(2)
            von = f1.date_input(t("Von", "From"), heute.replace(day=1),
                                format=DATUMSFORMAT_UI, key="ma_von_f")
            bis = f2.date_input(t("Bis", "To"), heute, format=DATUMSFORMAT_UI, key="ma_bis_f")

        if von > bis:
            st.error(t("Das Startdatum liegt nach dem Enddatum.", "The start date is after the end date."))
        else:
            ist, soll, saldo = berechne_saldo(benutzer, von, bis)
            kennzahlen_leiste([
                (t("Ist", "Actual"), f"{ist:.1f}", "inherit"),
                (t("Soll", "Target"), f"{soll:.1f}", "inherit"),
                (t("Saldo", "Balance"), f"{saldo:+.1f}",
                 "#1E7A46" if saldo >= 0 else "#C6362F"),
            ])

            eigene = zeiten_von(benutzer, von, bis)
            if eigene.empty:
                st.info(t("Keine Einträge in diesem Zeitraum.", "No entries in this period."))
            else:
                def _innerhalb(zeile) -> bool:
                    zeit = parse_zeit(zeile["Kommen"]) or time(0, 0)
                    return (isinstance(zeile["Datum"], date)
                            and datetime.combine(zeile["Datum"], zeit) >= grenze)

                bearbeitbar = eigene[(eigene["Status"] == "Erfasst")
                                     & eigene.apply(_innerhalb, axis=1)].copy()
                gesperrt_zeilen = eigene[~eigene["ID"].isin(bearbeitbar["ID"])]

                if not bearbeitbar.empty:
                    if nachtrag_unbegrenzt(limit_stunden):
                        st.caption(t("Direkt in der Tabelle änderbar. Stunden werden beim "
                                     "Speichern neu berechnet.",
                                     "Edit directly in the table. Hours are recalculated on save."))
                    else:
                        st.caption(t(
                            f"Direkt in der Tabelle änderbar (bis {limit_stunden:.0f} Std. rückwirkend). "
                            "Stunden werden beim Speichern neu berechnet.",
                            f"Edit directly in the table (up to {limit_stunden:.0f} h back). "
                            "Hours are recalculated on save."))

                    # Ohne Projektfeld (z. B. Kita) bleibt die Spalte leer – dann weglassen
                    _raster_spalten = ["ID", "Datum", "Kommen", "Gehen", "Pause (Min)", "Kategorie"]
                    if B["projekt_aktiv"]:
                        _raster_spalten.append("Projekt")
                    _raster_spalten += ["Notiz", "Netto (Std)"]
                    raster = bearbeitbar[_raster_spalten].copy()
                    for spalte in ("Kommen", "Gehen"):
                        raster[spalte] = raster[spalte].apply(
                            lambda w: parse_zeit(w).strftime(ZEITFORMAT) if parse_zeit(w) else "")
                    raster["Datum"] = pd.to_datetime(raster["Datum"], errors="coerce")
                    raster["Pause (Min)"] = pd.to_numeric(
                        raster["Pause (Min)"], errors="coerce").fillna(0).astype(int)
                    raster["Netto (Std)"] = pd.to_numeric(raster["Netto (Std)"], errors="coerce").astype(float)
                    for spalte in ("Projekt", "Notiz", "Kategorie"):
                        if spalte in raster.columns:
                            raster[spalte] = raster[spalte].astype(str).replace(
                                {"nan": "", "<NA>": "", "None": ""})
                    raster["Löschen"] = False
                    kategorie_optionen = list(dict.fromkeys(
                        kategorien() + [k for k in raster["Kategorie"].unique() if k]))

                    # Auf dem Telefon sind neun Spalten unbenutzbar. Standard ist daher
                    # die kurze Ansicht; die übrigen Felder lassen sich zuschalten.
                    alle_spalten = st.toggle(t("Alle Felder anzeigen", "Show all fields"),
                                             value=False, key="ma_spalten_voll")
                    spalten_kurz = [sp for sp in ["ID", "Datum", "Kommen", "Gehen", "Netto (Std)", "Löschen"]
                                    if sp in raster.columns]
                    raster_anzeige = raster if alle_spalten else raster[spalten_kurz]

                    bearbeitet = st.data_editor(
                        raster_anzeige, use_container_width=True, hide_index=True, num_rows="fixed",
                        key="zeiten_editor",
                        column_config={
                            "ID": None,
                            "Datum": st.column_config.DateColumn(
                                spalten_label("Datum"), format=DATUMSFORMAT_UI, width="small",
                                min_value=grenze.date(), max_value=heute),
                            "Kommen": st.column_config.TextColumn(
                                spalten_label("Kommen"), width="small",
                                validate=r"^([01]?\d|2[0-3]):[0-5]\d$", help="HH:MM"),
                            "Gehen": st.column_config.TextColumn(
                                spalten_label("Gehen"), width="small",
                                validate=r"^([01]?\d|2[0-3]):[0-5]\d$", help="HH:MM"),
                            "Pause (Min)": st.column_config.NumberColumn(
                                spalten_label("Pause (Min)"), min_value=0, max_value=480,
                                step=5, format="%d", width="small"),
                            "Kategorie": st.column_config.SelectboxColumn(
                                spalten_label("Kategorie"), options=kategorie_optionen, width="medium"),
                            "Projekt": st.column_config.TextColumn(projekt_label(), width="medium"),
                            "Notiz": st.column_config.TextColumn(spalten_label("Notiz"), width="medium"),
                            "Netto (Std)": st.column_config.NumberColumn(
                                spalten_label("Netto (Std)"), disabled=True, format="%.2f",
                                width="small",
                                help=t("Wird automatisch berechnet.", "Calculated automatically.")),
                            "Löschen": st.column_config.CheckboxColumn(
                                spalten_label("Löschen"), width="small"),
                        })

                    # Sind Zeilen zum Löschen angekreuzt, kommt beim Speichern erst
                    # eine Rückfrage. Erst der zweite Klick löscht wirklich.
                    _ma_delete_ids = [str(x) for x in bearbeitet.loc[
                        bearbeitet["Löschen"].fillna(False).astype(bool), "ID"].tolist()]
                    _speichern_geklickt = st.button(
                        t("💾 Änderungen speichern", "💾 Save changes"),
                        use_container_width=True, type="primary", key="ma_zeiten_save")
                    if _speichern_geklickt and _ma_delete_ids:
                        st.session_state["_loeschfrage_ma_zeiten"] = _ma_delete_ids
                        _speichern_geklickt = False
                    _ma_bestaetigt = loeschabfrage(
                        "ma_zeiten", _ma_delete_ids,
                        t(f"{len(st.session_state.get('_loeschfrage_ma_zeiten') or [])} Zeiteintrag/-einträge endgültig löschen?",
                          f"Permanently delete {len(st.session_state.get('_loeschfrage_ma_zeiten') or [])} time entr(y/ies)?"),
                        t("Wiederherstellung nur über eine Datensicherung möglich.",
                          "Restoration is only possible from a backup."))
                    if _ma_bestaetigt or _speichern_geklickt:
                        logs = st.session_state.time_logs.copy()
                        fehler_liste, geaendert, geloescht = [], 0, 0
                        pruefbestand = buchungen_von(benutzer)
                        # In der Kurzansicht fehlen Spalten – Originalwerte als Rückfall
                        rueckfall = raster.set_index("ID").to_dict("index")
                        for _, zeile in bearbeitet.iterrows():
                            werte = {**rueckfall.get(zeile["ID"], {}), **zeile.to_dict()}
                            zeile = pd.Series(werte)
                            ziel = logs["ID"] == zeile["ID"]
                            if not ziel.any():
                                continue
                            if bool(zeile.get("Löschen", False)):
                                # Ohne Bestätigung bleibt der Eintrag stehen
                                if _ma_bestaetigt and str(zeile["ID"]) in (_ma_bestaetigt or []):
                                    logs = logs[~ziel]
                                    geloescht += 1
                                continue
                            neues_datum = zeile["Datum"]
                            if isinstance(neues_datum, pd.Timestamp):
                                neues_datum = neues_datum.date()
                            kommen, gehen = parse_zeit(zeile["Kommen"]), parse_zeit(zeile["Gehen"])
                            if kommen is None or gehen is None:
                                fehler_liste.append(t("Von und Bis müssen im Format HH:MM gefüllt sein.",
                                                      "From and to must be filled in HH:MM format."))
                                continue
                            if not isinstance(neues_datum, date) or datetime.combine(neues_datum, kommen) < grenze:
                                fehler_liste.append(t("Datum liegt außerhalb deines Änderungszeitraums.",
                                                      "Date is outside your editing window."))
                                continue
                            if neues_datum > heute:
                                fehler_liste.append(t("Zukünftige Tage sind nicht erlaubt.",
                                                      "Future dates are not allowed."))
                                continue
                            kollision = pruefe_ueberschneidung(
                                benutzer, neues_datum, kommen, gehen, eigene_id=str(zeile["ID"]),
                                bestand=pruefbestand)
                            if kollision:
                                fehler_liste.append(kollision)
                                continue
                            try:
                                brutto, pause, netto = berechne_arbeitszeit(
                                    kommen, gehen, int(pd.to_numeric(zeile["Pause (Min)"], errors="coerce") or 0))
                            except ValueError as fehler:
                                fehler_liste.append(str(fehler))
                                continue
                            # Geänderte Zeile im Prüfbestand nachziehen, damit sich
                            # mehrere Änderungen im selben Durchgang nicht überlappen
                            pruefbestand = [b for b in pruefbestand if b.id != str(zeile["ID"])]
                            pruefbestand.append(Buchung(str(zeile["ID"]), neues_datum, kommen, gehen))
                            logs.loc[ziel, ["Datum", "Kommen", "Gehen", "Brutto (Std)", "Pause (Min)",
                                            "Netto (Std)", "Kategorie", "Projekt", "Notiz", "Typ"]] = [
                                neues_datum, kommen.strftime(ZEITFORMAT), gehen.strftime(ZEITFORMAT),
                                brutto, pause, netto, zeile["Kategorie"],
                                str(zeile.get("Projekt") or "").strip(), str(zeile.get("Notiz") or "").strip(),
                                "Korrigiert"]
                            geaendert += 1

                        if fehler_liste:
                            for text in dict.fromkeys(fehler_liste):
                                st.error(text)
                        else:
                            st.session_state.time_logs = logs.reset_index(drop=True)
                            speichern("time_logs")
                            melde(f"{geaendert} geändert, {geloescht} gelöscht.",
                                  f"{geaendert} updated, {geloescht} deleted.", "💾")
                            st.rerun()

                if not gesperrt_zeilen.empty:
                    with st.expander(t(f"Abgeschlossene Einträge ({len(gesperrt_zeilen)})",
                                       f"Closed entries ({len(gesperrt_zeilen)})")):
                        st.caption(t("Änderungen nur über die Leitung.",
                                     "Changes via management only."))
                        tabelle(gesperrt_zeilen.drop(columns=["ID"]))

    # ================= Abwesenheit =================
    with tab_abwesenheit:
        anspruch, genehmigt, ausstehend, verfuegbar = get_urlaubs_konto(benutzer)
        kennzahlen_leiste([
            (t("Frei", "Free"), f"{verfuegbar}", "inherit"),
            (t("Genehmigt", "Approved"), f"{genehmigt}", "inherit"),
            (t("Offen", "Pending"), f"{ausstehend}", "inherit"),
        ])

        with st.expander(t("➕ Neuer Antrag", "➕ New request"), expanded=False):
            modus = st.radio(t("Umfang", "Scope"), ["Tage", "Stunden"],
                             label_visibility="collapsed",
                             format_func=lambda m: t("Ganze Tage", "Full days") if m == "Tage"
                             else t("Stundenweise", "Hourly"),
                             horizontal=True, key="abw_modus")
            # Dritter Wert des Tupels sagt, ob die Art stundenweise erlaubt ist
            moegliche_arten = [a for a in abwesenheitsarten() if modus == "Tage" or a[2]]
            art = st.selectbox(t("Grund", "Reason"), [a[0] for a in moegliche_arten],
                               format_func=wert_label, key="abw_art")
            if modus == "Tage":
                d1, d2 = st.columns(2)
                u_start = d1.date_input(t("Von", "From"), heute, format=DATUMSFORMAT_UI,
                                        key="abw_start", on_change=_ende_nachziehen("abw_start", "abw_ende"))
                # Streamlit wirft einen Fehler, wenn der gespeicherte Wert unter
                # min_value liegt. Das passiert, sobald "Von" in die Zukunft gesetzt
                # und das Feld zwischenzeitlich nicht gezeichnet wurde (z.B. beim
                # Umschalten auf "Stundenweise"). Deshalb beide Werte zusammen führen.
                abw_von_aktuell = st.session_state.get("abw_start", heute)
                if not isinstance(abw_von_aktuell, date):
                    abw_von_aktuell = heute
                abw_bis_aktuell = st.session_state.get("abw_ende", abw_von_aktuell + timedelta(days=1))
                if not isinstance(abw_bis_aktuell, date) or abw_bis_aktuell < abw_von_aktuell:
                    abw_bis_aktuell = abw_von_aktuell + timedelta(days=1)
                    st.session_state["abw_ende"] = abw_bis_aktuell
                u_ende = d2.date_input(t("Bis", "To"), abw_bis_aktuell,
                                       min_value=abw_von_aktuell,
                                       format=DATUMSFORMAT_UI, key="abw_ende")
                u_stunden = 0.0
                tage_vorschau = arbeitstage_zwischen(u_start, u_ende)
                st.caption(t(f"= {tage_vorschau} Arbeitstage", f"= {tage_vorschau} working days"))
            else:
                d1, d2 = st.columns(2)
                u_start = d1.date_input(t("Tag", "Day"), heute, format=DATUMSFORMAT_UI, key="abw_tag")
                u_ende = u_start
                standard = round(tagessoll(benutzer, u_start.weekday()) / 2, 1) or 4.0
                u_stunden = d2.number_input(t("Stunden", "Hours"), 0.5, 12.0, float(standard), 0.5,
                                            key="abw_stunden")
            u_kommentar = st.text_input(t("Kommentar", "Comment"), key="abw_kommentar")

            if st.button(t("🌴 Antrag senden", "🌴 Submit request"),
                         use_container_width=True, type="primary", key="abw_senden"):
                if modus == "Tage" and u_start > u_ende:
                    st.error(t("Das Startdatum darf nicht nach dem Enddatum liegen.",
                               "The start date must not be after the end date."))
                else:
                    tage = arbeitstage_zwischen(u_start, u_ende) if modus == "Tage" else 0
                    if modus == "Tage" and tage == 0:
                        st.error(t("Der Zeitraum enthält keine Arbeitstage.",
                                   "The period contains no working days."))
                    elif modus == "Tage" and art == "Urlaub" and tage > verfuegbar:
                        st.error(t(f"Nicht genug Resturlaub: {tage} beantragt, {verfuegbar} verfügbar.",
                                   f"Not enough leave: {tage} requested, {verfuegbar} available."))
                    else:
                        st.session_state.vacation_requests = zeile_anhaengen(
                            st.session_state.vacation_requests,
                            {"ID": neue_id(), "Mitarbeiter": benutzer, "Startdatum": u_start,
                             "Enddatum": u_ende, "Einheit": modus, "Tage": int(tage),
                             "Stunden": float(u_stunden), "Art": art,
                             "Kommentar": str(u_kommentar).strip(), "Status": "Ausstehend",
                             "Entscheidungsgrund": "", "Erfasst von": "",
                             "Eingereicht am": heute})
                        speichern("vacation_requests")
                        melde("Antrag eingereicht.", "Request submitted.", "🌴")
                        st.rerun()

        df_vac = st.session_state.vacation_requests
        eigene_antraege = df_vac[df_vac["Mitarbeiter"] == benutzer] if not df_vac.empty else df_vac
        if eigene_antraege.empty:
            st.info(t("Noch keine Anträge.", "No requests yet."))
        else:
            offene = eigene_antraege[eigene_antraege["Status"] == "Ausstehend"].copy()
            if not offene.empty:
                st.caption(t("Ankreuzen und zurückziehen.", "Tick and withdraw."))
                antrag_raster = offene[["ID", "Startdatum", "Enddatum", "Einheit",
                                        "Tage", "Stunden", "Art"]].copy()
                for spalte in ("Startdatum", "Enddatum"):
                    antrag_raster[spalte] = pd.to_datetime(antrag_raster[spalte], errors="coerce")
                antrag_raster["Zurückziehen"] = False
                antrag_bearbeitet = st.data_editor(
                    antrag_raster, use_container_width=True, hide_index=True, num_rows="fixed",
                    key="abw_editor",
                    column_config={
                        "ID": None,
                        "Startdatum": st.column_config.DateColumn(
                            spalten_label("Startdatum"), format=DATUMSFORMAT_UI, disabled=True),
                        "Enddatum": st.column_config.DateColumn(
                            spalten_label("Enddatum"), format=DATUMSFORMAT_UI, disabled=True),
                        "Einheit": st.column_config.TextColumn(spalten_label("Einheit"), disabled=True),
                        "Tage": st.column_config.NumberColumn(spalten_label("Tage"), disabled=True, format="%d"),
                        "Stunden": st.column_config.NumberColumn(spalten_label("Stunden"), disabled=True, format="%.1f"),
                        "Art": st.column_config.TextColumn(spalten_label("Art"), disabled=True),
                        "Zurückziehen": st.column_config.CheckboxColumn(t("Zurückziehen", "Withdraw")),
                    })
                if st.button(t("↩️ Ausgewählte zurückziehen", "↩️ Withdraw selected"),
                             use_container_width=True, key="abw_zurueck"):
                    ids = antrag_bearbeitet.loc[antrag_bearbeitet["Zurückziehen"].astype(bool), "ID"].tolist()
                    if not ids:
                        st.info(t("Nichts ausgewählt.", "Nothing selected."))
                    else:
                        st.session_state.vacation_requests = st.session_state.vacation_requests[
                            ~st.session_state.vacation_requests["ID"].isin(ids)].reset_index(drop=True)
                        speichern("vacation_requests")
                        melde(f"{len(ids)} Antrag/Anträge zurückgezogen.",
                              f"{len(ids)} request(s) withdrawn.", "↩️")
                        st.rerun()

            erledigt = eigene_antraege[eigene_antraege["Status"] != "Ausstehend"]
            if not erledigt.empty:
                # Abgelehnte Anträge zuerst und mit Begründung – sonst muss die
                # Person nachfragen, warum die Entscheidung so ausfiel.
                # Abgelehnte und stornierte Anträge werden deutlich angezeigt. Eine
                # Stornierung betrifft einen bereits genehmigten Urlaub – das muss die
                # Person sehen, sonst plant sie weiter mit freien Tagen.
                zu_zeigen = erledigt[erledigt["Status"].isin(["Abgelehnt", "Storniert"])]
                for _, zeile in zu_zeigen.iterrows():
                    zeitraum = (f"{zeile['Startdatum'].strftime(DATUMSFORMAT)}"
                                if zeile["Einheit"] == "Stunden"
                                else f"{zeile['Startdatum'].strftime(DATUMSFORMAT)} – "
                                     f"{zeile['Enddatum'].strftime(DATUMSFORMAT)}")
                    grund = str(zeile.get("Entscheidungsgrund") or "").strip()
                    if str(zeile["Status"]) == "Storniert":
                        st.warning(
                            f"**{t('Storniert', 'Cancelled')}: {zeitraum}**  \n"
                            + (f"{t('Grund', 'Reason')}: {grund}" if grund
                               else t("Ein genehmigter Urlaub wurde zurückgenommen – "
                                      "bitte bei der Leitung nachfragen.",
                                      "An approved leave was withdrawn – please ask your manager.")))
                    else:
                        st.error(
                            f"**{t('Abgelehnt', 'Rejected')}: {zeitraum}**  \n"
                            + (f"{t('Grund', 'Reason')}: {grund}" if grund
                               else t("Kein Grund hinterlegt – bitte bei der Leitung nachfragen.",
                                      "No reason recorded – please ask your manager.")))

                with st.expander(t(f"Bearbeitete Anträge ({len(erledigt)})",
                                   f"Processed requests ({len(erledigt)})")):
                    tabelle(erledigt.drop(columns=["ID", "Mitarbeiter", "Erfasst von"],
                                          errors="ignore"))

        # ---------- Wer ist gerade nicht da? ----------
        st.markdown("---")
        st.markdown(f"##### {t('Im Team abwesend', 'Team absences')}")
        team_df = kommende_abwesenheiten(21)
        if team_df.empty:
            st.caption(t("In den nächsten drei Wochen ist niemand abwesend.",
                         "Nobody is away in the next three weeks."))
        else:
            # Bewusst ohne Grund: Kolleginnen und Kollegen sehen nur, WER wann fehlt.
            st.dataframe(
                team_df, use_container_width=True, hide_index=True,
                column_config={
                    t("Mitarbeiter", "Employee"): st.column_config.TextColumn(width="medium"),
                    t("Von", "From"): st.column_config.DateColumn(format=DATUMSFORMAT_UI, width="small"),
                    t("Bis", "To"): st.column_config.DateColumn(format=DATUMSFORMAT_UI, width="small"),
                    t("Status", "Status"): st.column_config.TextColumn(width="small"),
                })
            st.caption(t("Nur Zeitraum, kein Grund.", "Period only, no reason shown."))


# ============================================================
# 13. LEITUNG / ADMIN-ANSICHT
# ============================================================

elif st.session_state.role == "Systemadministrator" and not st.session_state.get("systemadmin_adminmodus", False):
    st.title("🛠️ Systemadministrator")
    st.caption("Betreiber-/Wartungsebene der Software. Kunden sehen diesen Bereich nicht.")

    konto_df = st.session_state.benutzer.copy()
    aktive_kunden_admins = konto_df[(konto_df["Rolle"] == "Leitung / Admin") & konto_df["Aktiv"].astype(bool)]
    aktive_mitarbeiter = konto_df[(konto_df["Rolle"] == "Mitarbeiter") & konto_df["Aktiv"].astype(bool)]

    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Kunden-Admins", len(aktive_kunden_admins))
    k2.metric("Mitarbeiterkonten", len(aktive_mitarbeiter))
    k3.metric("Datenbank", "OK" if DB_DATEI.exists() and sqlite_integritaet_pruefen() else "Prüfen")
    k4.metric("Backups", len(list(BACKUP_DIR.glob("zeiterfassung_*.db"))) if BACKUP_DIR.exists() else 0)

    if st.button("👥 Leitungs-/Admin-Ansicht öffnen", type="primary", use_container_width=True):
        st.session_state.systemadmin_adminmodus = True
        st.rerun()

    tab_sys, tab_backup, tab_kunden, tab_sicherheit = st.tabs([
        "🖥️ System", "💾 Backups", "👤 Kundenkonten", "🔐 Sicherheit"
    ])

    with tab_sys:
        st.subheader("Systemstatus")
        st.write(f"**App-Version:** `{APP_VERSION}` ({APP_VERSIONSDATUM})")
        st.write(f"**App-Verzeichnis:** `{APP_DIR}`")
        st.write(f"**Datenbank:** `{DB_DATEI}`")
        st.write(f"**Datenbankgröße:** {DB_DATEI.stat().st_size / 1024:.1f} KB" if DB_DATEI.exists() else "Datenbank noch nicht vorhanden")
        if st.button("🔄 Datenbankintegrität prüfen", use_container_width=True):
            if sqlite_integritaet_pruefen():
                st.success("SQLite-Integritätsprüfung erfolgreich.")
            else:
                protokolliere("Integritätsprüfung fehlgeschlagen")
                st.error("Die Datenbankprüfung ist fehlgeschlagen.")

        st.markdown("---")
        st.subheader("Diagnosebericht")
        st.caption("Enthält Version, Umgebung, Datenbank- und Backup-Status sowie die letzten "
                   "Protokolleinträge – ohne personenbezogene Daten. Bei Support-Anfragen anhängen.")
        bericht = diagnosebericht()
        st.download_button(
            "📄 Diagnosebericht herunterladen",
            data=bericht.encode("utf-8"),
            file_name=f"diagnose_{datetime.now():%Y-%m-%d_%H-%M}.txt",
            mime="text/plain", use_container_width=True, type="primary",
        )
        with st.expander("Bericht ansehen"):
            st.code(bericht, language="text")

        st.markdown("---")
        st.subheader("Protokoll")
        eintraege = protokoll_zeilen(100)
        if eintraege:
            st.code("\n".join(eintraege), language="text")
            st.caption(f"Protokolldatei: `{LOG_DATEI}`")
        else:
            st.success("Keine Warnungen oder Fehler protokolliert.")

        st.info("Der Systemadministrator ist für technische Wartung vorgesehen. Kunden arbeiten ausschließlich mit ihren eigenen Leitungs-/Admin-Konten.")

    with tab_backup:
        st.subheader("Backups")
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        backups = sorted(BACKUP_DIR.glob("zeiterfassung_*.db"), reverse=True)
        if st.button("💾 Backup jetzt erstellen", type="primary", use_container_width=True):
            try:
                ziel = backup_datenbank()
                if ziel:
                    st.success(f"Backup erstellt: {ziel.name}")
                else:
                    st.error("Backup konnte nicht erstellt werden.")
            except Exception as exc:
                st.error(f"Backup fehlgeschlagen: {exc}")
        if backups:
            st.dataframe(pd.DataFrame([
                {"Datei": b.name, "Größe (KB)": round(b.stat().st_size / 1024, 1),
                 "Erstellt": datetime.fromtimestamp(b.stat().st_mtime).strftime("%d.%m.%Y %H:%M")}
                for b in backups[:20]
            ]), use_container_width=True, hide_index=True)
        else:
            st.caption("Noch keine Backups vorhanden.")

    with tab_kunden:
        st.subheader("Kundenkonten")
        kunden = konto_df[konto_df["Rolle"] == "Leitung / Admin"].copy()
        st.dataframe(kunden.drop(columns=["Salt", "Passwort_Hash"], errors="ignore"), use_container_width=True, hide_index=True)
        st.caption("Systemadministrator kann Kunden-Admin-Konten prüfen. Passwörter werden nicht angezeigt und nur als Hash gespeichert.")

    with tab_sicherheit:
        st.subheader("Sicherheit")
        st.write(f"Passwort-Mindestlänge: **{int(cfg('passwort_mindestlaenge'))} Zeichen**")
        st.write("Passwortverfahren: **scrypt** (Bestandskonten werden beim erfolgreichen Login automatisch migriert)")
        st.write(f"Login-Sperre: **{int(cfg('max_login_versuche'))} Fehlversuche / {int(cfg('sperrdauer_minuten'))} Minuten**")
        st.warning("Der Systemadministrator sollte ausschließlich für technische Wartung verwendet werden. Kein Kundenmitarbeiter sollte dieses Konto erhalten.")

    if st.button("🚪 Abmelden", use_container_width=True):
        st.session_state.logged_in = False
        st.rerun()
    st.stop()

elif rolle_erlaubt("Leitung / Admin") or (rolle_erlaubt("Systemadministrator") and st.session_state.get("systemadmin_adminmodus", False)):
    systemadmin_vollzugriff = st.session_state.role == "Systemadministrator"
    if systemadmin_vollzugriff:
        if st.button("🛠️ Zur Systemadministrator-Ansicht", use_container_width=True):
            st.session_state.systemadmin_adminmodus = False
            st.rerun()

    # Ein Leitungs-/Admin-Konto ist gleichzeitig ein normales Mitarbeiterkonto.
    # Deshalb bekommt die Leitung einen eigenen Bereich für die persönliche
    # Zeiterfassung und Abwesenheitsanträge – zusätzlich zu den Admin-Funktionen.
    # Platzhalter für die Warnung zu ungespeicherten Einstellungen. Er steht oberhalb
    # der Reiter, wird aber erst gefüllt, wenn der Einstellungen-Reiter weiter unten
    # durchlaufen ist – dadurch ist die Warnung auch in allen anderen Reitern sichtbar.
    warnleiste = st.empty()

    if st.session_state.get("_zeit_kollisionsmeldung"):
        c_err, c_close = st.columns([10, 1])
        c_err.error(st.session_state["_zeit_kollisionsmeldung"])
        if c_close.button("✕", key="admin_zeit_kollisionsmeldung_schliessen", help="Meldung schließen"):
            st.session_state.pop("_zeit_kollisionsmeldung", None)
            st.rerun()

    # Reiter richten sich nach der Branche: Eine Kita braucht weder Kunden noch
    # Projekte noch deren Auswertung. Leere Reiter mit Hinweistext wirken wie
    # fehlende Berechtigungen – besser gar nicht erst anzeigen.
    mit_kunden_projekten = kunden_projekte_aktiv()
    reiter_plan = [("meine_zeit", t("🕒 Meine Arbeitszeit", "🕒 My working time")),
                   ("zeiten", t("📊 Zeiten & Export", "📊 Times & export"))]
    if mit_kunden_projekten:
        reiter_plan.append(("auswertung", t("📈 Auswertung", "📈 Analysis")))
    reiter_plan += [("antraege", t("🌴 Anträge", "🌴 Requests")),
                    ("stamm", t("👥 Stammdaten", "👥 Employees"))]
    if mit_kunden_projekten:
        reiter_plan += [("kunden", t("👤 Kunden", "👤 Customers")),
                        ("projekte", t("📁 Projekte", "📁 Projects"))]
    reiter_plan += [("konten", t("🔐 Benutzerkonten", "🔐 User accounts")),
                    ("einst", t("⚙️ Einstellungen", "⚙️ Settings")),
                    ("hilfe", t("❓ Hilfe", "❓ Help"))]

    _tabs = st.tabs([beschriftung for _, beschriftung in reiter_plan])
    reiter = {name: tab for (name, _), tab in zip(reiter_plan, _tabs)}
    tab_meine_zeit = reiter["meine_zeit"]
    tab_zeiten = reiter["zeiten"]
    tab_antraege = reiter["antraege"]
    tab_stamm = reiter["stamm"]
    tab_konten = reiter["konten"]
    tab_einst = reiter["einst"]
    tab_hilfe = reiter["hilfe"]
    tab_auswertung = reiter.get("auswertung")
    tab_kunden_verwaltung = reiter.get("kunden")
    tab_projekte = reiter.get("projekte")

    # ---------------- Persönliche Zeiterfassung / Abwesenheiten ----------------
    with tab_meine_zeit:
        meine_ma_id = str(st.session_state.get("ma_id") or "")
        benutzer = id_zu_name(meine_ma_id) if meine_ma_id else ""
        if not benutzer:
            st.warning(t(
                "Deinem Admin-Konto ist kein aktiver Mitarbeiterdatensatz zugeordnet. "
                "Bitte lege den Mitarbeiterdatensatz an und verknüpfe das Konto über die MA-ID.",
                "Your admin account is not linked to an active employee record. "
                "Create the employee record and link the account using the employee ID."
            ))
        else:
            heute = date.today()
            alle_zeiten = st.session_state.time_logs
            offen = (
                alle_zeiten[(alle_zeiten["Mitarbeiter"] == benutzer) & (alle_zeiten["Status"] == "Läuft")]
                if not alle_zeiten.empty else alle_zeiten
            )
            live_aktiv = cfg("live_stempeln_aktiv")
            limit_stunden = nachtragslimit_stunden(meine_ma_id)
            grenze = nachtrag_grenze(meine_ma_id)

            st.markdown(f"### {t('Meine Arbeitszeit', 'My working time')}")
            # Die Nachtrags-Kachel entfällt: Leitung und Admin haben ohnehin ein
            # unbegrenztes Fenster, die Angabe hat also keinen Informationswert.
            if live_aktiv:
                k1, k2 = st.columns(2)
                k1.metric(t("Mitarbeiter", "Employee"), benutzer)
                k2.metric(t("Status", "Status"),
                          t("🟢 Eingestempelt", "🟢 Clocked in") if not offen.empty
                          else t("⚪ Nicht eingestempelt", "⚪ Not clocked in"))
            else:
                st.caption(f"**{benutzer}**")

            # Ist Live-Stempeln betrieblich abgeschaltet, wird der Bereich für alle
            # Rollen ausgeblendet – auch für die Leitung. Eine noch offene Buchung
            # bleibt sichtbar, damit sie geschlossen werden kann.
            if live_aktiv or not offen.empty:
                st.markdown(f"#### {t('Stempeln', 'Clock in/out')}")
                if not live_aktiv:
                    st.caption(t("Live-Stempeln ist betrieblich deaktiviert – nur die offene "
                                 "Buchung kann noch beendet werden.",
                                 "Live clocking is disabled – only the open entry can be closed."))
                _stempelbereich_sichtbar = True
            else:
                _stempelbereich_sichtbar = False

            if _stempelbereich_sichtbar:
              with st.container(border=True):
                s1, s2 = st.columns(2)
                kategorie = s1.selectbox(t("Kategorie", "Category"), kategorien(),
                                         format_func=wert_label, disabled=not offen.empty,
                                         key="admin_eigene_kategorie")
                admin_kunde_id, admin_projekt_id, projekt = "", "", ""
                if B["projekt_aktiv"]:
                    if kunden_projekte_aktiv():
                        kdf = aktive_kunden_df(); kopt = ["__KEINER__"] + (kdf["Kunden-ID"].astype(str).tolist() if not kdf.empty else [])
                        admin_kunde_id = s2.selectbox(t("Kunde", "Customer"), kopt, format_func=lambda x: t("Kein Kunde", "No customer") if x == "__KEINER__" else kunden_label(x), disabled=not offen.empty, key="admin_eigenes_kunde")
                        if admin_kunde_id == "__KEINER__": admin_kunde_id = ""
                        popt = projekt_optionen_fuer_kunde(admin_kunde_id)
                        projekt_widget_normalisieren("admin_eigenes_projekt", popt)
                        admin_projekt_id = s2.selectbox(t("Projekt (optional)", "Project (optional)"), popt, format_func=lambda x: t("— ohne Projekt —", "— no project —") if x == "__KEINER__" else projekt_label_id(x), disabled=not offen.empty, key="admin_eigenes_projekt")
                        if admin_projekt_id == "__KEINER__": admin_projekt_id = ""
                        projekt = projekt_label_id(admin_projekt_id) if admin_projekt_id else ""
                    else:
                        projekt = s2.text_input(projekt_label(), disabled=not offen.empty, key="admin_eigenes_projekt_text")
                b1, b2 = st.columns(2)
                if b1.button(t("▶️ KOMMEN", "▶️ CLOCK IN"), key="admin_btn_kommen",
                             use_container_width=True, disabled=not offen.empty or not live_aktiv):
                    now = datetime.now()
                    kollision = pruefe_ueberschneidung(benutzer, now.date(), now.time(), None)
                    if kollision:
                        st.session_state["_zeit_kollisionsmeldung"] = kollision
                        st.rerun()
                    st.session_state.time_logs = zeile_anhaengen(
                        st.session_state.time_logs,
                        {"ID": neue_id(), "Mitarbeiter": benutzer, "Datum": now.date(),
                         "Kommen": now.strftime(ZEITFORMAT), "Gehen": "",
                         "Brutto (Std)": pd.NA, "Pause (Min)": pd.NA, "Netto (Std)": pd.NA,
                         "Kategorie": kategorie, "Kunde-ID": str(admin_kunde_id), "Projekt-ID": str(admin_projekt_id), "Projekt": projekt.strip(), "Notiz": "",
                         "Typ": "Live", "Status": "Läuft"})
                    speichern("time_logs")
                    melde("Eingestempelt.", "Clocked in.", "▶️")
                    st.rerun()
                if b2.button(t("⏹️ GEHEN", "⏹️ CLOCK OUT"), key="admin_btn_gehen",
                             use_container_width=True, disabled=offen.empty or not live_aktiv):
                    now = datetime.now()
                    idx = offen.index[-1]
                    kommen = parse_zeit(st.session_state.time_logs.at[idx, "Kommen"])
                    try:
                        brutto, pause, netto = berechne_arbeitszeit(kommen, now.time())
                    except ValueError as fehler:
                        st.error(str(fehler))
                    else:
                        st.session_state.time_logs.loc[idx, ["Gehen", "Brutto (Std)", "Pause (Min)", "Netto (Std)", "Status"]] = [
                            now.strftime(ZEITFORMAT), brutto, pause, netto, "Erfasst"]
                        speichern("time_logs")
                        melde(f"Ausgestempelt – {netto:.2f} Std. netto (Pause {pause} Min.)",
                              f"Clocked out – {netto:.2f} h net (break {pause} min)", "⏹️")
                        st.rerun()

            st.markdown(f"#### {t('Zeit nachtragen', 'Add time')}")
            with st.container(border=True):
                with st.form("admin_nachtrag"):
                    # Leitung / Admin unterliegt beim Nachtragen keinem persönlichen Nachtragslimit.
                    m_datum = st.date_input(t("Datum", "Date"), heute,
                                            max_value=heute,
                                            format=DATUMSFORMAT_UI, key="admin_nach_datum")
                    c1, c2, c3 = st.columns(3)
                    m_kommen = c1.time_input(t("Kommen", "Start"), time(8, 0), step=300, key="admin_nach_kommen")
                    m_gehen = c2.time_input(t("Gehen", "End"), time(16, 30), step=300, key="admin_nach_gehen")
                    m_pause = c3.number_input(t("Pause (Min.)", "Break (min)"), 0, 480, 0, 5, key="admin_nach_pause")
                    c4, c5 = st.columns(2)
                    m_kategorie = c4.selectbox(t("Kategorie", "Category"), kategorien(), format_func=wert_label, key="admin_nach_kat")
                    admin_nach_kunde_id, admin_nach_projekt_id, m_projekt = "", "", ""
                    if B["projekt_aktiv"]:
                        if kunden_projekte_aktiv():
                            kdf = aktive_kunden_df(); kopt = ["__KEINER__"] + (kdf["Kunden-ID"].astype(str).tolist() if not kdf.empty else [])
                            admin_nach_kunde_id = c5.selectbox(t("Kunde", "Customer"), kopt, format_func=lambda x: t("Kein Kunde", "No customer") if x == "__KEINER__" else kunden_label(x), key="admin_nach_kunde")
                            if admin_nach_kunde_id == "__KEINER__": admin_nach_kunde_id = ""
                            popt = projekt_optionen_fuer_kunde(admin_nach_kunde_id)
                            projekt_widget_normalisieren("admin_nach_projekt", popt)
                            admin_nach_projekt_id = st.selectbox(t("Projekt (optional)", "Project (optional)"), popt, format_func=lambda x: t("— ohne Projekt —", "— no project —") if x == "__KEINER__" else projekt_label_id(x), key="admin_nach_projekt")
                            if admin_nach_projekt_id == "__KEINER__": admin_nach_projekt_id = ""
                            m_projekt = projekt_label_id(admin_nach_projekt_id) if admin_nach_projekt_id else ""
                        else:
                            m_projekt = c5.text_input(projekt_label(), key="admin_nach_projekt_text")
                    m_notiz = st.text_input(t("Notiz (optional)", "Note (optional)"), key="admin_nach_notiz")
                    gespeichert = st.form_submit_button(t("💾 Zeit speichern", "💾 Save time"), use_container_width=True, type="primary")
                if gespeichert:
                    kommen_zeitpunkt = datetime.combine(m_datum, m_kommen)
                    # Leitung / Admin darf immer korrigieren bzw. nachtragen; nur Zukunft ist verboten.
                    kollision = pruefe_ueberschneidung(benutzer, m_datum, m_kommen, m_gehen)
                    if kollision:
                        st.session_state["_zeit_kollisionsmeldung"] = kollision
                        st.rerun()
                    try:
                        brutto, pause, netto = berechne_arbeitszeit(m_kommen, m_gehen, m_pause)
                    except ValueError as fehler:
                        st.error(str(fehler))
                    else:
                        st.session_state.time_logs = zeile_anhaengen(
                            st.session_state.time_logs,
                            {"ID": neue_id(), "Mitarbeiter": benutzer, "Datum": m_datum,
                             "Kommen": m_kommen.strftime(ZEITFORMAT), "Gehen": m_gehen.strftime(ZEITFORMAT),
                             "Brutto (Std)": brutto, "Pause (Min)": pause, "Netto (Std)": netto,
                             "Kategorie": m_kategorie, "Kunde-ID": str(admin_nach_kunde_id), "Projekt-ID": str(admin_nach_projekt_id), "Projekt": m_projekt.strip(), "Notiz": m_notiz.strip(),
                             "Typ": "Manuell", "Status": "Erfasst"})
                        speichern("time_logs")
                        melde(f"Zeit gespeichert: {netto:.2f} Std. netto, Pause {pause} Min.",
                              f"Time saved: {netto:.2f} h net, break {pause} min", "💾")
                        st.rerun()

            st.markdown(f"#### {t('Meine Abwesenheiten', 'My absences')}")
            anspruch, genehmigt, ausstehend, verfuegbar = get_urlaubs_konto(benutzer)
            a1, a2, a3 = st.columns(3)
            a1.metric(t("Urlaubsanspruch", "Leave entitlement"), f"{anspruch} {t('Tage', 'days')}")
            a2.metric(t("Genehmigt", "Approved"), f"{genehmigt} {t('Tage', 'days')}")
            a3.metric(t("Verfügbar", "Available"), f"{verfuegbar} {t('Tage', 'days')}")

            with st.container(border=True):
                modus = st.radio(t("Art der Abwesenheit", "Type of absence"), ["Tage", "Stunden"],
                                 format_func=lambda m: t("Ganze Tage", "Full days") if m == "Tage" else t("Stundenweise", "Hourly"),
                                 horizontal=True, key="admin_abw_modus")
                moegliche_arten = [a for a in abwesenheitsarten() if modus == "Tage" or a[2]]
                art = st.selectbox(t("Grund", "Reason"), [a[0] for a in moegliche_arten],
                                   format_func=wert_label, key="admin_abw_art")
                d1, d2 = st.columns(2)
                if modus == "Tage":
                    u_start = d1.date_input(t("Startdatum", "Start date"), heute, format=DATUMSFORMAT_UI,
                                            key="admin_abw_start",
                                            on_change=_ende_nachziehen("admin_abw_start", "admin_abw_ende"))
                    # Streamlit darf keinen bestehenden Endwert anzeigen, der vor
                    # dem aktuellen Startdatum liegt. Das kann z.B. passieren, wenn
                    # das Startdatum zuvor auf einen späteren Tag gesetzt wurde.
                    admin_abw_start_aktuell = st.session_state.get("admin_abw_start", heute)
                    if not isinstance(admin_abw_start_aktuell, date):
                        admin_abw_start_aktuell = heute
                    admin_abw_ende_aktuell = st.session_state.get("admin_abw_ende", heute + timedelta(days=1))
                    if (not isinstance(admin_abw_ende_aktuell, date)
                            or admin_abw_ende_aktuell < admin_abw_start_aktuell):
                        admin_abw_ende_aktuell = admin_abw_start_aktuell + timedelta(days=1)
                        st.session_state["admin_abw_ende"] = admin_abw_ende_aktuell
                    u_ende = d2.date_input(t("Enddatum", "End date"), admin_abw_ende_aktuell,
                                           min_value=admin_abw_start_aktuell,
                                           format=DATUMSFORMAT_UI, key="admin_abw_ende")
                    u_stunden = 0.0
                else:
                    u_start = d1.date_input(t("Datum", "Date"), heute, format=DATUMSFORMAT_UI, key="admin_abw_tag")
                    u_ende = u_start
                    u_stunden = d2.number_input(t("Stunden", "Hours"), 0.5, 12.0,
                                                value=round(tagessoll(benutzer) / 2, 1), step=0.5, key="admin_abw_stunden")
                u_kommentar = st.text_input(t("Kommentar (optional)", "Comment (optional)"), key="admin_abw_kommentar")
                if st.button(t("🌴 Antrag absenden", "🌴 Submit request"), key="admin_abw_absenden",
                             use_container_width=True, type="primary"):
                    if modus == "Tage" and u_start > u_ende:
                        st.error(t("Das Startdatum darf nicht nach dem Enddatum liegen.", "The start date must not be after the end date."))
                    else:
                        tage = arbeitstage_zwischen(u_start, u_ende) if modus == "Tage" else 0
                        if modus == "Tage" and tage == 0:
                            st.error(t("Der Zeitraum enthält keine Arbeitstage.", "The period contains no working days."))
                        elif modus == "Tage" and art == "Urlaub" and tage > verfuegbar:
                            st.error(t(f"Nicht genug Resturlaub: {tage} Tage beantragt, {verfuegbar} verfügbar.",
                                       f"Not enough leave left: {tage} days requested, {verfuegbar} available."))
                        else:
                            st.session_state.vacation_requests = zeile_anhaengen(
                                st.session_state.vacation_requests,
                                {"ID": neue_id(), "Mitarbeiter": benutzer, "Startdatum": u_start,
                                 "Enddatum": u_ende, "Einheit": modus, "Tage": int(tage),
                                 "Stunden": float(u_stunden), "Art": art, "Kommentar": u_kommentar.strip(),
                                 "Status": "Ausstehend", "Eingereicht am": heute,
                                 "Entscheidungsgrund": "", "Erfasst von": ""})
                            speichern("vacation_requests")
                            melde("Abwesenheitsantrag eingereicht.", "Absence request submitted.", "🌴")
                            st.rerun()

            eigene_antraege = st.session_state.vacation_requests[st.session_state.vacation_requests["Mitarbeiter"] == benutzer] if not st.session_state.vacation_requests.empty else st.session_state.vacation_requests
            if not eigene_antraege.empty:
                st.markdown(f"##### {t('Meine Anträge', 'My requests')}")
                tabelle(eigene_antraege.drop(columns=["ID", "Mitarbeiter"]))

    # ---------------- Zeiten & Export ----------------
    with tab_zeiten:
        st.markdown(f"#### {t('Alle Mitarbeiterzeiten', 'All employee times')}")
        st.caption(t(
            "Leitung / Admin kann hier die Arbeitszeiten aller Mitarbeiter unabhängig vom persönlichen Nachtragslimit bearbeiten.",
            "Management / admin can edit all employees' working times here regardless of their personal backdating limit."))
        af1, af2, af3 = st.columns([1, 1, 1])
        admin_heute = date.today()
        admin_von = af1.date_input(t("Von", "From"), admin_heute.replace(day=1), format=DATUMSFORMAT_UI, key="admin_zeiten_von")
        admin_bis = af2.date_input(t("Bis", "To"), admin_heute, format=DATUMSFORMAT_UI, key="admin_zeiten_bis")
        alle_personen = alle_mitarbeiter()
        namen = alle_personen["Mitarbeiter"].astype(str).tolist() if not alle_personen.empty else []
        namen = sorted([n for n in namen if n and n != "nan"])
        auswahl_person = af3.selectbox(t("Mitarbeiter", "Employee"), ["__ALLE__"] + namen, format_func=lambda x: t("Alle Mitarbeiter", "All employees") if x == "__ALLE__" else x, key="admin_zeiten_person") if namen else "__ALLE__"
        if admin_von > admin_bis:
            st.error(t("Das Startdatum liegt nach dem Enddatum.", "The start date is after the end date."))
        else:
            admin_zeiten = zeiten_abfragen(None if auswahl_person == "__ALLE__" else auswahl_person, admin_von, admin_bis)
            if admin_zeiten.empty:
                st.info(t("Für diesen Zeitraum sind keine Arbeitszeiten vorhanden.", "No working times exist for this period."))
            else:
                edit = admin_zeiten.copy()
                for c in ("Datum",):
                    edit[c] = pd.to_datetime(edit[c], errors="coerce")
                for c in ("Pause (Min)",):
                    edit[c] = pd.to_numeric(edit[c], errors="coerce").fillna(0).astype(int)
                for c in ("Brutto (Std)", "Netto (Std)"):
                    edit[c] = pd.to_numeric(edit[c], errors="coerce")
                edit["Löschen"] = False
                # Ohne Kunden-/Projektmodul (z. B. Kita) bleiben diese Spalten leer –
                # dann gar nicht erst anzeigen.
                _spalten_edit = ["ID", "Mitarbeiter", "Datum", "Kommen", "Gehen", "Pause (Min)", "Kategorie"]
                if mit_kunden_projekten:
                    _spalten_edit += ["Kunde-ID", "Projekt-ID"]
                if B["projekt_aktiv"]:
                    _spalten_edit.append("Projekt")
                _spalten_edit += ["Notiz", "Typ", "Status", "Netto (Std)", "Löschen"]
                edit = edit[_spalten_edit]
                # Auswahllisten einmal bilden statt je Spaltenkonfiguration erneut
                _kdf = aktive_kunden_df()
                _pdf = aktive_projekte_df()
                _kunden_ids = [str(x) for x in _kdf["Kunden-ID"].tolist()] if not _kdf.empty else []
                _projekt_ids = [str(x) for x in _pdf["Projekt-ID"].tolist()] if not _pdf.empty else []
                typ_optionen = list(dict.fromkeys(["Normal", "Korrigiert", "Nachtrag", "Import"] + [str(x) for x in edit["Typ"].dropna().unique() if str(x) not in ("", "nan")]))
                status_optionen = ["Läuft", "Erfasst", "Freigegeben"]
                kategorie_optionen = list(dict.fromkeys(kategorien() + [str(x) for x in edit["Kategorie"].dropna().unique() if str(x) not in ("", "nan")]))
                edited = st.data_editor(edit, use_container_width=True, hide_index=True, num_rows="fixed", key="admin_zeiten_editor", column_config={
                    "ID": None,
                    "Datum": st.column_config.DateColumn(spalten_label("Datum"), format=DATUMSFORMAT_UI),
                    "Kommen": st.column_config.TextColumn(spalten_label("Kommen"), validate=r"^([01]?\d|2[0-3]):[0-5]\d$"),
                    "Gehen": st.column_config.TextColumn(spalten_label("Gehen"), validate=r"^([01]?\d|2[0-3]):[0-5]\d$"),
                    "Pause (Min)": st.column_config.NumberColumn(spalten_label("Pause (Min)"), min_value=0, max_value=480, step=5, format="%d"),
                    "Kategorie": st.column_config.SelectboxColumn(spalten_label("Kategorie"), options=kategorie_optionen),
                    "Kunde-ID": st.column_config.SelectboxColumn(t("Kunde", "Customer"), options=_kunden_ids),
                    "Projekt-ID": st.column_config.SelectboxColumn(t("Projekt", "Project"), options=_projekt_ids),
                    "Typ": st.column_config.SelectboxColumn(spalten_label("Typ"), options=typ_optionen),
                    "Status": st.column_config.SelectboxColumn(spalten_label("Status"), options=status_optionen),
                    "Netto (Std)": st.column_config.NumberColumn(spalten_label("Netto (Std)"), disabled=True, format="%.2f"),
                    "Löschen": st.column_config.CheckboxColumn(t("Löschen", "Delete")),
                })
                _admin_delete_ids = [str(x) for x in edited.loc[
                    edited["Löschen"].fillna(False).astype(bool), "ID"].tolist()]
                _admin_speichern = st.button(
                    t("💾 Alle Änderungen speichern", "💾 Save all changes"),
                    key="admin_zeiten_save", type="primary", use_container_width=True)
                if _admin_speichern and _admin_delete_ids:
                    st.session_state["_loeschfrage_admin_zeiten"] = _admin_delete_ids
                    _admin_speichern = False
                _admin_bestaetigt = loeschabfrage(
                    "admin_zeiten", _admin_delete_ids,
                    t(f"{len(st.session_state.get('_loeschfrage_admin_zeiten') or [])} Zeiteintrag/-einträge endgültig löschen?",
                      f"Permanently delete {len(st.session_state.get('_loeschfrage_admin_zeiten') or [])} time entr(y/ies)?"),
                    t("Betrifft auch bereits freigegebene Zeiten. Wiederherstellung nur über eine Datensicherung.",
                      "This also affects released times. Restoration only from a backup."))
                if _admin_bestaetigt or _admin_speichern:
                    logs = st.session_state.time_logs.copy()
                    fehler = []
                    pruefbestaende: dict = {}
                    for _, row in edited.iterrows():
                        mask = logs["ID"].astype(str) == str(row["ID"])
                        if not mask.any():
                            continue
                        if bool(row.get("Löschen", False)):
                            # Nur löschen, was in der Rückfrage bestätigt wurde
                            if _admin_bestaetigt and str(row["ID"]) in (_admin_bestaetigt or []):
                                logs = logs.loc[~mask].reset_index(drop=True)
                            continue
                        kommen, gehen = parse_zeit(row["Kommen"]), parse_zeit(row["Gehen"])
                        datum = row["Datum"].date() if isinstance(row["Datum"], pd.Timestamp) else row["Datum"]
                        if kommen is None or gehen is None or not isinstance(datum, date):
                            fehler.append(f"{row['ID']}: " + t("Datum/Kommen/Gehen ungültig.", "Invalid date/start/end.")); continue
                        person = str(row["Mitarbeiter"])
                        kollision = pruefe_ueberschneidung(
                            person, datum, kommen, gehen, eigene_id=str(row["ID"]),
                            bestand=pruefbestaende.setdefault(person, buchungen_von(person)))
                        if kollision:
                            fehler.append(f"{person}: {kollision}"); continue
                        try:
                            brutto, pause, netto = berechne_arbeitszeit(kommen, gehen, int(pd.to_numeric(row["Pause (Min)"], errors="coerce") or 0))
                        except ValueError as exc:
                            fehler.append(f"{row['ID']}: {exc}"); continue
                        # Prüfbestand nachziehen, damit mehrere Änderungen in einem
                        # Durchgang sich nicht gegenseitig überlappen können
                        pruefbestaende[person] = [b for b in pruefbestaende[person] if b.id != str(row["ID"])]
                        pruefbestaende[person].append(Buchung(str(row["ID"]), datum, kommen, gehen))
                        # Nicht angezeigte Spalten behalten ihren gespeicherten Wert
                        _alt_zeile = logs.loc[mask].iloc[0]
                        logs.loc[mask, ["Mitarbeiter", "Datum", "Kommen", "Gehen", "Brutto (Std)", "Pause (Min)", "Netto (Std)", "Kategorie", "Kunde-ID", "Projekt-ID", "Projekt", "Notiz", "Typ", "Status"]] = [
                            str(row["Mitarbeiter"]), datum, kommen.strftime(ZEITFORMAT), gehen.strftime(ZEITFORMAT), brutto, pause, netto,
                            str(row.get("Kategorie", "")),
                            str(row.get("Kunde-ID", _alt_zeile.get("Kunde-ID", "")) or ""),
                            str(row.get("Projekt-ID", _alt_zeile.get("Projekt-ID", "")) or ""),
                            str(row.get("Projekt", _alt_zeile.get("Projekt", "")) or ""),
                            str(row.get("Notiz", "") or ""), str(row.get("Typ", "Korrigiert") or "Korrigiert"), str(row.get("Status", "Erfasst"))
                        ]
                    if fehler:
                        # Bei Fehlern wird nichts gespeichert – sonst landet ein
                        # Teil der Änderungen in der Datenbank und der Rest nicht.
                        for text in dict.fromkeys(fehler[:10]):
                            st.error(text)
                    else:
                        st.session_state.time_logs = logs
                        speichern("time_logs")
                        melde("Arbeitszeiten gespeichert.", "Working times saved.", "💾")
                        st.rerun()

        st.markdown("---")
        if st.session_state.time_logs.empty:
            st.info(t("Bisher wurden keine Arbeitszeiten erfasst.", "No working times recorded yet."))
        else:
            heute = date.today()
            c1, c2, c3 = st.columns([2, 1, 1])
            auswahl_ma = c1.multiselect(t("Mitarbeitende", "Employees"), aktive_mitarbeiter(), default=[])
            von = c2.date_input(t("Von", "From"), heute.replace(day=1), format=DATUMSFORMAT_UI, key="ad_von")
            bis = c3.date_input(t("Bis", "To"), heute, format=DATUMSFORMAT_UI, key="ad_bis")

            gefiltert = zeiten_von(None, von, bis)
            if auswahl_ma:
                gefiltert = gefiltert[gefiltert["Mitarbeiter"].isin(auswahl_ma)]

            if gefiltert.empty:
                st.warning(t("Keine Einträge im gewählten Zeitraum.", "No entries in the selected period."))
            else:
                netto_summe = pd.to_numeric(gefiltert["Netto (Std)"], errors="coerce").sum()
                k1, k2, k3 = st.columns(3)
                k1.metric(t("Einträge", "Entries"), len(gefiltert))
                k2.metric(t("Netto-Stunden gesamt", "Total net hours"), f"{netto_summe:.2f}")
                k3.metric(t("Laufend", "Running"), int((gefiltert["Status"] == "Läuft").sum()))

                # Interne IDs gehören nicht in eine Übersicht: Bei aktivem Modul
                # werden Kunde und Projekt als Klarnamen gezeigt, sonst entfallen
                # die Spalten ganz.
                if mit_kunden_projekten:
                    anzeige_gefiltert = zeit_mit_kunden_projekten(gefiltert).drop(
                        columns=["Kunde-ID", "Projekt-ID"], errors="ignore")
                else:
                    anzeige_gefiltert = gefiltert.drop(
                        columns=["Kunde-ID", "Projekt-ID"], errors="ignore")
                tabelle(anzeige_gefiltert)

                st.markdown(f"##### {t('Auswertung je Mitarbeiter', 'Per-employee summary')}")
                auswertung = []
                for name in sorted(gefiltert["Mitarbeiter"].unique()):
                    ist, soll, saldo = berechne_saldo(name, von, bis)
                    auswertung.append({
                        spalten_label("Mitarbeiter"): name,
                        spalten_label("Ist (Std)"): ist,
                        spalten_label("Soll (Std)"): soll,
                        spalten_label("Saldo (Std)"): saldo,
                    })
                st.dataframe(
                    pd.DataFrame(auswertung), use_container_width=True, hide_index=True,
                    column_config={
                        spalten_label("Mitarbeiter"): st.column_config.TextColumn(
                            spalten_label("Mitarbeiter"), width="medium"),
                        spalten_label("Ist (Std)"): st.column_config.NumberColumn(
                            spalten_label("Ist (Std)"), format="%.2f"),
                        spalten_label("Soll (Std)"): st.column_config.NumberColumn(
                            spalten_label("Soll (Std)"), format="%.2f"),
                        spalten_label("Saldo (Std)"): st.column_config.NumberColumn(
                            spalten_label("Saldo (Std)"), format="%+.2f"),
                    },
                )

                e1, e2 = st.columns(2)
                dateiname = f"Zeiterfassung_{von.strftime('%Y%m%d')}_{bis.strftime('%Y%m%d')}"
                e1.download_button(t("📥 Excel exportieren", "📥 Export Excel"),
                                   data=konvertiere_zu_excel(gefiltert),
                                   file_name=f"{dateiname}.xlsx",
                                   mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                                   use_container_width=True)
                e2.download_button(t("📥 CSV exportieren (Excel/DE)", "📥 Export CSV (Excel/DE)"),
                                   data=konvertiere_zu_csv(gefiltert), file_name=f"{dateiname}.csv",
                                   mime="text/csv", use_container_width=True)

                if st.button(t("✅ Angezeigte Einträge freigeben", "✅ Release shown entries"),
                             use_container_width=True):
                    ids = gefiltert.loc[gefiltert["Status"] == "Erfasst", "ID"]
                    maske = st.session_state.time_logs["ID"].isin(ids)
                    st.session_state.time_logs.loc[maske, "Status"] = "Freigegeben"
                    speichern("time_logs")
                    melde(f"{int(maske.sum())} Einträge freigegeben.",
                          f"{int(maske.sum())} entries released.", "✅")
                    st.rerun()

        # Bearbeitung über die Eintrags-ID ist ausschließlich ein Werkzeug des
        # Systemadministrators (Support). Leitung und Admin ändern Zeiten oben
        # direkt in der Tabelle.
        if st.session_state.role == "Systemadministrator":
            st.markdown("---")
            st.markdown("##### 🛠️ Systemadmin: Einzelnen Eintrag über die ID bearbeiten")
            zeit_df = st.session_state.time_logs.copy()
            if zeit_df.empty:
                st.info("Keine Arbeitszeiten vorhanden.")
            else:
                st.caption("Klicke in der Tabelle auf einen Zeiteintrag. Dieser wird automatisch in die Bearbeitungsmaske übernommen.")
                zeit_tabelle = zeit_df.copy()
                zeit_anzeige = zeit_tabelle.drop(columns=["ID"], errors="ignore")
                zeit_event = st.dataframe(
                    anzeige_df(zeit_anzeige),
                    use_container_width=True,
                    hide_index=True,
                    column_config=spalten_config(zeit_anzeige),
                    on_select="rerun",
                    selection_mode="single-row",
                    key="sys_zeit_tabelle",
                )
                zeit_rows = getattr(getattr(zeit_event, "selection", None), "rows", []) or []
                if zeit_rows:
                    ausgewaehlte_zeit_id = str(zeit_tabelle.iloc[zeit_rows[0]]["ID"])
                    # Die Widget-Schlüssel unten enthalten die Eintrags-ID. Dadurch ist
                    # jede Zeile ein eigenes Formular und lädt ihre eigenen Werte –
                    # das Löschen der Schlüssel ist dafür nicht nötig und funktioniert
                    # bei Streamlit auch nicht zuverlässig.
                    if st.session_state.get("sys_zeit_id") != ausgewaehlte_zeit_id:
                        st.session_state["sys_zeit_id"] = ausgewaehlte_zeit_id
                        _felder_anderer_auswahl_verwerfen(
                            "sys_zeit_", ausgewaehlte_zeit_id,
                            ("ma", "datum", "status", "kommen", "gehen", "pause",
                             "kat", "typ", "projekt", "notiz", "delete_confirm"))
                ziel_id = st.session_state.get("sys_zeit_id")
                if not ziel_id or not (zeit_df["ID"].astype(str) == str(ziel_id)).any():
                    st.info("Bitte oben einen Zeiteintrag anklicken.")
                    ziel_id = None
                if ziel_id:
                    zidx = zeit_df.index[zeit_df["ID"].astype(str) == str(ziel_id)][0]
                    z = zeit_df.loc[zidx]
                    # Werte robust vorbereiten: Bei laufenden Buchungen ist "Gehen" leer
                    # und steht je nach Herkunft als "", None oder "nan" in den Daten.
                    # parse_zeit liefert dann None – ein Zeitfeld ohne Wert lässt sich
                    # zwar anzeigen, aber beim Speichern nicht formatieren.
                    # Streamlit date_input expects a native datetime.date.
                    # pandas.Timestamp is also an instance of date, so a simple
                    # isinstance(..., date) check would leave the Timestamp in
                    # place. In that case Streamlit can fall back to today's date
                    # instead of the selected record's date. Always normalize the
                    # stored value explicitly to a native Python date.
                    _zdatum = pd.to_datetime(z["Datum"], errors="coerce")
                    zdatum = _zdatum.date() if pd.notna(_zdatum) else date.today()
                    zkommen = parse_zeit(z["Kommen"]) or time(8, 0)
                    zgehen = parse_zeit(z["Gehen"]) or time(16, 30)
                    zpause_roh = pd.to_numeric(z["Pause (Min)"], errors="coerce")
                    zpause = int(zpause_roh) if pd.notna(zpause_roh) else 0
                    zpause = max(0, min(480, zpause))
                    # Die Formular-Widget-Keys enthalten zusätzlich einen Fingerabdruck
                    # des gespeicherten Datensatzes. Dadurch werden die Werte beim Wechsel
                    # auf einen Eintrag sicher aus der Tabelle übernommen – insbesondere
                    # das Datum darf nicht vom vorherigen Datensatz "mitgeschleppt" werden.
                    # Nach einer Bearbeitung ändert sich der Fingerabdruck und die Maske
                    # wird beim nächsten Lauf wieder mit dem tatsächlich gespeicherten
                    # Datensatz aufgebaut.
                    _sys_zeit_fingerprint = "|".join(str(z.get(f, "")) for f in (
                        "Mitarbeiter", "Datum", "Kommen", "Gehen", "Pause (Min)",
                        "Kategorie", "Typ", "Projekt", "Notiz", "Status"))
                    _sys_zeit_form_suffix = hashlib.sha1(_sys_zeit_fingerprint.encode("utf-8")).hexdigest()[:10]
                    with st.form(f"sys_zeit_bearbeiten_{ziel_id}_{_sys_zeit_form_suffix}"):
                        c1, c2, c3 = st.columns(3)
                        alle_namen = sorted(st.session_state.mitarbeiter_stammdaten["Mitarbeiter"].astype(str).tolist())
                        if str(z["Mitarbeiter"]) not in alle_namen:
                            alle_namen.append(str(z["Mitarbeiter"]))
                        ez_mitarbeiter = c1.selectbox("Mitarbeiter", alle_namen,
                                                       index=(alle_namen.index(z["Mitarbeiter"])
                                                              if z["Mitarbeiter"] in alle_namen else 0),
                                                       key=f"sys_zeit_ma_{ziel_id}_{_sys_zeit_form_suffix}")
                        ez_datum = c2.date_input("Datum", zdatum, format=DATUMSFORMAT_UI, key=f"sys_zeit_datum_{ziel_id}_{_sys_zeit_form_suffix}")
                        ez_status = c3.selectbox("Status", ["Läuft", "Erfasst", "Freigegeben"],
                                                 index=(["Läuft", "Erfasst", "Freigegeben"].index(str(z["Status"]))
                                                        if str(z["Status"]) in ["Läuft", "Erfasst", "Freigegeben"] else 1),
                                                 key=f"sys_zeit_status_{ziel_id}_{_sys_zeit_form_suffix}")
                        c4, c5, c6 = st.columns(3)
                        ez_kommen = c4.time_input("Kommen", zkommen, step=300, key=f"sys_zeit_kommen_{ziel_id}_{_sys_zeit_form_suffix}")
                        ez_gehen = c5.time_input("Gehen", zgehen, step=300, key=f"sys_zeit_gehen_{ziel_id}_{_sys_zeit_form_suffix}")
                        ez_pause = c6.number_input("Pause (Min.)", 0, 480, zpause, 5, key=f"sys_zeit_pause_{ziel_id}_{_sys_zeit_form_suffix}")
                        # Die gebuchte Kategorie muss wählbar bleiben, auch wenn sie
                        # zwischenzeitlich aus den Einstellungen entfernt wurde –
                        # sonst wird sie beim Speichern still überschrieben.
                        kat_aktuell = str(z["Kategorie"] or "").strip()
                        kat_optionen = list(dict.fromkeys(
                            [k for k in kategorien() if k] + ([kat_aktuell] if kat_aktuell else [])))
                        if not kat_optionen:
                            kat_optionen = [t("Arbeitszeit", "Working time")]
                        ez_kat = st.selectbox(
                            "Kategorie", kat_optionen,
                            index=kat_optionen.index(kat_aktuell) if kat_aktuell in kat_optionen else 0,
                            format_func=wert_label, key=f"sys_zeit_kat_{ziel_id}_{_sys_zeit_form_suffix}")
                        typ_aktuell = str(z["Typ"] or "").strip()
                        typ_optionen = list(dict.fromkeys(["Normal", "Korrigiert", "Nachtrag", "Import"] + ([typ_aktuell] if typ_aktuell else [])))
                        ez_typ = st.selectbox(
                            "Typ", typ_optionen,
                            index=typ_optionen.index(typ_aktuell) if typ_aktuell in typ_optionen else 0,
                            key=f"sys_zeit_typ_{ziel_id}_{_sys_zeit_form_suffix}")
                        ez_projekt = st.text_input(projekt_label(), str(z["Projekt"] or ""), key=f"sys_zeit_projekt_{ziel_id}_{_sys_zeit_form_suffix}") if B["projekt_aktiv"] else ""
                        ez_notiz = st.text_input("Notiz", str(z["Notiz"] or ""), key=f"sys_zeit_notiz_{ziel_id}_{_sys_zeit_form_suffix}")
                        speichern_zeit = st.form_submit_button("💾 Arbeitszeit ändern", use_container_width=True, type="primary")
                    if speichern_zeit:
                        try:
                            if ez_kommen is None or ez_gehen is None:
                                raise ValueError(t("Bitte Kommen- und Gehen-Zeit angeben.",
                                                   "Please provide start and end time."))
                            brutto, pause, netto = berechne_arbeitszeit(ez_kommen, ez_gehen, ez_pause)
                            maske = st.session_state.time_logs["ID"].astype(str) == ziel_id
                            st.session_state.time_logs.loc[maske, ["Mitarbeiter", "Datum", "Kommen", "Gehen", "Brutto (Std)", "Pause (Min)", "Netto (Std)", "Kategorie", "Projekt", "Notiz", "Typ", "Status"]] = [
                                ez_mitarbeiter, ez_datum, ez_kommen.strftime(ZEITFORMAT), ez_gehen.strftime(ZEITFORMAT),
                                brutto, pause, netto, ez_kat, ez_projekt.strip(), ez_notiz.strip(), ez_typ, ez_status]
                            speichern("time_logs")
                            melde("Arbeitszeit geändert.", "Working time updated.", "🛠️")
                            st.rerun()
                        except ValueError as fehler:
                            st.error(str(fehler))
                        except Exception as fehler:   # damit die Seite nicht abstürzt
                            protokolliere("Zeiteintrag konnte nicht geändert werden", fehler)
                            st.error(t(f"Der Eintrag konnte nicht gespeichert werden: {fehler}",
                                       f"The entry could not be saved: {fehler}"))
                    if st.checkbox("Diesen Zeiteintrag zur Löschung markieren", key=f"sys_zeit_delete_confirm_{ziel_id}"):
                        st.warning("Der Zeiteintrag wird dauerhaft gelöscht. Diese Aktion kann nicht rückgängig gemacht werden.")
                        c_del1, c_del2 = st.columns(2)
                        if c_del1.button("⚠️ Ja, endgültig löschen", key=f"sys_zeit_delete_{ziel_id}", use_container_width=True):
                            st.session_state.time_logs = st.session_state.time_logs[~(st.session_state.time_logs["ID"].astype(str) == ziel_id)].reset_index(drop=True)
                            speichern("time_logs")
                            melde("Zeiteintrag gelöscht.", "Working-time entry deleted.", "🗑️")
                            st.rerun()
                        if c_del2.button("Abbrechen", key=f"sys_zeit_delete_cancel_{ziel_id}", use_container_width=True):
                            st.session_state[f"sys_zeit_delete_confirm_{ziel_id}"] = False
                            st.rerun()

    # ---------------- Auswertung ----------------
    if tab_auswertung is not None:
      with tab_auswertung:
        if not kunden_projekte_aktiv():
            st.info(t("Die Kunden-/Projekt-Auswertung ist für Handwerk/Bau und Dienstleistung/Beratung vorgesehen. Wählen Sie diese Branche unter Einstellungen, um sie zu aktivieren.", "Customer/project analysis is intended for trades/construction and services/consulting. Select one of these industries under Settings to activate it."))
        else:
            st.markdown(f"### {t('Auswertung nach Kunde & Projekt', 'Customer & project analysis')}")
            heute_a = date.today()
            c1, c2 = st.columns(2)
            avon = c1.date_input(t("Von", "From"), heute_a.replace(day=1), format=DATUMSFORMAT_UI, key="aus_von")
            abis = c2.date_input(t("Bis", "To"), heute_a, format=DATUMSFORMAT_UI, key="aus_bis")
            if avon > abis:
                st.error(t("Von darf nicht nach Bis liegen.", "From cannot be after To."))
            else:
                kunden_df_a = aktive_kunden_df()
                kunden_ids_a = ["__ALLE__"] + (kunden_df_a["Kunden-ID"].astype(str).tolist() if not kunden_df_a.empty else [])
                aus_kunde = st.selectbox(t("Kunde", "Customer"), kunden_ids_a, format_func=lambda x: t("Alle Kunden", "All customers") if x == "__ALLE__" else kunden_label(x), key="aus_kunde")
                proj_df_a = aktive_projekte_df(aus_kunde)
                proj_ids_a = ["__ALLE__"] + (proj_df_a["Projekt-ID"].astype(str).tolist() if not proj_df_a.empty else [])
                aus_projekt = st.selectbox(t("Projekt", "Project"), proj_ids_a, format_func=lambda x: t("Alle Projekte", "All projects") if x == "__ALLE__" else projekt_label_id(x), key="aus_projekt")
                ma_ids_a = ["__ALLE__"] + [str(x) for x in aktive_mitarbeiter()]
                aus_ma = st.selectbox(t("Mitarbeiter", "Employee"), ma_ids_a, format_func=lambda x: t("Alle Mitarbeiter", "All employees") if x == "__ALLE__" else x, key="aus_ma")
                df_a = zeiten_von(None, avon, abis).copy()
                if "Kunde-ID" not in df_a.columns: df_a["Kunde-ID"] = ""
                if "Projekt-ID" not in df_a.columns: df_a["Projekt-ID"] = ""
                if aus_kunde != "__ALLE__": df_a = df_a[df_a["Kunde-ID"].astype(str) == aus_kunde]
                if aus_projekt != "__ALLE__": df_a = df_a[df_a["Projekt-ID"].astype(str) == aus_projekt]
                if aus_ma != "__ALLE__": df_a = df_a[df_a["Mitarbeiter"].astype(str) == aus_ma]
                df_a = zeit_mit_kunden_projekten(df_a)
                if df_a.empty:
                    st.info(t("Keine Zeiteinträge für die gewählten Filter.", "No time entries for the selected filters."))
                else:
                    stunden_a = pd.to_numeric(df_a["Netto (Std)"], errors="coerce").fillna(0)
                    k1,k2,k3 = st.columns(3)
                    k1.metric(t("Einträge", "Entries"), len(df_a))
                    k2.metric(t("Netto-Stunden", "Net hours"), f"{stunden_a.sum():.2f}")
                    k3.metric(t("Projekte", "Projects"), int(df_a["Projekt-ID"].astype(str).replace("", pd.NA).nunique(dropna=True)))
                    by_proj = (df_a.assign(_stunden=stunden_a).groupby(["Kunde", "Projekt"], dropna=False, as_index=False).agg(**{"Einträge": ("ID", "count"), "Netto-Stunden": ("_stunden", "sum")}))
                    by_proj["Netto-Stunden"] = by_proj["Netto-Stunden"].round(2)
                    st.markdown(f"#### {t('Stunden je Kunde / Projekt', 'Hours by customer / project')}")
                    st.dataframe(by_proj, use_container_width=True, hide_index=True)
                    by_ma = (df_a.assign(_stunden=stunden_a).groupby(["Mitarbeiter"], as_index=False).agg(**{"Einträge": ("ID", "count"), "Netto-Stunden": ("_stunden", "sum")}))
                    by_ma["Netto-Stunden"] = by_ma["Netto-Stunden"].round(2)
                    st.markdown(f"#### {t('Stunden je Mitarbeiter', 'Hours by employee')}")
                    st.dataframe(by_ma, use_container_width=True, hide_index=True)

                    # Detaillierte Zuordnung Mitarbeiter -> Kunde -> Projekt.
                    # Damit kann der Betrieb direkt sehen, wer wie viele Stunden
                    # auf welchem Projekt gebucht hat.
                    by_ma_proj = (
                        df_a.assign(_stunden=stunden_a)
                        .groupby(["Kunde", "Projekt", "Mitarbeiter"], dropna=False, as_index=False)
                        .agg(**{"Einträge": ("ID", "count"), "Netto-Stunden": ("_stunden", "sum")})
                    )
                    by_ma_proj["Netto-Stunden"] = by_ma_proj["Netto-Stunden"].round(2)
                    st.markdown(f"#### {t('Mitarbeiter je Kunde / Projekt', 'Employees by customer / project')}")
                    st.dataframe(by_ma_proj, use_container_width=True, hide_index=True)

                    # Kreuztabelle für einen schnellen Monats-/Zeitraumüberblick.
                    matrix = pd.pivot_table(
                        df_a.assign(_stunden=stunden_a),
                        index="Mitarbeiter", columns="Projekt", values="_stunden",
                        aggfunc="sum", fill_value=0
                    ).reset_index()
                    if not matrix.empty:
                        numeric_cols = [c for c in matrix.columns if c != "Mitarbeiter"]
                        matrix[numeric_cols] = matrix[numeric_cols].round(2)
                        st.markdown(f"#### {t('Übersicht Mitarbeiter × Projekt', 'Employee × project overview')}")
                        st.dataframe(matrix, use_container_width=True, hide_index=True)

                    export_a = df_a[[c for c in ["Mitarbeiter","Datum","Kommen","Gehen","Netto (Std)","Kunde","Projekt","Kategorie","Notiz","Status"] if c in df_a.columns]].copy()
                    puffer_a = io.BytesIO()
                    with pd.ExcelWriter(puffer_a, engine="openpyxl") as writer:
                        export_a.to_excel(writer, index=False, sheet_name="Zeiten")
                        by_proj.to_excel(writer, index=False, sheet_name="Kunde_Projekt")
                        by_ma.to_excel(writer, index=False, sheet_name="Mitarbeiter")
                        by_ma_proj.to_excel(writer, index=False, sheet_name="Mitarbeiter_Projekt")
                        matrix.to_excel(writer, index=False, sheet_name="Matrix")
                    # Drei Ausgabewege: Excel für die manuelle Weiterverarbeitung,
                    # CSV für Import-/Buchhaltungssysteme und ein API-kompatibles
                    # JSON-Format als stabile Grundlage für eine spätere REST-API.
                    st.markdown(f"#### {t('Export & Schnittstelle', 'Export & interface')}")
                    ex1, ex2, ex3 = st.columns(3)
                    with ex1:
                        st.download_button(
                            t("📥 Excel", "📥 Excel"),
                            data=puffer_a.getvalue(),
                            file_name=f"Auswertung_{avon:%Y%m%d}_{abis:%Y%m%d}.xlsx",
                            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                            use_container_width=True,
                            key="auswertung_excel_download",
                        )

                    # Semikolon + UTF-8-SIG ist für deutsche Excel-/ERP-Importe
                    # besonders praktisch (Umlaute und Dezimalwerte bleiben sauber).
                    csv_a = export_a.to_csv(index=False, sep=";", encoding="utf-8-sig").encode("utf-8-sig")
                    with ex2:
                        st.download_button(
                            t("📄 CSV", "📄 CSV"),
                            data=csv_a,
                            file_name=f"Auswertung_{avon:%Y%m%d}_{abis:%Y%m%d}.csv",
                            mime="text/csv",
                            use_container_width=True,
                            key="auswertung_csv_download",
                        )

                    # API-neutrales Austauschformat. Die Feldnamen sind bewusst
                    # maschinenlesbar und enthalten zusätzlich IDs, damit eine
                    # spätere FastAPI-Schnittstelle dieselbe Struktur liefern kann.
                    api_spalten = [c for c in [
                        "ID", "Mitarbeiter", "Datum", "Kommen", "Gehen",
                        "Pause (Min)", "Netto (Std)", "Kunde-ID", "Kunde",
                        "Projekt-ID", "Projekt", "Kategorie", "Notiz", "Status"
                    ] if c in df_a.columns]
                    api_df = df_a[api_spalten].copy()
                    for col in api_df.columns:
                        if col in DATUMSSPALTEN or col == "Datum":
                            api_df[col] = api_df[col].apply(
                                lambda v: v.isoformat() if hasattr(v, "isoformat") else ("" if pd.isna(v) else str(v))
                            )
                        elif pd.api.types.is_datetime64_any_dtype(api_df[col]):
                            api_df[col] = api_df[col].dt.strftime("%Y-%m-%dT%H:%M:%S").fillna("")
                    api_df = api_df.where(pd.notna(api_df), None)
                    api_payload = {
                        "api_version": "v1",
                        "von": avon.isoformat(),
                        "bis": abis.isoformat(),
                        "filter": {
                            "kunde_id": None if aus_kunde == "__ALLE__" else aus_kunde,
                            "projekt_id": None if aus_projekt == "__ALLE__" else aus_projekt,
                            "mitarbeiter": None if aus_ma == "__ALLE__" else aus_ma,
                        },
                        "anzahl": int(len(api_df)),
                        "gesamtstunden": round(float(stunden_a.sum()), 2),
                        "daten": api_df.to_dict(orient="records"),
                    }
                    import json as _json
                    api_json = _json.dumps(api_payload, ensure_ascii=False, indent=2, default=str).encode("utf-8")
                    with ex3:
                        st.download_button(
                            t("🔗 API / JSON", "🔗 API / JSON"),
                            data=api_json,
                            file_name=f"api_zeiten_{avon:%Y%m%d}_{abis:%Y%m%d}.json",
                            mime="application/json",
                            use_container_width=True,
                            key="auswertung_api_json_download",
                        )

                    with st.expander(t("🔗 API-Schnittstelle", "🔗 API interface")):
                        st.info(t(
                            "Der JSON-Export verwendet bereits das Datenformat der geplanten API. "
                            "Für eine echte automatische REST-Schnittstelle wird später ein separater, "
                            "abgesicherter API-Dienst (z. B. FastAPI) vor die Produktivdatenbank gesetzt. "
                            "Dadurch muss die Streamlit-Oberfläche nicht als API-Server verwendet werden.",
                            "The JSON export already uses the planned API data format. A separate secured "
                            "API service (for example FastAPI) can later expose the production database "
                            "without using the Streamlit UI as the API server."
                        ))
                        st.code(
                            "GET /api/v1/zeiten?von=YYYY-MM-DD&bis=YYYY-MM-DD&kunde_id=...&projekt_id=...",
                            language="text",
                        )
                        st.caption(t(
                            "Vorgesehen: Authentifizierung per API-Key, Mandantentrennung und dieselben Filter wie oben.",
                            "Planned: API-key authentication, tenant isolation and the same filters as above."
                        ))

    # ---------------- Anträge ----------------
    with tab_antraege:
        df_vac = st.session_state.vacation_requests
        offene = df_vac[df_vac["Status"] == "Ausstehend"] if not df_vac.empty else df_vac

        # ---------- Abwesenheitskalender ----------
        st.markdown(f"##### {t('Abwesenheitskalender', 'Absence calendar')}")
        kal1, kal2 = st.columns([1, 2])
        kal_von = kal1.date_input(t("Start", "Start"), date.today(), format=DATUMSFORMAT_UI,
                                  key="abwkal_von")
        kal_wochen = kal2.select_slider(
            t("Zeitraum", "Range"),
            options=[1, 2, 4, 8, 13, 26, 39, 52, 104],
            value=4,
            format_func=lambda w: (t("1 Woche", "1 week") if w == 1
                                   else t(f"{w} Wochen", f"{w} weeks")
                                   + (t(" (1 Jahr)", " (1 year)") if w == 52
                                      else t(" (2 Jahre)", " (2 years)") if w == 104
                                      else t(" (1/2 Jahr)", " (6 months)") if w == 26
                                      else t(" (1 Quartal)", " (1 quarter)") if w == 13
                                      else "")),
            key="abwkal_wochen")
        kal_bis = kal_von + timedelta(weeks=int(kal_wochen)) - timedelta(days=1)

        # Ab drei Monaten je Kalenderwoche zusammenfassen, sonst wird es unlesbar breit
        wochenansicht = int(kal_wochen) > 8
        if wochenansicht:
            wochenansicht = not st.toggle(
                t("Trotzdem Tag für Tag anzeigen", "Show day by day anyway"),
                value=False, key="abwkal_tage",
                help=t("Bei langen Zeiträumen sehr breit – waagerecht scrollbar.",
                       "Very wide for long ranges – scrolls horizontally."))

        st.caption(f"{kal_von.strftime(DATUMSFORMAT)} – {kal_bis.strftime(DATUMSFORMAT)}")

        kalender_df = abwesenheitskalender(kal_von, kal_bis, als_wochen=wochenansicht)
        if kalender_df.empty:
            st.info(t("Keine aktiven Mitarbeitenden vorhanden.", "No active employees."))
        else:
            st.dataframe(kalender_df, use_container_width=True, hide_index=True,
                         column_config={t("Mitarbeiter", "Employee"):
                                        st.column_config.TextColumn(pinned=True, width="medium")})
            if wochenansicht:
                st.caption(t("Je Kalenderwoche: 🟩 genehmigte / 🟨 offene Abwesenheitstage.",
                             "Per calendar week: 🟩 approved / 🟨 pending absence days."))
            else:
                st.caption(t("🟩 genehmigt · 🟨 beantragt · · Arbeitstag ohne Abwesenheit",
                             "🟩 approved · 🟨 requested · · working day without absence"))

            # Überschneidungen ausdrücklich benennen
            kollisionen = [
                (tag, namen) for tag, namen in logik.abwesenheits_ueberschneidungen(alle_abwesenheiten())
                if kal_von <= tag <= kal_bis
            ]
            if kollisionen:
                zeilen = [f"**{tag.strftime(DATUMSFORMAT)}**: {', '.join(namen)}"
                          for tag, namen in kollisionen[:15]]
                rest = len(kollisionen) - len(zeilen)
                text = t("⚠️ Mehrfache Abwesenheiten an diesen Tagen:\n\n",
                         "⚠️ Overlapping absences on these days:\n\n") + "\n\n".join(zeilen)
                if rest > 0:
                    text += t(f"\n\n… und {rest} weitere Tage.", f"\n\n… and {rest} more days.")
                st.warning(text)
            else:
                st.success(t("Keine Überschneidungen im gewählten Zeitraum.",
                             "No overlapping absences in the selected range."))

        # ---------- Abwesenheit für Mitarbeitende erfassen ----------
        with st.expander(t("➕ Abwesenheit für eine Mitarbeiterin / einen Mitarbeiter erfassen",
                           "➕ Record an absence for an employee")):
            st.caption(t("Direkt genehmigt eingetragen – gedacht für Krankmeldungen und "
                         "vereinbarte Abwesenheiten, die nicht beantragt werden.",
                         "Recorded as approved – intended for sick leave and agreed absences "
                         "that are not requested by the employee."))
            e1, e2 = st.columns(2)
            erf_person = e1.selectbox(t("Mitarbeiter", "Employee"), aktive_mitarbeiter(),
                                      key="erf_person") if aktive_mitarbeiter() else ""
            erf_art = e2.selectbox(t("Grund", "Reason"), [a[0] for a in abwesenheitsarten()],
                                   format_func=wert_label, key="erf_art")
            e3, e4 = st.columns(2)
            erf_von = e3.date_input(t("Von", "From"), date.today(), format=DATUMSFORMAT_UI,
                                    key="erf_von",
                                    on_change=_ende_nachziehen("erf_von", "erf_bis"))
            # Streamlit verlangt, dass der aktuelle Wert von `value` nicht
            # kleiner als `min_value` ist. Wenn "Von" z.B. auf 25.09.
            # geändert wurde, darf "Bis" nicht mehr mit date.today()
            # (19.09.) initialisiert werden.
            erf_von_aktuell = st.session_state.get("erf_von", date.today())
            if not isinstance(erf_von_aktuell, date):
                erf_von_aktuell = date.today()
            erf_bis_aktuell = st.session_state.get("erf_bis", date.today())
            if not isinstance(erf_bis_aktuell, date) or erf_bis_aktuell < erf_von_aktuell:
                erf_bis_aktuell = erf_von_aktuell
                st.session_state["erf_bis"] = erf_bis_aktuell
            erf_bis = e4.date_input(t("Bis", "To"), erf_bis_aktuell,
                                    min_value=erf_von_aktuell,
                                    format=DATUMSFORMAT_UI, key="erf_bis")
            erf_kommentar = st.text_input(t("Notiz (optional)", "Note (optional)"), key="erf_kommentar")
            erf_tage = arbeitstage_zwischen(erf_von, erf_bis)
            st.caption(t(f"= {erf_tage} Arbeitstage", f"= {erf_tage} working days"))

            if st.button(t("💾 Abwesenheit eintragen", "💾 Record absence"),
                         use_container_width=True, type="primary", key="erf_speichern"):
                if not erf_person:
                    st.error(t("Bitte eine Person auswählen.", "Please select a person."))
                elif erf_von > erf_bis:
                    st.error(t("Das Startdatum liegt nach dem Enddatum.",
                               "The start date is after the end date."))
                elif erf_tage == 0:
                    st.error(t("Der Zeitraum enthält keine Arbeitstage.",
                               "The period contains no working days."))
                else:
                    st.session_state.vacation_requests = zeile_anhaengen(
                        st.session_state.vacation_requests,
                        {"ID": neue_id(), "Mitarbeiter": erf_person, "Startdatum": erf_von,
                         "Enddatum": erf_bis, "Einheit": "Tage", "Tage": int(erf_tage),
                         "Stunden": 0.0, "Art": erf_art, "Kommentar": str(erf_kommentar).strip(),
                         "Status": "Genehmigt", "Eingereicht am": date.today(),
                         "Entscheidungsgrund": "", "Erfasst von": str(st.session_state.username)})
                    speichern("vacation_requests")
                    melde(f"{wert_label(erf_art)} für {erf_person} eingetragen.",
                          f"{wert_label(erf_art)} recorded for {erf_person}.", "💾")
                    st.rerun()

        st.markdown("---")
        st.markdown(f"##### {t('Offene Anträge', 'Pending requests')}")

        if offene.empty:
            st.success(t("Keine ausstehenden Anträge.", "No pending requests."))
        else:
            for idx, zeile in offene.iterrows():
                with st.container(border=True):
                    start, ende = zeile["Startdatum"], zeile["Enddatum"]
                    st.markdown(f"**{zeile['Mitarbeiter']}** · {wert_label(zeile['Art'])}")
                    if zeile["Einheit"] == "Stunden":
                        st.write(f"🕐 {start.strftime(DATUMSFORMAT) if isinstance(start, date) else start} · "
                                 f"{float(zeile['Stunden']):.1f} {t('Stunden', 'hours')}")
                    else:
                        st.write(f"📅 {start.strftime(DATUMSFORMAT) if isinstance(start, date) else start} – "
                                 f"{ende.strftime(DATUMSFORMAT) if isinstance(ende, date) else ende} "
                                 f"({zeile['Tage']} {t('Arbeitstage', 'working days')})")
                    if zeile.get("Kommentar"):
                        st.caption(f"{t('Kommentar', 'Comment')}: {zeile['Kommentar']}")

                    anspruch, genehmigt_tage, _, verfuegbar = get_urlaubs_konto(zeile["Mitarbeiter"])
                    st.caption(t(f"Urlaubskonto: {genehmigt_tage} von {anspruch} Tagen genehmigt, "
                                 f"{verfuegbar} noch verfügbar.",
                                 f"Leave account: {genehmigt_tage} of {anspruch} days approved, "
                                 f"{verfuegbar} still available."))
                    if zeile["Art"] == "Urlaub" and verfuegbar < 0:
                        st.warning(t("Der Anspruch wäre mit diesem Antrag überschritten.",
                                     "This request would exceed the entitlement."))

                    # Eine Ablehnung ohne Begründung führt beim Mitarbeiter unweigerlich
                    # zur Rückfrage – deshalb ist der Grund hier Pflicht und wird
                    # zusammen mit der Entscheidung gespeichert.
                    grund = st.text_input(
                        t("Grund (Pflicht bei Ablehnung)", "Reason (required for rejection)"),
                        key=f"grund_{zeile['ID']}",
                        placeholder=t("z. B. Besetzung in der Gruppe nicht gesichert",
                                      "e.g. staffing cannot be covered"))
                    c1, c2 = st.columns(2)
                    if c1.button(t("✅ Genehmigen", "✅ Approve"), key=f"gen_{zeile['ID']}",
                                 use_container_width=True):
                        st.session_state.vacation_requests.at[idx, "Status"] = "Genehmigt"
                        st.session_state.vacation_requests.at[idx, "Entscheidungsgrund"] = str(grund).strip()
                        speichern("vacation_requests")
                        melde(f"Antrag von {zeile['Mitarbeiter']} genehmigt.",
                              f"Request from {zeile['Mitarbeiter']} approved.", "✅")
                        st.rerun()
                    if c2.button(t("❌ Ablehnen", "❌ Reject"), key=f"abl_{zeile['ID']}",
                                 use_container_width=True):
                        if not str(grund).strip():
                            st.error(t("Bitte einen Grund für die Ablehnung angeben – "
                                       "der Mitarbeiter sieht ihn in seiner Übersicht.",
                                       "Please state a reason for the rejection – "
                                       "the employee will see it in their overview."))
                        else:
                            st.session_state.vacation_requests.at[idx, "Status"] = "Abgelehnt"
                            st.session_state.vacation_requests.at[idx, "Entscheidungsgrund"] = str(grund).strip()
                            speichern("vacation_requests")
                            melde(f"Antrag von {zeile['Mitarbeiter']} abgelehnt.",
                                  f"Request from {zeile['Mitarbeiter']} rejected.", "❌")
                            st.rerun()

        st.markdown("---")
        st.markdown(f"##### {t('Historie', 'History')}")
        historie = df_vac[df_vac["Status"] != "Ausstehend"] if not df_vac.empty else df_vac
        if historie.empty:
            st.caption(t("Noch keine bearbeiteten Anträge.", "No processed requests yet."))
        else:
            tabelle(historie.drop(columns=["ID"]))

        # Genehmigte Urlaube dürfen von Leitung/Admin und Systemadmin storniert werden.
        # Eine Stornierung ist kein "Abgelehnt": Der Antrag bleibt in der Historie
        # nachvollziehbar, zählt aber nicht mehr als genehmigte Abwesenheit.
        genehmigte = df_vac[df_vac["Status"] == "Genehmigt"].copy() if not df_vac.empty else df_vac
        if (systemadmin_vollzugriff or st.session_state.role == "Leitung / Admin") and not genehmigte.empty:
            st.markdown(f"##### {t('Genehmigte Urlaube stornieren', 'Cancel approved leave')}")
            optionen = {}
            for _, _v in genehmigte.iterrows():
                _start = _v["Startdatum"].strftime(DATUMSFORMAT) if isinstance(_v["Startdatum"], date) else str(_v["Startdatum"])
                _ende = _v["Enddatum"].strftime(DATUMSFORMAT) if isinstance(_v["Enddatum"], date) else str(_v["Enddatum"])
                _label = f"{_v['Mitarbeiter']} · {wert_label(_v['Art'])} · {_start} – {_ende} · {_v['ID']}"
                optionen[_label] = str(_v["ID"])
            _auswahl_label = st.selectbox(
                t("Urlaubsantrag auswählen", "Select leave request"),
                list(optionen.keys()), key="urlaub_storno_auswahl")
            _storno_id = optionen[_auswahl_label]
            _storno_zeile = genehmigte[genehmigte["ID"].astype(str) == _storno_id].iloc[0]
            _storno_key = "urlaub_storno_bestaetigt"
            if st.session_state.pop("_urlaub_storno_clear", False):
                st.session_state.pop(_storno_key, None)
            # Der Grund ist Pflicht: Eine Stornierung nimmt einen bereits zugesagten
            # Urlaub zurück – ohne Begründung führt das unweigerlich zur Rückfrage.
            _storno_grund = st.text_input(
                t("Grund für die Stornierung (Pflicht)", "Reason for cancellation (required)"),
                key=f"urlaub_storno_grund_{_storno_id}",
                placeholder=t("z. B. Krankheitsvertretung nötig", "e.g. sick cover required"))
            if st.checkbox(t("Ich möchte diesen genehmigten Urlaub stornieren",
                             "I want to cancel this approved leave"), key=_storno_key):
                st.warning(t(
                    f"Der genehmigte Urlaub von {_storno_zeile['Mitarbeiter']} wird auf 'Storniert' gesetzt. Die Urlaubstage werden wieder freigegeben.",
                    f"The approved leave of {_storno_zeile['Mitarbeiter']} will be marked as 'Cancelled'. The leave days will be released again."))
                if st.button(t("⚠️ Ja, Urlaub endgültig stornieren", "⚠️ Yes, cancel leave"),
                             key="urlaub_storno_final", use_container_width=True):
                    if not str(_storno_grund).strip():
                        st.error(t("Bitte einen Grund angeben – der Mitarbeiter sieht ihn in seiner Übersicht.",
                                   "Please state a reason – the employee will see it in their overview."))
                    else:
                        _maske_storno = st.session_state.vacation_requests["ID"].astype(str) == _storno_id
                        st.session_state.vacation_requests.loc[_maske_storno, "Status"] = "Storniert"
                        st.session_state.vacation_requests.loc[_maske_storno, "Entscheidungsgrund"] = str(_storno_grund).strip()
                        speichern("vacation_requests")
                        melde(f"Urlaub von {_storno_zeile['Mitarbeiter']} storniert.",
                              f"Leave of {_storno_zeile['Mitarbeiter']} cancelled.", "↩️")
                        st.session_state["_urlaub_storno_clear"] = True
                        st.rerun()

        if systemadmin_vollzugriff and not df_vac.empty:
            st.markdown("---")
            st.markdown("##### 🛠️ Systemadmin: Urlaubsanträge bearbeiten")
            st.caption("Klicke in der Tabelle auf einen Urlaubsantrag. Dieser wird automatisch in die Bearbeitungsmaske übernommen.")
            vac_tabelle = df_vac.copy()
            vac_anzeige = vac_tabelle.drop(columns=["ID"], errors="ignore")
            vac_event = st.dataframe(
                anzeige_df(vac_anzeige),
                use_container_width=True,
                hide_index=True,
                column_config=spalten_config(vac_anzeige),
                on_select="rerun",
                selection_mode="single-row",
                key="sys_vac_tabelle",
            )
            vac_rows = getattr(getattr(vac_event, "selection", None), "rows", []) or []
            if vac_rows:
                ausgewahlter_vac_id = str(vac_tabelle.iloc[vac_rows[0]]["ID"])
                # Die Widget-Schlüssel enthalten die Antrags-ID (siehe unten),
                # dadurch lädt jede neue Auswahl automatisch ihre eigenen Werte.
                if st.session_state.get("sys_vac_id") != ausgewahlter_vac_id:
                    st.session_state["sys_vac_id"] = ausgewahlter_vac_id
                    _felder_anderer_auswahl_verwerfen(
                        "sys_vac_", ausgewahlter_vac_id,
                        ("ma", "status", "einheit", "start", "ende", "tage",
                         "stunden", "art", "kom", "delete_confirm"))
            vac_id = st.session_state.get("sys_vac_id")
            if not vac_id or not (df_vac["ID"].astype(str) == str(vac_id)).any():
                st.info("Bitte oben einen Urlaubsantrag anklicken.")
                vac_id = None
            if vac_id:
                vidx = df_vac.index[df_vac["ID"].astype(str) == str(vac_id)][0]
                v = df_vac.loc[vidx]
                vstart = v["Startdatum"] if isinstance(v["Startdatum"], date) else pd.to_datetime(v["Startdatum"]).date()
                vende = v["Enddatum"] if isinstance(v["Enddatum"], date) else pd.to_datetime(v["Enddatum"]).date()
                with st.form(f"sys_vac_bearbeiten_{vac_id}"):
                    vc1, vc2, vc3 = st.columns(3)
                    vma = vc1.selectbox("Mitarbeiter", aktive_mitarbeiter(), index=(aktive_mitarbeiter().index(v["Mitarbeiter"]) if v["Mitarbeiter"] in aktive_mitarbeiter() else 0), key=f"sys_vac_ma_{vac_id}")
                    vstatus_opts = ["Ausstehend", "Genehmigt", "Abgelehnt", "Storniert"]
                    vstatus = vc2.selectbox("Status", vstatus_opts, index=(vstatus_opts.index(str(v["Status"])) if str(v["Status"]) in vstatus_opts else 0), key=f"sys_vac_status_{vac_id}")
                    vunits = ["Tage", "Stunden"]
                    veinh = vc3.selectbox("Einheit", vunits, index=(vunits.index(str(v["Einheit"])) if str(v["Einheit"]) in vunits else 0), key=f"sys_vac_einheit_{vac_id}")
                    vc4, vc5 = st.columns(2)
                    vs = vc4.date_input("Startdatum", vstart, format=DATUMSFORMAT_UI, key=f"sys_vac_start_{vac_id}")
                    ve = vc5.date_input("Enddatum", vende, format=DATUMSFORMAT_UI, key=f"sys_vac_ende_{vac_id}")
                    vc6, vc7 = st.columns(2)
                    vt = vc6.number_input("Tage", 0, 366, int(v["Tage"] or 0), 1, key=f"sys_vac_tage_{vac_id}")
                    vh = vc7.number_input("Stunden", 0.0, 8760.0, float(v["Stunden"] or 0), 0.5, key=f"sys_vac_stunden_{vac_id}")
                    varts = [a[0] for a in ABWESENHEITSARTEN if veinh == "Tage" or a[2]]
                    vart = st.selectbox("Grund", varts, index=(varts.index(str(v["Art"])) if str(v["Art"]) in varts else 0), format_func=wert_label, key=f"sys_vac_art_{vac_id}")
                    vkom = st.text_input("Kommentar", str(v["Kommentar"] or ""), key=f"sys_vac_kom_{vac_id}")
                    speichern_vac = st.form_submit_button("💾 Urlaubsantrag ändern", use_container_width=True, type="primary")
                if speichern_vac:
                    if ve < vs:
                        st.error("Das Enddatum darf nicht vor dem Startdatum liegen.")
                    else:
                        maske = st.session_state.vacation_requests["ID"].astype(str) == vac_id
                        st.session_state.vacation_requests.loc[maske, ["Mitarbeiter", "Startdatum", "Enddatum", "Einheit", "Tage", "Stunden", "Art", "Kommentar", "Status"]] = [
                            vma, vs, ve, veinh, int(vt) if veinh == "Tage" else 0, float(vh) if veinh == "Stunden" else 0.0, vart, vkom.strip(), vstatus]
                        speichern("vacation_requests")
                        melde("Urlaubsantrag geändert.", "Leave request updated.", "🛠️")
                        st.rerun()
                if st.checkbox("Diesen Urlaubsantrag zur Löschung markieren", key=f"sys_vac_delete_confirm_{vac_id}"):
                    st.warning("Der Urlaubsantrag wird dauerhaft gelöscht. Diese Aktion kann nicht rückgängig gemacht werden.")
                    c_del1, c_del2 = st.columns(2)
                    if c_del1.button("⚠️ Ja, endgültig löschen", key=f"sys_vac_delete_{vac_id}", use_container_width=True):
                        st.session_state.vacation_requests = st.session_state.vacation_requests[~(st.session_state.vacation_requests["ID"].astype(str) == vac_id)].reset_index(drop=True)
                        speichern("vacation_requests")
                        melde("Urlaubsantrag gelöscht.", "Leave request deleted.", "🗑️")
                        st.rerun()
                    if c_del2.button("Abbrechen", key=f"sys_vac_delete_cancel_{vac_id}", use_container_width=True):
                        st.session_state[f"sys_vac_delete_confirm_{vac_id}"] = False
                        st.rerun()

    # ---------------- Stammdaten ----------------
    with tab_stamm:
        st.markdown(f"##### {t('Mitarbeitende bearbeiten', 'Edit employees')}")
        st.caption(t("Namen können jederzeit korrigiert werden – die Zuordnung zum Benutzerkonto hängt "
                     "an der MA-ID. Erfasste Zeiten und Anträge werden mitgeändert.",
                     "Names can be corrected at any time – the link to the user account uses the "
                     "employee ID. Recorded times and requests are updated accordingly."))

        personalnr_frei = st.toggle(
            t("🔓 Personalnummern bearbeiten", "🔓 Edit staff numbers"), value=False,
            help=t("Personalnummern sind nach der Anlage gesperrt und können nur bewusst von der "
                   "Leitung geändert werden.",
                   "Staff numbers are locked after creation and can only be changed deliberately "
                   "by management."),
        )

        stamm_anzeige = st.session_state.mitarbeiter_stammdaten.copy()
        for spalte in ("MA-ID", "Mitarbeiter", "Personalnummer"):
            stamm_anzeige[spalte] = stamm_anzeige[spalte].astype(str).replace({"nan": "", "<NA>": ""})
        for spalte in ("Wochenstunden", "Urlaub_Pro_Jahr", "Resturlaub_Vorjahr", "Nachtrag_Std_Limit"):
            stamm_anzeige[spalte] = pd.to_numeric(stamm_anzeige[spalte], errors="coerce")
        stamm_anzeige["Aktiv"] = stamm_anzeige["Aktiv"].fillna(True).astype(bool)
        konten_je_id = (
            st.session_state.benutzer.groupby(st.session_state.benutzer["MA-ID"].astype(str))["Benutzername"]
            .apply(lambda s: ", ".join(s.astype(str))).to_dict()
        )
        stamm_anzeige["Login"] = stamm_anzeige["MA-ID"].astype(str).map(konten_je_id).fillna(
            t("— kein Konto —", "— no account —"))

        bearbeitet = st.data_editor(
            stamm_anzeige, use_container_width=True, hide_index=True, num_rows="dynamic",
            column_config={
                "MA-ID": st.column_config.TextColumn(spalten_label("MA-ID"), disabled=True),
                "Mitarbeiter": st.column_config.TextColumn(spalten_label("Mitarbeiter"), required=True),
                "Personalnummer": st.column_config.TextColumn(
                    spalten_label("Personalnummer"), disabled=not personalnr_frei,
                    help=t("Zum Ändern oben entsperren.", "Unlock above to edit.")),
                "Wochenstunden": st.column_config.NumberColumn(
                    spalten_label("Wochenstunden"), disabled=True, format="%.2f",
                    help=t("Ergibt sich aus dem Wochenarbeitszeitkalender weiter unten.",
                           "Derived from the weekly working-time calendar below.")),
                "Urlaub_Pro_Jahr": st.column_config.NumberColumn(
                    spalten_label("Urlaub_Pro_Jahr"), min_value=0, max_value=60),
                "Resturlaub_Vorjahr": st.column_config.NumberColumn(
                    spalten_label("Resturlaub_Vorjahr"), min_value=0, max_value=60),
                "Nachtrag_Std_Limit": st.column_config.NumberColumn(
                    spalten_label("Nachtrag_Std_Limit"), min_value=1.0, max_value=8760.0, step=1.0,
                    help=t(f"Wie weit darf diese Person Zeiten rückwirkend ändern? "
                           f"Vorgabe: {STANDARD_NACHTRAGSLIMIT:.0f} Std., für Leitung/Admin unbegrenzt.",
                           f"How far back may this person edit times? "
                           f"Default: {STANDARD_NACHTRAGSLIMIT:.0f} h.")),
                "Aktiv": st.column_config.CheckboxColumn(spalten_label("Aktiv")),
                "Login": st.column_config.TextColumn(spalten_label("Login"), disabled=True),
            },
            key="stamm_editor",
        )

        if st.button(t("💾 Stammdaten speichern", "💾 Save employees"),
                     use_container_width=True, type="primary"):
            bereinigt = bearbeitet.drop(columns=["Login"], errors="ignore").copy()
            bereinigt = bereinigt.dropna(subset=["Mitarbeiter"])
            bereinigt["Mitarbeiter"] = bereinigt["Mitarbeiter"].astype(str).str.strip()
            bereinigt["Personalnummer"] = (
                bereinigt["Personalnummer"].astype(str).replace({"nan": "", "<NA>": ""}).str.strip())
            bereinigt = bereinigt[bereinigt["Mitarbeiter"] != ""]

            fehlend = bereinigt["MA-ID"].isna() | bereinigt["MA-ID"].astype(str).str.strip().isin(
                ["", "nan", "<NA>"])
            bereinigt.loc[fehlend, "MA-ID"] = [f"ma-{uuid.uuid4().hex[:6]}" for _ in range(int(fehlend.sum()))]

            if bereinigt["Mitarbeiter"].duplicated().any():
                st.error(t("Es gibt doppelte Namen – bitte eindeutig benennen.",
                           "There are duplicate names – please make them unique."))
            else:
                # Wochenstunden kommen ausschließlich aus dem Wochenplan. Liegt für eine
                # Person noch keiner vor, bleibt der bisherige Wert stehen.
                bereinigt["Wochenstunden"] = pd.to_numeric(
                    bereinigt["Wochenstunden"], errors="coerce").fillna(B["wochenstunden"])
                for pos, ma_id in bereinigt["MA-ID"].astype(str).items():
                    aus_plan = wochensoll_aus_kalender(ma_id)
                    if aus_plan is not None:
                        bereinigt.at[pos, "Wochenstunden"] = aus_plan
                for spalte in ("Urlaub_Pro_Jahr", "Resturlaub_Vorjahr"):
                    bereinigt[spalte] = pd.to_numeric(bereinigt[spalte], errors="coerce").fillna(0).astype(int)
                bereinigt["Nachtrag_Std_Limit"] = pd.to_numeric(
                    bereinigt["Nachtrag_Std_Limit"], errors="coerce"
                ).fillna(STANDARD_NACHTRAGSLIMIT).clip(lower=1.0)
                bereinigt["Aktiv"] = bereinigt["Aktiv"].fillna(True).astype(bool)

                vorher = dict(zip(
                    st.session_state.mitarbeiter_stammdaten["MA-ID"].astype(str),
                    st.session_state.mitarbeiter_stammdaten["Mitarbeiter"].astype(str)))
                st.session_state.mitarbeiter_stammdaten = bereinigt[SPALTEN_STAMM].reset_index(drop=True)

                umbenannt = 0
                for _, person in st.session_state.mitarbeiter_stammdaten.iterrows():
                    alter_name = vorher.get(str(person["MA-ID"]))
                    neuer_name = str(person["Mitarbeiter"])
                    if alter_name and alter_name != neuer_name:
                        person_umbenennen(alter_name, neuer_name)
                        umbenannt += 1

                speichern("mitarbeiter_stammdaten")
                if umbenannt:
                    melde(f"Stammdaten gespeichert · {umbenannt} Umbenennung(en) übernommen.",
                          f"Employees saved · {umbenannt} rename(s) applied.", "💾")
                else:
                    melde("Stammdaten erfolgreich gespeichert.", "Employees saved successfully.", "💾")
                st.rerun()

        st.caption(t("Statt Löschen empfiehlt sich das Häkchen „Aktiv“ zu entfernen – so bleiben "
                     "erfasste Zeiten erhalten. Logins werden im Tab „Benutzerkonten“ vergeben.",
                     "Instead of deleting, clear the “Active” checkbox – recorded times are then kept. "
                     "Logins are created in the “User accounts” tab."))

        st.markdown("---")
        st.markdown(f"##### {t('Wochenarbeitszeitkalender', 'Weekly working-time calendar')}")
        st.caption(t(
            "Wiederkehrender Wochenplan je Person. Trage Beginn, Ende und Pause ein – "
            "die Sollstunden berechnet die App daraus automatisch. Freie Tage einfach abwählen.",
            "Recurring weekly schedule per person. Enter start, end and break – target hours "
            "are calculated automatically. Simply untick days off."))
        kalender_ma = st.selectbox(
            t("Mitarbeiter", "Employee"),
            st.session_state.mitarbeiter_stammdaten["Mitarbeiter"].astype(str).tolist()
            if not st.session_state.mitarbeiter_stammdaten.empty else [],
            key="kalender_ma")

        if kalender_ma:
            kalender_person = stammdaten_zeile(kalender_ma)
            kalender_id = str(kalender_person["MA-ID"]) if kalender_person is not None else ""
            namen_tage = WOCHENTAGE[st.session_state.sprache]
            bestehend = st.session_state.arbeitszeitkalender
            zeilen = []
            for idx, tagname in enumerate(namen_tage):
                treffer = bestehend[
                    (bestehend["MA-ID"].astype(str) == kalender_id)
                    & (pd.to_numeric(bestehend["Wochentag"], errors="coerce") == idx)
                ] if not bestehend.empty else pd.DataFrame()
                if treffer.empty:
                    zeilen.append({"Tag": tagname, "Arbeitstag": idx < 5, "Von": "08:00",
                                   "Bis": "16:30", "Pause_Min": 30})
                else:
                    z = treffer.iloc[0]
                    zeilen.append({
                        "Tag": tagname,
                        "Arbeitstag": bool(z.get("Arbeitstag", False)),
                        "Von": str(z.get("Von") or "08:00"),
                        "Bis": str(z.get("Bis") or "16:30"),
                        "Pause_Min": int(pd.to_numeric(z.get("Pause_Min"), errors="coerce") or 0),
                    })
            kalender_editor = pd.DataFrame(zeilen)
            # Sollstunden werden immer gerechnet, nie eingetippt
            kalender_editor["Soll_Std"] = [
                wochenplan_soll(r["Arbeitstag"], r["Von"], r["Bis"], r["Pause_Min"])
                for _, r in kalender_editor.iterrows()
            ]

            # Sollstunden stehen als gesperrte Spalte IM Editor. Damit sie nach einer
            # Änderung sofort stimmen, werden die noch nicht gespeicherten Eingaben aus
            # dem Widget-Zustand übernommen, bevor gerechnet wird. Streamlit löst bei
            # jeder Zelländerung ohnehin einen neuen Durchlauf aus.
            editor_key = f"arbeitszeitkalender_editor_{kalender_id}"
            draft_key = f"arbeitszeitkalender_draft_{kalender_id}"

            # WICHTIG: st.data_editor gibt geänderte Zellen über den Widget-State zurück.
            # Wenn bei jedem Streamlit-Rerun wieder ein neu aufgebautes DataFrame übergeben
            # wird, können Eingaben (insbesondere bei Enter) scheinbar auf den alten Wert
            # zurückspringen. Deshalb halten wir für jeden Mitarbeiter einen eigenen Entwurf
            # in session_state und übernehmen jede Änderung sofort dorthin.
            if draft_key not in st.session_state:
                st.session_state[draft_key] = kalender_editor.copy()

            def _kalender_editor_aenderung():
                state = st.session_state.get(editor_key, {})
                edits = state.get("edited_rows", {}) if isinstance(state, dict) else {}
                draft = st.session_state.get(draft_key)
                if draft is None:
                    return
                draft = draft.copy()
                for zeilen_nr, aenderungen in edits.items():
                    try:
                        pos = int(zeilen_nr)
                    except (TypeError, ValueError):
                        continue
                    if 0 <= pos < len(draft):
                        for spalte, wert in aenderungen.items():
                            if spalte in draft.columns:
                                draft.at[pos, spalte] = wert
                st.session_state[draft_key] = draft

            kalender_editor = st.session_state[draft_key].copy()
            kalender_editor["Soll_Std"] = [
                wochenplan_soll(r["Arbeitstag"], r["Von"], r["Bis"], r["Pause_Min"])
                for _, r in kalender_editor.iterrows()
            ]
            st.session_state[draft_key] = kalender_editor.copy()

            bearb_kalender = st.data_editor(
                kalender_editor[["Tag", "Arbeitstag", "Von", "Bis", "Pause_Min", "Soll_Std"]],
                use_container_width=True, hide_index=True, num_rows="fixed", key=editor_key,
                on_change=_kalender_editor_aenderung,
                column_config={
                    "Tag": st.column_config.TextColumn(t("Wochentag", "Weekday"), disabled=True),
                    "Arbeitstag": st.column_config.CheckboxColumn(t("Arbeitstag", "Working day")),
                    "Von": st.column_config.TextColumn(
                        t("Von", "Start"), validate=r"^([01]?\d|2[0-3]):[0-5]\d$", help="HH:MM"),
                    "Bis": st.column_config.TextColumn(
                        t("Bis", "End"), validate=r"^([01]?\d|2[0-3]):[0-5]\d$", help="HH:MM"),
                    "Pause_Min": st.column_config.NumberColumn(
                        t("Pause (Min)", "Break (min)"), min_value=0, max_value=300, step=5, format="%d"),
                    "Soll_Std": st.column_config.NumberColumn(
                        t("Soll (Std)", "Target (h)"), disabled=True, format="%.2f",
                        help=t("Wird automatisch aus Von, Bis und Pause berechnet.",
                               "Calculated automatically from start, end and break.")),
                })

            # Die aktuelle Widget-Ausgabe ist maßgeblich; anschließend wird der Entwurf
            # erneut als persistenter Session-State gespeichert.
            bearb_kalender = bearb_kalender.copy()
            bearb_kalender["Soll_Std"] = [
                wochenplan_soll(r["Arbeitstag"], r["Von"], r["Bis"], r["Pause_Min"])
                for _, r in bearb_kalender.iterrows()
            ]
            st.session_state[draft_key] = bearb_kalender.copy()

            # Nach dem Editor erneut rechnen, damit die Wochensumme zur Eingabe passt
            bearb_kalender = bearb_kalender.copy()
            bearb_kalender["Soll_Std"] = [
                wochenplan_soll(r["Arbeitstag"], r["Von"], r["Bis"], r["Pause_Min"])
                for _, r in bearb_kalender.iterrows()
            ]

            wochensumme = float(pd.to_numeric(bearb_kalender["Soll_Std"], errors="coerce").fillna(0).sum())
            hinterlegt = float(kalender_person["Wochenstunden"]) if kalender_person is not None else 0.0
            k1, k2 = st.columns(2)
            k1.metric(t("Wochensoll laut Plan", "Weekly target from plan"), f"{wochensumme:.2f} h")
            k2.metric(t("In Stammdaten hinterlegt", "Stored in employee record"), f"{hinterlegt:.2f} h")
            if abs(wochensumme - hinterlegt) > 0.01:
                st.warning(t(
                    f"Der Wochenplan ergibt {wochensumme:.2f} Std., in den Stammdaten stehen "
                    f"{hinterlegt:.2f} Std. Beim Speichern werden die Stammdaten angeglichen.",
                    f"The weekly plan totals {wochensumme:.2f} h, the employee record says "
                    f"{hinterlegt:.2f} h. Saving will align the employee record."))

            if st.button(t("💾 Wochenplan speichern", "💾 Save weekly plan"),
                         use_container_width=True, type="primary",
                         key=f"kalender_speichern_{kalender_id}"):
                neu_zeilen, fehler = [], []
                for idx, row in bearb_kalender.iterrows():
                    arbeitstag = bool(row["Arbeitstag"])
                    von = str(row["Von"] or "").strip()
                    bis = str(row["Bis"] or "").strip()
                    pause = int(pd.to_numeric(row["Pause_Min"], errors="coerce") or 0)
                    if arbeitstag and (parse_zeit(von) is None or parse_zeit(bis) is None):
                        fehler.append(t(f"{namen_tage[int(idx)]}: Bitte Von und Bis im Format HH:MM angeben.",
                                        f"{namen_tage[int(idx)]}: Please enter start and end as HH:MM."))
                        continue
                    soll = wochenplan_soll(arbeitstag, von, bis, pause)
                    if arbeitstag and soll <= 0:
                        fehler.append(t(f"{namen_tage[int(idx)]}: Die Arbeitszeit ergibt 0 Stunden.",
                                        f"{namen_tage[int(idx)]}: The working time adds up to 0 hours."))
                        continue
                    neu_zeilen.append({
                        "KAL-ID": f"{kalender_id}-{int(idx)}",
                        "MA-ID": kalender_id, "Wochentag": int(idx), "Arbeitstag": arbeitstag,
                        "Von": von if arbeitstag else "", "Bis": bis if arbeitstag else "",
                        "Pause_Min": pause if arbeitstag else 0,
                        "Soll_Std": soll,
                    })

                if fehler:
                    for text in dict.fromkeys(fehler):
                        st.error(text)
                elif len(neu_zeilen) == 7:
                    alt = st.session_state.arbeitszeitkalender
                    rest = alt[alt["MA-ID"].astype(str) != kalender_id].copy() if not alt.empty else alt
                    st.session_state.arbeitszeitkalender = pd.concat(
                        [rest, pd.DataFrame(neu_zeilen, columns=SPALTEN_ARBEITSZEITKALENDER)],
                        ignore_index=True)
                    speichern("arbeitszeitkalender")

                    # Wochenstunden in den Stammdaten an den Plan angleichen
                    summe = round(sum(z["Soll_Std"] for z in neu_zeilen), 2)
                    stamm = st.session_state.mitarbeiter_stammdaten
                    stamm.loc[stamm["MA-ID"].astype(str) == kalender_id, "Wochenstunden"] = summe
                    st.session_state.mitarbeiter_stammdaten = stamm
                    speichern("mitarbeiter_stammdaten")

                    melde(f"Wochenplan gespeichert – Wochensoll {summe:.2f} Std.",
                          f"Weekly plan saved – weekly target {summe:.2f} h", "💾")
                    st.rerun()

        if systemadmin_vollzugriff and not st.session_state.mitarbeiter_stammdaten.empty:
            st.markdown("---")
            st.markdown("##### 🛠️ Systemadmin: Mitarbeiter endgültig löschen")
            personen = st.session_state.mitarbeiter_stammdaten[["MA-ID", "Mitarbeiter"]].copy()
            personen["Label"] = personen["Mitarbeiter"].astype(str) + " · " + personen["MA-ID"].astype(str)
            person_id = st.selectbox("Mitarbeiter auswählen", personen["MA-ID"].astype(str).tolist(), format_func=lambda x: personen.loc[personen["MA-ID"].astype(str) == x, "Label"].iloc[0], key="sys_ma_delete")
            person_name = id_zu_name(person_id)
            st.warning(f"Beim Löschen von **{person_name}** werden der Mitarbeiterdatensatz, verknüpfte Benutzerkonten, Arbeitszeiten und Urlaubsanträge entfernt.")
            ma_del_runde = st.session_state.get("_sys_ma_del_runde", 0)
            if st.checkbox("Ich möchte diesen Mitarbeiter zur endgültigen Löschung markieren",
                           key=f"sys_ma_delete_confirm_{ma_del_runde}"):
                st.warning(f"ACHTUNG: **{person_name}** sowie das verknüpfte Konto, Arbeitszeiten und Urlaubsanträge werden dauerhaft gelöscht.")
                c_del1, c_del2 = st.columns(2)
                if c_del1.button("⚠️ Ja, endgültig löschen", key="sys_ma_delete_btn", use_container_width=True):
                    st.session_state.mitarbeiter_stammdaten = st.session_state.mitarbeiter_stammdaten[st.session_state.mitarbeiter_stammdaten["MA-ID"].astype(str) != person_id].reset_index(drop=True)
                    st.session_state.benutzer = st.session_state.benutzer[st.session_state.benutzer["MA-ID"].astype(str) != person_id].reset_index(drop=True)
                    st.session_state.time_logs = st.session_state.time_logs[st.session_state.time_logs["Mitarbeiter"].astype(str) != person_name].reset_index(drop=True)
                    st.session_state.vacation_requests = st.session_state.vacation_requests[st.session_state.vacation_requests["Mitarbeiter"].astype(str) != person_name].reset_index(drop=True)
                    speichern("mitarbeiter_stammdaten")
                    speichern("benutzer")
                    speichern("time_logs")
                    speichern("vacation_requests")
                    if str(st.session_state.get("ma_id") or "") == person_id:
                        st.session_state.update(logged_in=False, role=None, user=None, username=None, ma_id=None, passwort_wechseln=False)
                    melde(f"Mitarbeiter „{person_name}“ und zugehörige Daten gelöscht.", "Employee and linked data deleted.", "🗑️")
                    st.rerun()
                if c_del2.button("Abbrechen", key="sys_ma_delete_cancel", use_container_width=True):
                    st.session_state["_sys_ma_del_runde"] = ma_del_runde + 1
                    melde("Löschen abgebrochen.", "Deletion cancelled.", "↩️")
                    st.rerun()

    # ---------------- Kunden ----------------
    if tab_kunden_verwaltung is not None:
      with tab_kunden_verwaltung:
        if not kunden_projekte_aktiv():
            st.info(t("Das Kundenmodul wird für Handwerk/Bau und Dienstleistung/Beratung angezeigt.", "The customer module is shown for trades/construction and services/consulting."))
        else:
            st.markdown(f"### {t('Kundenverwaltung', 'Customer management')}")
            # Robuster Formular-Reset: Nach erfolgreicher Anlage wird die Widget-Version erhöht.
            # Dadurch erzeugt Streamlit beim nächsten Lauf neue Widgets mit leeren Standardwerten.
            _kunde_form_version = int(st.session_state.get("_kunde_form_version", 0))
            with st.expander(t("➕ Neuen Kunden anlegen", "➕ Add customer"), expanded=False):
                c1,c2,c3 = st.columns(3)
                knr = c1.text_input(t("Kundennummer", "Customer no."), key=f"neu_kundennr_{_kunde_form_version}")
                kn = c2.text_input(t("Kunde / Firma", "Customer / company"), key=f"neu_kunde_{_kunde_form_version}")
                ap = c3.text_input(t("Ansprechpartner", "Contact person"), key=f"neu_kunden_ap_{_kunde_form_version}")
                c1,c2,c3 = st.columns(3)
                tel = c1.text_input(t("Telefon", "Phone"), key=f"neu_kunden_tel_{_kunde_form_version}")
                email = c2.text_input(t("E-Mail", "Email"), key=f"neu_kunden_email_{_kunde_form_version}")
                ort = c3.text_input(t("Ort", "City"), key=f"neu_kunden_ort_{_kunde_form_version}")
                strasse = st.text_input(t("Straße", "Street"), key=f"neu_kunden_strasse_{_kunde_form_version}")
                notiz = st.text_input(t("Notiz", "Note"), key=f"neu_kunden_notiz_{_kunde_form_version}")
                if st.button(t("💾 Kunde anlegen", "💾 Add customer"), key="kunde_anlegen", type="primary"):
                    nr = knr.strip() or f"K-{len(st.session_state.kunden)+1:04d}"
                    if not kn.strip(): st.error(t("Bitte einen Kundennamen eingeben.", "Please enter a customer name."))
                    elif not eindeutige_nummer_pruefen(st.session_state.kunden, "Kundennummer", nr):
                        st.error(t(f"Die Kundennummer „{nr}“ ist bereits vergeben. Bitte eine andere Kundennummer verwenden.",
                                    f"Customer number “{nr}” is already in use. Please use another customer number."))
                    else:
                        st.session_state.kunden = zeile_anhaengen(st.session_state.kunden, {"Kunden-ID": neue_id(), "Kundennummer": nr, "Kunde": kn.strip(), "Ansprechpartner": ap.strip(), "Telefon": tel.strip(), "E-Mail": email.strip(), "Straße": strasse.strip(), "PLZ": "", "Ort": ort.strip(), "Aktiv": True, "Notiz": notiz.strip()})
                        speichern("kunden")
                        st.session_state["_kunde_form_version"] = _kunde_form_version + 1
                        melde(f"Kunde „{kn.strip()}“ angelegt.", "Customer created.", "👤"); st.rerun()
            if st.session_state.kunden.empty:
                st.info(t("Noch keine Kunden angelegt.", "No customers yet."))
            else:
                kunden_edit = st.session_state.kunden.copy(); kunden_edit["Löschen"] = False
                edited_k = st.data_editor(kunden_edit, use_container_width=True, hide_index=True, num_rows="fixed", key="kunden_editor", column_config={"Kunden-ID": st.column_config.TextColumn("ID", disabled=True), "Aktiv": st.column_config.CheckboxColumn("Aktiv"), "Löschen": st.column_config.CheckboxColumn("Löschen")})
                if st.button(t("💾 Kundenänderungen speichern", "💾 Save customer changes"), key="kunden_speichern", type="primary"):
                    doppelte_k = doppelte_nummern(edited_k, "Kundennummer")
                    if doppelte_k:
                        st.error(t(f"Kundennummern dürfen nicht doppelt vergeben werden: {', '.join(doppelte_k)}",
                                   f"Customer numbers must be unique: {', '.join(doppelte_k)}"))
                    elif bool(edited_k["Löschen"].fillna(False).any()):
                        ids = set(edited_k.loc[edited_k["Löschen"].fillna(False), "Kunden-ID"].astype(str))
                        linked = not st.session_state.projekte.empty and st.session_state.projekte["Kunden-ID"].astype(str).isin(ids).any()
                        if linked: st.error(t("Kunden mit verknüpften Projekten können nicht gelöscht werden. Setze sie auf Inaktiv.", "Customers with linked projects cannot be deleted. Set them inactive."))
                        else:
                            edited_k = edited_k[~edited_k["Löschen"].fillna(False)].copy().drop(columns=["Löschen"])
                            st.session_state.kunden = edited_k.reset_index(drop=True); speichern("kunden"); st.rerun()
                    else:
                        st.session_state.kunden = edited_k.drop(columns=["Löschen"]).reset_index(drop=True); speichern("kunden"); st.rerun()

    # ---------------- Projekte ----------------
    if tab_projekte is not None:
      with tab_projekte:
        if not kunden_projekte_aktiv():
            st.info(t("Das Projektmodul wird für Handwerk/Bau und Dienstleistung/Beratung angezeigt.", "The project module is shown for trades/construction and services/consulting."))
        else:
            st.markdown(f"### {t('Projektverwaltung', 'Project management')}")
            _projekt_form_version = int(st.session_state.get("_projekt_form_version", 0))
            with st.expander(t("➕ Neues Projekt anlegen", "➕ Add project"), expanded=False):
                c1,c2,c3 = st.columns(3)
                pnr = c1.text_input(t("Projektnummer", "Project no."), key=f"neu_projektnr_{_projekt_form_version}")
                pname = c2.text_input(t("Projektname", "Project name"), key=f"neu_projektname_{_projekt_form_version}")
                kdf = aktive_kunden_df(); kop = kdf["Kunden-ID"].astype(str).tolist() if not kdf.empty else []
                pkunde = c3.selectbox(t("Kunde", "Customer"), ["__KEINER__"] + kop, format_func=lambda x: t("Kein Kunde", "No customer") if x == "__KEINER__" else kunden_label(x), key=f"neu_projektkunde_{_projekt_form_version}")
                c1,c2,c3 = st.columns(3)
                status = c1.selectbox(t("Status", "Status"), ["Offen", "Laufend", "Abgeschlossen", "Pausiert"], key=f"neu_projektstatus_{_projekt_form_version}")
                start = c2.date_input(t("Startdatum", "Start date"), date.today(), format=DATUMSFORMAT_UI, key=f"neu_projektstart_{_projekt_form_version}")
                ende = c3.date_input(t("Enddatum", "End date"), None, format=DATUMSFORMAT_UI, key=f"neu_projektende_{_projekt_form_version}")
                satz = st.number_input(t("Stundensatz (optional)", "Hourly rate (optional)"), min_value=0.0, step=5.0, key=f"neu_projektsatz_{_projekt_form_version}")
                pnotiz = st.text_input(t("Notiz", "Note"), key=f"neu_projektnotiz_{_projekt_form_version}")
                if st.button(t("💾 Projekt anlegen", "💾 Add project"), key="projekt_anlegen", type="primary"):
                    nr = pnr.strip() or f"P-{len(st.session_state.projekte)+1:04d}"
                    if not pname.strip(): st.error(t("Bitte einen Projektnamen eingeben.", "Please enter a project name."))
                    elif pkunde == "__KEINER__": st.error(t("Bitte einen Kunden auswählen.", "Please select a customer."))
                    elif ende is not None and ende < start: st.error(t("Das Enddatum darf nicht vor dem Startdatum liegen.", "End date cannot be before start date."))
                    elif not eindeutige_nummer_pruefen(st.session_state.projekte, "Projektnummer", nr):
                        st.error(t(f"Die Projektnummer „{nr}“ ist bereits vergeben. Bitte eine andere Projektnummer verwenden.",
                                    f"Project number “{nr}” is already in use. Please use another project number."))
                    else:
                        st.session_state.projekte = zeile_anhaengen(st.session_state.projekte, {"Projekt-ID": neue_id(), "Projektnummer": nr, "Projekt": pname.strip(), "Kunden-ID": pkunde, "Status": status, "Startdatum": start, "Enddatum": ende, "Stundensatz": float(satz), "Aktiv": True, "Notiz": pnotiz.strip()})
                        speichern("projekte")
                        st.session_state["_projekt_form_version"] = _projekt_form_version + 1
                        melde(f"Projekt „{pname.strip()}“ angelegt.", "Project created.", "📁"); st.rerun()
            if st.session_state.projekte.empty:
                st.info(t("Noch keine Projekte angelegt.", "No projects yet."))
            else:
                proj_edit = st.session_state.projekte.copy(); proj_edit["Löschen"] = False
                _pk = aktive_kunden_df()
                _proj_kunden_ids = _pk["Kunden-ID"].astype(str).tolist() if not _pk.empty else []
                edited_p = st.data_editor(proj_edit, use_container_width=True, hide_index=True, num_rows="fixed", key="projekte_editor", column_config={"Projekt-ID": st.column_config.TextColumn("ID", disabled=True), "Kunden-ID": st.column_config.SelectboxColumn("Kunde", options=_proj_kunden_ids), "Startdatum": st.column_config.DateColumn("Startdatum", format=DATUMSFORMAT_UI), "Enddatum": st.column_config.DateColumn("Enddatum", format=DATUMSFORMAT_UI), "Stundensatz": st.column_config.NumberColumn("Stundensatz", min_value=0.0, step=5.0, format="%.2f"), "Aktiv": st.column_config.CheckboxColumn("Aktiv"), "Löschen": st.column_config.CheckboxColumn("Löschen")})
                if st.button(t("💾 Projektänderungen speichern", "💾 Save project changes"), key="projekte_speichern", type="primary"):
                    doppelte_p = doppelte_nummern(edited_p, "Projektnummer")
                    if doppelte_p:
                        st.error(t(f"Projektnummern dürfen nicht doppelt vergeben werden: {', '.join(doppelte_p)}",
                                   f"Project numbers must be unique: {', '.join(doppelte_p)}"))
                    else:
                        st.session_state.projekte = edited_p.drop(columns=["Löschen"]).reset_index(drop=True); speichern("projekte"); st.rerun()

    # ---------------- Benutzerkonten ----------------
    with tab_konten:
        admin_anzahl = len(aktive_admins())
        st.markdown(f"##### {t('Kontoübersicht', 'Account overview')}")
        uebersicht = benutzer_ohne_geheimnisse().copy()
        uebersicht.insert(1, "Person", uebersicht["MA-ID"].apply(id_zu_name).replace("", "—"))
        uebersicht = uebersicht.drop(columns=["MA-ID"])
        uebersicht["Sprache"] = uebersicht["Sprache"].map(lambda s: SPRACHEN.get(str(s), str(s)))
        tabelle(uebersicht, status_spalte=None)
        st.caption(t(f"Aktive Admin-Konten: {admin_anzahl} · Es sind beliebig viele Admins möglich; "
                     "nur das letzte aktive Admin-Konto ist geschützt. "
                     "Passwörter liegen ausschließlich als PBKDF2-Hash vor.",
                     f"Active admin accounts: {admin_anzahl} · Any number of admins is possible; "
                     "only the last active admin account is protected. "
                     "Passwords are stored as PBKDF2 hashes only."))

        stamm = alle_mitarbeiter()
        verknuepfte_ids = set(st.session_state.benutzer["MA-ID"].astype(str))
        ohne_konto = [str(p["Mitarbeiter"]) for _, p in stamm.iterrows()
                      if bool(p["Aktiv"]) and str(p["MA-ID"]) not in verknuepfte_ids]
        verwaiste = st.session_state.benutzer[
            (st.session_state.benutzer["Rolle"] == "Mitarbeiter")
            & (st.session_state.benutzer["MA-ID"].apply(id_zu_name) == "")
        ]["Benutzername"].tolist()
        if ohne_konto:
            st.warning(t(f"Noch ohne Login: {', '.join(ohne_konto)}",
                         f"Still without a login: {', '.join(ohne_konto)}"))
        if verwaiste:
            st.error(t(f"Ohne gültige Personenzuordnung: {', '.join(verwaiste)}",
                       f"Without a valid person link: {', '.join(verwaiste)}"))

        st.markdown(f"##### {t('Neues Konto anlegen', 'Create a new account')}")
        st.info(t("Das Systemadministrator-Konto wird ausschließlich vom Betreiber verwaltet und kann vom Kunden nicht angelegt oder einem Mitarbeiter zugeordnet werden. Kunden verwenden die Rolle „Leitung / Admin“ als KeyUser.",
                   "The System Administrator account is managed exclusively by the software operator and cannot be created or assigned by the customer. Customers use the “Management / Admin” role as KeyUser."))
        with st.container(border=True):
            c1, c2 = st.columns(2)
            # Kunden können nur normale Mitarbeiter- oder Leitungs-/Admin-Konten anlegen.
            # Das Systemadministrator-Konto bleibt ausschließlich auf Betreiberebene.
            rollen_kunde = ["Mitarbeiter", "Leitung / Admin"]
            rolle_neu = c1.selectbox(t("Rolle", "Role"), rollen_kunde, format_func=wert_label, key="rolle_neu")
            zuordnung_id = ""
            if rolle_neu in ("Mitarbeiter", "Leitung / Admin"):
                kandidaten = stamm[stamm["Aktiv"].fillna(True).astype(bool)]
                kandidaten = kandidaten[~kandidaten["MA-ID"].astype(str).isin(verknuepfte_ids)]
                if kandidaten.empty:
                    c2.warning(t("Kein Mitarbeiter ohne Benutzerkonto vorhanden. Bitte zuerst einen weiteren Mitarbeiter in den Stammdaten hinterlegen.",
                                  "No employee without a user account is available. Please add another employee in the employee master data first."))
                else:
                    ids = kandidaten["MA-ID"].astype(str).tolist()
                    ids.sort(key=lambda x: id_zu_name(x))
                    zuordnung_id = c2.selectbox(
                        t("Zugeordnete Person", "Linked person"), ids,
                        format_func=lambda x: id_zu_name(x),
                        key="zuordnung_neu")
            else:
                c2.text_input(t("Zugeordnete Person", "Linked person"),
                              t("— nicht nötig —", "— not required —"), disabled=True)

            vorschlag = benutzername_vorschlag(id_zu_name(zuordnung_id) or "leitung",
                                               st.session_state.benutzer["Benutzername"].tolist())
            c3, c4, c5 = st.columns(3)
            name_neu = c3.text_input(t("Benutzername", "Username"), vorschlag, key="benutzername_neu")
            pw_neu = c4.text_input(t("Startpasswort", "Initial password"), START_PASSWORT, key="startpw_neu")
            sprache_neu = c5.selectbox(t("Sprache", "Language"), list(SPRACHEN.keys()),
                                       format_func=lambda s: SPRACHEN[s], key="sprache_neu")

            wechsel_pflicht = st.checkbox(
                t("Passwortwechsel beim ersten Login erzwingen",
                  "Force password change at first sign-in"),
                value=True, key="neu_wechsel_pflicht",
                help=t("Empfohlen: Das Startpasswort ist dir bekannt und sollte nicht dauerhaft gelten.",
                       "Recommended: you know the initial password, so it should not remain in use."))

            if st.button(t("➕ Konto anlegen", "➕ Create account"),
                         use_container_width=True, type="primary"):
                name_neu = name_neu.strip().lower()
                if not name_neu:
                    st.error(t("Der Benutzername darf nicht leer sein.", "The username must not be empty."))
                elif finde_benutzer(name_neu) is not None:
                    st.error(t("Dieser Benutzername ist bereits vergeben.", "This username already exists."))
                elif rolle_neu in ("Mitarbeiter", "Leitung / Admin") and not zuordnung_id:
                    st.error(t("Für ein Mitarbeiter- oder Leitungs-/Admin-Konto muss eine Person zugeordnet werden.",
                               "An employee or management/admin account needs a linked person."))
                elif len(pw_neu) < int(cfg("passwort_mindestlaenge")):
                    st.error(t(f"Das Startpasswort braucht mindestens {int(cfg('passwort_mindestlaenge'))} Zeichen.",
                               f"The initial password needs at least {MIN_PASSWORTLAENGE} characters."))
                else:
                    st.session_state.benutzer = zeile_anhaengen(
                        st.session_state.benutzer,
                        neuer_benutzer_datensatz(name_neu, pw_neu, rolle_neu, zuordnung_id,
                                                 sprache_neu, wechsel_erzwingen=bool(wechsel_pflicht)))
                    speichern("benutzer")
                    # Leitung/Admin darf rückwirkend korrigieren – Vorgabe unbegrenzt
                    if rolle_neu in ("Leitung / Admin", "Systemadministrator") and zuordnung_id:
                        stamm_df = st.session_state.mitarbeiter_stammdaten
                        ziel_maske = stamm_df["MA-ID"].astype(str) == str(zuordnung_id)
                        stamm_df.loc[ziel_maske, "Nachtrag_Std_Limit"] = NACHTRAG_UNBEGRENZT
                        st.session_state.mitarbeiter_stammdaten = stamm_df
                        speichern("mitarbeiter_stammdaten")
                    melde(f"Konto „{name_neu}“ angelegt – Startpasswort weitergeben.",
                          f"Account “{name_neu}” created – share the initial password.", "➕")
                    st.rerun()

        st.markdown(f"##### {t('Konto bearbeiten', 'Edit account')}")
        with st.container(border=True):
            konto_df = st.session_state.benutzer.copy()
            if not systemadmin_vollzugriff:
                konto_df = konto_df[konto_df["Rolle"].astype(str) != "Systemadministrator"]
            konten = konto_df["Benutzername"].astype(str).tolist()
            if not konten:
                st.info(t("Keine Konten vorhanden.", "No accounts available."))
            else:
                def _konto_label(b):
                    z = finde_benutzer(b)
                    zusatz = "" if bool(z["Aktiv"]) else t("  (gesperrt)", "  (blocked)")
                    return f"{b} · {id_zu_name(z['MA-ID']) or wert_label(z['Rolle'])}{zusatz}"

                ziel = st.selectbox(t("Konto", "Account"), konten, format_func=_konto_label, key="konto_ziel")
                ziel_zeile = finde_benutzer(ziel)
                aktiv = bool(ziel_zeile["Aktiv"])
                ist_eigenes = ziel == st.session_state.username

                with st.form("konto_bearbeiten"):
                    e1, e2, e3 = st.columns(3)
                    neuer_benutzername = e1.text_input(t("Benutzername", "Username"), ziel)
                    rollen_bearbeiten = ROLLEN if systemadmin_vollzugriff else ["Mitarbeiter", "Leitung / Admin"]
                    aktuelle_rolle = str(ziel_zeile["Rolle"])
                    if aktuelle_rolle == "Systemadministrator" and not systemadmin_vollzugriff:
                        # Systemadmin-Konten gehören zur Betreiber-Ebene und sind für Kunden nicht editierbar.
                        st.error(t("Dieses Konto gehört zur Betreiber-Ebene und kann vom Kunden nicht geändert werden.",
                                   "This account belongs to the software operator and cannot be changed by the customer."))
                        neue_rolle = aktuelle_rolle
                    else:
                        neue_rolle = e2.selectbox(t("Rolle", "Role"), rollen_bearbeiten, format_func=wert_label,
                                                  index=rollen_bearbeiten.index(aktuelle_rolle)
                                                  if aktuelle_rolle in rollen_bearbeiten else 0)
                    sprachschluessel = list(SPRACHEN.keys())
                    aktuelle_sprache = str(ziel_zeile["Sprache"] or "de")
                    neue_sprache_konto = e3.selectbox(
                        t("Sprache", "Language"), sprachschluessel,
                        index=sprachschluessel.index(aktuelle_sprache)
                        if aktuelle_sprache in sprachschluessel else 0,
                        format_func=lambda s: SPRACHEN[s])

                    ids = [""] + stamm["MA-ID"].astype(str).tolist()
                    aktuelle_id = str(ziel_zeile["MA-ID"] or "")
                    neue_zuordnung = st.selectbox(
                        t("Zugeordnete Person", "Linked person"), ids,
                        index=ids.index(aktuelle_id) if aktuelle_id in ids else 0,
                        format_func=lambda x: id_zu_name(x) if x else t("— keine Person zugeordnet —",
                                                                        "— no person linked —"))
                    uebernommen = st.form_submit_button(t("💾 Änderungen speichern", "💾 Save changes"),
                                                        use_container_width=True, type="primary")

                if uebernommen:
                    neuer_benutzername = neuer_benutzername.strip().lower()
                    doppelt = neuer_benutzername != ziel and finde_benutzer(neuer_benutzername) is not None
                    letzter_admin = (str(ziel_zeile["Rolle"]) == "Leitung / Admin"
                                     and neue_rolle != "Leitung / Admin" and admin_anzahl <= 1)
                    if not neuer_benutzername:
                        st.error(t("Der Benutzername darf nicht leer sein.", "The username must not be empty."))
                    elif doppelt:
                        st.error(t("Dieser Benutzername ist bereits vergeben.", "This username already exists."))
                    elif neue_rolle in ("Mitarbeiter", "Leitung / Admin") and not neue_zuordnung:
                        st.error(t("Bitte eine Person aus den Stammdaten zuordnen.",
                                   "Please link a person from the employee master data."))
                    elif letzter_admin:
                        st.error(t("Das letzte Admin-Konto kann die Rolle nicht abgeben.",
                                   "The last admin account cannot give up its role."))
                    else:
                        maske = st.session_state.benutzer["Benutzername"].astype(str) == ziel
                        st.session_state.benutzer.loc[maske, "Benutzername"] = neuer_benutzername
                        st.session_state.benutzer.loc[maske, "Rolle"] = neue_rolle
                        st.session_state.benutzer.loc[maske, "Sprache"] = neue_sprache_konto
                        st.session_state.benutzer.loc[maske, "MA-ID"] = (
                            neue_zuordnung if neue_rolle in ("Mitarbeiter", "Leitung / Admin") else "")
                        speichern("benutzer")

                        # Wird jemandem die Leitungsrolle gegeben, bekommt die Person
                        # ein unbegrenztes Nachtragsfenster. In den Stammdaten lässt
                        # sich das jederzeit wieder auf einen konkreten Wert setzen.
                        if (neue_rolle in ("Leitung / Admin", "Systemadministrator")
                                and neue_zuordnung and str(ziel_zeile["Rolle"]) != neue_rolle):
                            stamm_df = st.session_state.mitarbeiter_stammdaten
                            ziel_maske = stamm_df["MA-ID"].astype(str) == str(neue_zuordnung)
                            aktuelles_limit = pd.to_numeric(
                                stamm_df.loc[ziel_maske, "Nachtrag_Std_Limit"], errors="coerce")
                            if (aktuelles_limit < NACHTRAG_UNBEGRENZT_AB).any():
                                stamm_df.loc[ziel_maske, "Nachtrag_Std_Limit"] = NACHTRAG_UNBEGRENZT
                                st.session_state.mitarbeiter_stammdaten = stamm_df
                                speichern("mitarbeiter_stammdaten")
                        if ist_eigenes:
                            st.session_state.username = neuer_benutzername
                            st.session_state.role = neue_rolle
                            st.session_state.sprache = neue_sprache_konto
                        melde("Konto aktualisiert.", "Account updated.", "💾")
                        st.rerun()

                st.markdown("---")
                c1, c2 = st.columns(2)
                with c1:
                    reset_pw = st.text_input(t("Neues Startpasswort", "New initial password"),
                                             START_PASSWORT, key="reset_pw")
                    if st.button(t("🔄 Passwort zurücksetzen", "🔄 Reset password"),
                                 use_container_width=True):
                        if len(reset_pw) < int(cfg("passwort_mindestlaenge")):
                            st.error(t(f"Mindestens {int(cfg('passwort_mindestlaenge'))} Zeichen erforderlich.",
                                       f"At least {MIN_PASSWORTLAENGE} characters required."))
                        else:
                            passwort_setzen(ziel, reset_pw, wechsel_erzwingen=True)
                            melde(f"Passwort für „{ziel}“ zurückgesetzt.",
                                  f"Password for “{ziel}” has been reset.", "🔄")
                            st.rerun()
                with c2:
                    label = t("🚫 Konto sperren", "🚫 Block account") if aktiv else \
                            t("✅ Konto entsperren", "✅ Unblock account")
                    if st.button(label, use_container_width=True, disabled=ist_eigenes and aktiv):
                        if aktiv and str(ziel_zeile["Rolle"]) == "Leitung / Admin" and admin_anzahl <= 1:
                            st.error(t("Das letzte aktive Admin-Konto kann nicht gesperrt werden.",
                                       "The last active admin account cannot be blocked."))
                        else:
                            maske = st.session_state.benutzer["Benutzername"].astype(str) == ziel
                            st.session_state.benutzer.loc[maske, "Aktiv"] = not aktiv
                            speichern("benutzer")
                            melde("Kontostatus geändert.", "Account status changed.", "🔐")
                            st.rerun()
                    if ist_eigenes and aktiv:
                        st.caption(t("Das eigene Konto kann nicht gesperrt werden.",
                                     "You cannot block your own account."))

                if systemadmin_vollzugriff:
                    st.markdown("---")
                    st.warning("Systemadmin: Konto endgültig löschen. Das eigene Konto und das letzte Systemadmin-Konto sind geschützt.")
                    konto_del_runde = st.session_state.get("_sys_konto_del_runde", 0)
                    if st.checkbox("Ich möchte dieses Konto zur endgültigen Löschung markieren",
                                   key=f"sys_konto_delete_confirm_{konto_del_runde}"):
                        st.warning(f"Das Konto **{ziel}** wird dauerhaft gelöscht. Diese Aktion kann nicht rückgängig gemacht werden.")
                        c_del1, c_del2 = st.columns(2)
                        if c_del1.button("⚠️ Ja, Konto endgültig löschen", key="sys_konto_delete", use_container_width=True):
                            sys_admin_anzahl = int((st.session_state.benutzer["Rolle"].astype(str) == "Systemadministrator").sum())
                            if ziel == st.session_state.username:
                                st.error("Das aktuell angemeldete Konto kann nicht gelöscht werden.")
                            elif str(ziel_zeile["Rolle"]) == "Systemadministrator" and sys_admin_anzahl <= 1:
                                st.error("Das letzte Systemadministrator-Konto kann nicht gelöscht werden.")
                            else:
                                maske = st.session_state.benutzer["Benutzername"].astype(str) == ziel
                                st.session_state.benutzer = st.session_state.benutzer.loc[~maske].reset_index(drop=True)
                                speichern("benutzer")
                                melde(f"Konto „{ziel}“ gelöscht.", f"Account “{ziel}” deleted.", "🗑️")
                                st.rerun()
                        if c_del2.button("Abbrechen", key="sys_konto_delete_cancel", use_container_width=True):
                            st.session_state["_sys_konto_del_runde"] = konto_del_runde + 1
                            melde("Löschen abgebrochen.", "Deletion cancelled.", "↩️")
                            st.rerun()

    # ---------------- Einstellungen ----------------
    with tab_einst:
        # Demo-Daten sind eine Betreiber-/Systemadmin-Funktion und dürfen von
        # Kundennutzern (Leitung / Admin) niemals angezeigt oder ausgelöst werden.
        if systemadmin_vollzugriff:
            with st.expander(t("🎭 Demo-Daten für eine Kundenvorführung laden",
                                   "🎭 Load demo data for a customer presentation")):
                st.caption(t(
                    "Füllt die App in Sekunden mit branchentypischen Beispiel-Mitarbeitenden, "
                    "-Zeiten und einem Urlaubsantrag – praktisch, um dieselbe App heute einem "
                    "Handwerksbetrieb und morgen einer Kita zu zeigen. Deine eigenen Admin-Konten "
                    "bleiben dabei erhalten, du wirst also nicht ausgeloggt.",
                    "Fills the app with industry-typical sample employees, times and a leave "
                    "request in seconds – handy for showing the same app to a trades business "
                    "today and a childcare center tomorrow. Your own admin accounts are kept, "
                    "so you won't be signed out."))
                st.warning(t(
                    "⚠️ Alle aktuellen Mitarbeitenden, Zeiten, Urlaubsanträge und Mitarbeiter-Logins "
                    "werden dabei unwiderruflich ersetzt.",
                    "⚠️ All current employees, times, leave requests and employee logins will be "
                    "permanently replaced."))

                d1, d2 = st.columns(2)
                demo_branche = d1.selectbox(
                    t("Branche für die Vorführung", "Industry for the presentation"),
                    list(BRANCHEN.keys()), format_func=branche_label, key="demo_branche")
                demo_firma = d2.text_input(
                    t("Name der Einrichtung", "Organization name"),
                    DEMO_FIRMENNAMEN[demo_branche], key="demo_firma")

                # Der Zähler im Schlüssel setzt die Checkbox nach dem Laden zurück.
                # Ein direktes Setzen von st.session_state ist bei bereits erzeugten
                # Widgets nicht erlaubt und löst einen Fehler aus.
                lauf = st.session_state.get("demo_lauf", 0)
                bestaetigt = st.checkbox(
                    t("Ich bestätige, dass alle aktuellen Daten überschrieben werden.",
                      "I confirm that all current data will be overwritten."),
                    key=f"demo_bestaetigt_{lauf}")
                if st.button(t("🔄 Demo-Daten jetzt laden", "🔄 Load demo data now"),
                             use_container_width=True, disabled=not bestaetigt):
                    demo_zuruecksetzen(demo_branche, demo_firma)
                    st.session_state.demo_lauf = lauf + 1
                    melde(f"Demo-Daten für „{branche_label(demo_branche)}“ geladen.",
                          f"Demo data for “{branche_label(demo_branche)}” loaded.", "🎭")
                    st.rerun()

        if systemadmin_vollzugriff:
            st.markdown(f"##### {t('Betrieb', 'Company')}")
            with st.container(border=True):
                firmenname = st.text_input(t("Name der Einrichtung", "Organization name"), cfg("firmenname"))
                branchen_liste = list(BRANCHEN.keys())
                gewaehlte_branche = st.selectbox(t("Branche", "Industry"), branchen_liste,
                                                 index=branchen_liste.index(cfg("branche")),
                                                 format_func=branche_label)
                vorschau = BRANCHEN[gewaehlte_branche]
                kategorien_text = ", ".join(
                    (en if ist_englisch() else de) for de, en in vorschau["kategorien"])
                st.caption(f"{t('Kategorien', 'Categories')}: {kategorien_text} · "
                           f"{t('Projektfeld', 'Project field')}: "
                           f"{vorschau['projekt_label'][1] if ist_englisch() else vorschau['projekt_label'][0]}")
        else:
            st.markdown(f"##### {t('Betrieb', 'Company')}")
            st.info(t(f"Einrichtung: **{cfg('firmenname')}** · Branche: **{branche_label(cfg('branche'))}**. "
                       "Firmenname und Branche werden ausschließlich vom Systemadmin festgelegt.",
                       f"Company: **{cfg('firmenname')}** · Industry: **{branche_label(cfg('branche'))}**. "
                       "Company name and industry are set exclusively by the system administrator."))
            firmenname = cfg("firmenname")
            gewaehlte_branche = cfg("branche")

        # Arbeitszeit- und Abwesenheitsarten werden branchenspezifisch ausgerollt.
        # Nur der Systemadmin bestimmt Branche/Firma; der Kunde darf die ausgerollten
        # Arten bearbeiten, solange sie noch nicht verwendet wurden.
        st.markdown(f"##### {t('Arbeitszeit- und Abwesenheitsarten', 'Working-time and absence types')}")
        with st.container(border=True):
            if systemadmin_vollzugriff:
                st.caption(t(
                    "Diese Arten werden aus der aktuell festgelegten Branche ausgerollt. "
                    "Der Kunde kann sie anschließend bearbeiten, solange die jeweilige Art noch nicht gebucht wurde.",
                    "These types are rolled out from the selected industry. The customer can then edit them "
                    "until the respective type has been used in a booking."))
            else:
                st.caption(t(
                    "Die Arten wurden vom Systemadmin für die Branche dieses Betriebs ausgerollt. "
                    "Unbenutzte Arten können Sie als KeyUser anpassen; bereits gebuchte Arten sind gesperrt.",
                    "The types were rolled out by the system administrator for this company's industry. "
                    "Unused types can be changed by the KeyUser; already booked types are locked."))

            az = arbeitszeitarten()
            st.markdown(f"**{t('Arbeitszeitarten', 'Working-time types')}**")
            neue_az = []
            for nr, wert in enumerate(az):
                gebucht = arbeitszeitart_gebucht(wert)
                c1, c2, c3 = st.columns([6, 2, 1])
                neu_wert = c1.text_input(
                    f"{t('Bezeichnung', 'Name')} {nr + 1}", wert, disabled=gebucht,
                    key=f"az_name_{nr}")
                if gebucht:
                    c2.caption(t("bereits gebucht", "already booked"))
                loeschen = c3.checkbox(t("Löschen", "Delete"), disabled=gebucht, key=f"az_del_{nr}")
                if not loeschen and neu_wert.strip():
                    neue_az.append(neu_wert.strip())
            c1, c2 = st.columns([6, 2])
            az_runde = st.session_state.get("_az_neu_runde", 0)
            neue_az_bezeichnung = c1.text_input(t("Neue Arbeitszeitart", "New working-time type"),
                                                key=f"az_neu_{az_runde}")
            if c2.button(t("➕ Hinzufügen", "➕ Add"), key="az_hinzufuegen"):
                name = neue_az_bezeichnung.strip()
                if not name:
                    st.error(t("Bitte eine Bezeichnung eingeben.", "Please enter a name."))
                elif name in neue_az:
                    st.error(t("Diese Arbeitszeitart ist bereits vorhanden.", "This working-time type already exists."))
                else:
                    neue_az.append(name)
                    st.session_state.config["arbeitszeitarten"] = neue_az
                    einstellungen_speichern(st.session_state.config)
                    st.session_state["_az_neu_runde"] = az_runde + 1
                    melde("Arbeitszeitart hinzugefügt.", "Working-time type added.", "➕")
                    st.rerun()

            st.markdown(f"**{t('Abwesenheitsgründe', 'Absence reasons')}**")
            aw = abwesenheitsarten()
            neue_aw = []
            for nr, (wert, _, stundenweise) in enumerate(aw):
                gebucht = abwesenheitsart_gebucht(wert)
                c1, c2, c3 = st.columns([5, 2, 1])
                neu_wert = c1.text_input(
                    f"{t('Bezeichnung', 'Name')} {nr + 1}", wert, disabled=gebucht,
                    key=f"aw_name_{nr}")
                neu_stunden = c2.checkbox(
                    t("Stundenweise", "Hourly allowed"), stundenweise, disabled=gebucht, key=f"aw_std_{nr}")
                loeschen = c3.checkbox(t("Löschen", "Delete"), disabled=gebucht, key=f"aw_del_{nr}")
                if not loeschen and neu_wert.strip():
                    neue_aw.append({"name": neu_wert.strip(), "stundenweise": bool(neu_stunden)})
                if gebucht:
                    st.caption(t("Bereits gebucht – gesperrt.", "Already booked – locked."))
            c1, c2, c3 = st.columns([5, 2, 1])
            aw_runde = st.session_state.get("_aw_neu_runde", 0)
            aw_neu = c1.text_input(t("Neuer Abwesenheitsgrund", "New absence reason"),
                                   key=f"aw_neu_{aw_runde}")
            aw_neu_std = c2.checkbox(t("Stundenweise möglich", "Hourly allowed"),
                                     key=f"aw_neu_std_{aw_runde}")
            if c3.button(t("➕ Hinzufügen", "➕ Add"), key="aw_hinzufuegen"):
                name = aw_neu.strip()
                if not name:
                    st.error(t("Bitte eine Bezeichnung eingeben.", "Please enter a name."))
                elif any(x["name"] == name for x in neue_aw):
                    st.error(t("Dieser Abwesenheitsgrund ist bereits vorhanden.", "This absence reason already exists."))
                else:
                    neue_aw.append({"name": name, "stundenweise": bool(aw_neu_std)})
                    st.session_state.config["abwesenheitsarten"] = neue_aw
                    einstellungen_speichern(st.session_state.config)
                    st.session_state["_aw_neu_runde"] = aw_runde + 1
                    melde("Abwesenheitsgrund hinzugefügt.", "Absence reason added.", "➕")
                    st.rerun()

            if st.button(t("💾 Arten speichern", "💾 Save types"), key="arten_speichern", use_container_width=True):
                # Bereits gebuchte Arten dürfen weder umbenannt noch gelöscht werden.
                gebuchte_az = {x for x in az if arbeitszeitart_gebucht(x)}
                gebuchte_aw = {x[0] for x in aw if abwesenheitsart_gebucht(x[0])}
                if not gebuchte_az.issubset(set(neue_az)):
                    st.error(t("Bereits gebuchte Arbeitszeitarten dürfen nicht gelöscht oder umbenannt werden.",
                               "Already booked working-time types cannot be deleted or renamed."))
                elif not gebuchte_aw.issubset({x["name"] for x in neue_aw}):
                    st.error(t("Bereits gebuchte Abwesenheitsgründe dürfen nicht gelöscht oder umbenannt werden.",
                               "Already booked absence reasons cannot be deleted or renamed."))
                elif len(set(neue_az)) != len(neue_az) or len({x["name"] for x in neue_aw}) != len(neue_aw):
                    st.error(t("Bezeichnungen müssen eindeutig sein.", "Names must be unique."))
                elif not neue_az or not neue_aw:
                    st.error(t("Es muss mindestens eine Arbeitszeitart und einen Abwesenheitsgrund geben.",
                               "At least one working-time type and one absence reason are required."))
                else:
                    st.session_state.config["arbeitszeitarten"] = neue_az
                    st.session_state.config["abwesenheitsarten"] = neue_aw
                    einstellungen_speichern(st.session_state.config)
                    melde(t("Arbeitszeit- und Abwesenheitsarten gespeichert.", "Working-time and absence types saved."),
                          t("Working-time and absence types saved.", "Working-time and absence types saved."), "💾")
                    st.rerun()

        alte_branche = cfg("branche")

        st.markdown(f"##### {t('Funktionen', 'Features')}")
        with st.container(border=True):
            live_stempeln = st.toggle(
                t("🕒 Live-Stempeln aktivieren", "🕒 Enable live clocking"), cfg("live_stempeln_aktiv"),
                help=t("Wenn deaktiviert, sehen Mitarbeitende nur „Zeit nachtragen“. Offene Buchungen "
                       "können trotzdem geschlossen werden.",
                       "When disabled, employees only see “Add time”. Open entries can still be closed."))
            st.caption(t("Wie weit einzelne Mitarbeitende Zeiten rückwirkend ändern dürfen, wird je "
                         "Person unter „👥 Stammdaten“ eingestellt (Vorgabe: 24 Std.).",
                         "How far back each employee may edit times is set per person under "
                         "“👥 Employees” (default: 24 h)."))

        st.markdown(f"##### {t('Pausenregelung', 'Break rules')}")
        with st.container(border=True):
            c1, c2 = st.columns(2)
            schwelle_1 = c1.number_input(t("Pause ab mehr als … Std.", "Break after more than … h"),
                                         0.0, 12.0, float(cfg("pause_schwelle_1")), 0.5)
            dauer_1 = c2.number_input(t("… Minuten Pause", "… minutes of break"),
                                      0, 120, int(cfg("pause_dauer_1")), 5)
            c3, c4 = st.columns(2)
            schwelle_2 = c3.number_input(t("Pause ab mehr als … Std. (Stufe 2)",
                                           "Break after more than … h (level 2)"),
                                         0.0, 16.0, float(cfg("pause_schwelle_2")), 0.5)
            dauer_2 = c4.number_input(t("… Minuten Pause (Stufe 2)", "… minutes of break (level 2)"),
                                      0, 180, int(cfg("pause_dauer_2")), 5)
            st.caption(t("Voreinstellung entspricht § 4 ArbZG: über 6 Std. → 30 Min., über 9 Std. → 45 Min.",
                         "Default follows German law (§ 4 ArbZG): over 6 h → 30 min, over 9 h → 45 min."))

        if systemadmin_vollzugriff:
            st.markdown("##### 🔐 Systemadmin: Sicherheit & Login")
            with st.container(border=True):
                sec1, sec2 = st.columns(2)
                sicher_mindest = sec1.number_input(
                    "Passwort-Mindestlänge", min_value=6, max_value=128,
                    value=int(cfg("passwort_mindestlaenge")), step=1, key="sys_passwort_min")
                sicher_versuche = sec2.number_input(
                    "Maximale Login-Fehlversuche", min_value=1, max_value=20,
                    value=int(cfg("max_login_versuche")), step=1, key="sys_login_versuche")
                sicher_sperre = st.number_input(
                    "Login-Sperrdauer (Minuten)", min_value=1, max_value=1440,
                    value=int(cfg("sperrdauer_minuten")), step=1, key="sys_sperrdauer")
                st.caption("Diese Werte gelten für alle Benutzerkonten. Änderungen werden dauerhaft gespeichert.")

        st.markdown(f"##### {t('Berechnung', 'Calculation')}")
        with st.container(border=True):
            urlaub_arbeitstage = st.toggle(t("Urlaub in Arbeitstagen zählen (Mo–Fr)",
                                             "Count leave in working days (Mon–Fri)"),
                                           cfg("urlaub_in_arbeitstagen"))
            feiertage_aktiv = st.toggle(t("Gesetzliche Feiertage berücksichtigen",
                                          "Consider public holidays"),
                                        cfg("feiertage_beruecksichtigen"))

            laender = list(BUNDESLAENDER.keys())
            aktuelles_land = cfg("bundesland") if cfg("bundesland") in laender else "BY"
            bundesland = st.selectbox(
                t("Bundesland", "Federal state"), laender,
                index=laender.index(aktuelles_land),
                format_func=lambda k: f"{BUNDESLAENDER[k]} ({k})",
                disabled=not feiertage_aktiv,
                help=t("Bestimmt die regionalen Feiertage, z. B. Fronleichnam oder Reformationstag.",
                       "Determines regional holidays, e.g. Corpus Christi or Reformation Day."),
            )

            if feiertage_aktiv:
                jahr = date.today().year
                liste = feiertage_benannt(jahr, bundesland)
                werktags = [x for x in liste if x[0].weekday() < 5]
                with st.expander(t(f"📅 Feiertage {jahr} in {BUNDESLAENDER[bundesland]} "
                                   f"({len(werktags)} an Werktagen)",
                                   f"📅 Public holidays {jahr} in {BUNDESLAENDER[bundesland]} "
                                   f"({len(werktags)} on weekdays)")):
                    vorschau = pd.DataFrame([
                        {t("Datum", "Date"): tag.strftime(DATUMSFORMAT),
                         t("Wochentag", "Weekday"): WOCHENTAGE[st.session_state.sprache][tag.weekday()],
                         t("Feiertag", "Holiday"): FEIERTAGSNAMEN[name][1 if ist_englisch() else 0]}
                        for tag, name in liste
                    ])
                    st.dataframe(vorschau, use_container_width=True, hide_index=True)
                    if bundesland == "BY":
                        st.caption(t("Hinweis: Mariä Himmelfahrt gilt in Bayern nur in überwiegend "
                                     "katholischen Gemeinden und ist hier nicht enthalten.",
                                     "Note: Assumption Day only applies in predominantly Catholic "
                                     "municipalities in Bavaria and is not included here."))
                    if bundesland in ("SN", "TH"):
                        st.caption(t("Hinweis: Fronleichnam gilt in einzelnen Gemeinden und ist hier "
                                     "nicht enthalten.",
                                     "Note: Corpus Christi applies in individual municipalities only "
                                     "and is not included here."))

            nachtschicht = st.toggle(t("Schichten über Mitternacht zulassen",
                                       "Allow shifts across midnight"), cfg("nachtschicht_erlaubt"))

        # Ungespeicherte Änderungen erkennen: Formularwerte gegen den gespeicherten
        # Stand vergleichen. Das Ergebnis füllt die Warnleiste oben in der App.
        formular_werte = {
            "pause_schwelle_1": float(schwelle_1), "pause_dauer_1": int(dauer_1),
            "pause_schwelle_2": float(schwelle_2), "pause_dauer_2": int(dauer_2),
            "urlaub_in_arbeitstagen": bool(urlaub_arbeitstage),
            "feiertage_beruecksichtigen": bool(feiertage_aktiv),
            "bundesland": str(bundesland), "nachtschicht_erlaubt": bool(nachtschicht),
            "live_stempeln_aktiv": bool(live_stempeln),
        }
        if systemadmin_vollzugriff:
            formular_werte.update({
                "firmenname": str(firmenname).strip() or "Mein Betrieb",
                "branche": str(gewaehlte_branche),
                "passwort_mindestlaenge": int(sicher_mindest),
                "max_login_versuche": int(sicher_versuche),
                "sperrdauer_minuten": int(sicher_sperre),
            })
        offene_aenderungen = [
            schluessel for schluessel, wert in formular_werte.items()
            if str(st.session_state.config.get(schluessel)) != str(wert)
        ]
        st.session_state["_einstellungen_offen"] = offene_aenderungen
        if offene_aenderungen:
            st.warning(t(
                f"⚠️ {len(offene_aenderungen)} Änderung(en) noch nicht gespeichert. "
                "Beim Verlassen ohne Speichern gehen sie verloren.",
                f"⚠️ {len(offene_aenderungen)} change(s) not saved yet. "
                "They will be lost if you leave without saving."))

        if st.button(t("💾 Einstellungen übernehmen", "💾 Apply settings"),
                     use_container_width=True, type="primary"):
            if schwelle_2 <= schwelle_1:
                st.error(t("Die zweite Pausenschwelle muss über der ersten liegen.",
                           "The second break threshold must be higher than the first."))
            else:
                st.session_state.config.update({
                    "pause_schwelle_1": schwelle_1,
                    "pause_dauer_1": int(dauer_1),
                    "pause_schwelle_2": schwelle_2,
                    "pause_dauer_2": int(dauer_2),
                    "urlaub_in_arbeitstagen": urlaub_arbeitstage,
                    "feiertage_beruecksichtigen": feiertage_aktiv,
                    "bundesland": bundesland,
                    "nachtschicht_erlaubt": nachtschicht,
                    "live_stempeln_aktiv": live_stempeln,
                })
                if systemadmin_vollzugriff:
                    st.session_state.config.update({
                        "firmenname": firmenname.strip() or "Mein Betrieb",
                        "branche": gewaehlte_branche,
                        "passwort_mindestlaenge": int(sicher_mindest),
                        "max_login_versuche": int(sicher_versuche),
                        "sperrdauer_minuten": int(sicher_sperre),
                    })
                    if str(gewaehlte_branche) != str(alte_branche):
                        # Neues Branchen-Grundset ausrollen, bereits gebuchte Arten aber
                        # als historische Werte erhalten, damit bestehende Buchungen lesbar bleiben.
                        alte_az = arbeitszeitarten()
                        gebuchte_az = [x for x in alte_az if arbeitszeitart_gebucht(x)]
                        neue_az = standard_arbeitszeitarten(str(gewaehlte_branche))
                        for x in gebuchte_az:
                            if x not in neue_az:
                                neue_az.append(x)
                        alte_aw = abwesenheitsarten()
                        gebuchte_aw = [x for x in alte_aw if abwesenheitsart_gebucht(x[0])]
                        neue_aw = [{"name": de, "stundenweise": erlaubt} for de, _, erlaubt in ABWESENHEITSARTEN]
                        for x in gebuchte_aw:
                            if not any(y["name"] == x[0] for y in neue_aw):
                                neue_aw.append({"name": x[0], "stundenweise": x[2]})
                        st.session_state.config["arbeitszeitarten"] = neue_az
                        st.session_state.config["abwesenheitsarten"] = neue_aw
                einstellungen_speichern(st.session_state.config)
                st.session_state["_einstellungen_offen"] = []
                melde("Einstellungen übernommen – für alle Nutzer gültig.",
                      "Settings applied – valid for all users.", "⚙️")
                st.rerun()

    # ---------------- Hilfe ----------------
    with tab_hilfe:
        st.markdown(f"#### {t('Hilfe & häufige Fragen', 'Help & frequently asked questions')}")
        st.caption(t(
            "Die meisten Fragen lassen sich hier in einer Minute selbst klären. "
            "Hilft das nicht weiter, steht unten, wie du den Support erreichst.",
            "Most questions can be answered here in a minute. If that does not help, "
            "you will find the support contact below."))

        with st.expander(t("🔑 Eine Mitarbeiterin hat ihr Passwort vergessen",
                           "🔑 An employee forgot their password")):
            st.markdown(t(
                "1. Tab **🔐 Benutzerkonten** öffnen\n"
                "2. Unter *Konto bearbeiten* das betreffende Konto auswählen\n"
                "3. Ein neues Startpasswort eintragen und auf **🔄 Passwort zurücksetzen** klicken\n"
                "4. Das Startpasswort der Person mitteilen – sie muss es beim nächsten Login ändern\n\n"
                "Du kannst bestehende Passwörter nicht einsehen. Sie sind nur verschlüsselt "
                "gespeichert, auch für dich als Leitung.",
                "1. Open the **🔐 User accounts** tab\n"
                "2. Select the account under *Edit account*\n"
                "3. Enter a new initial password and click **🔄 Reset password**\n"
                "4. Share the initial password – the user must change it at next sign-in\n\n"
                "Existing passwords cannot be viewed. They are only stored encrypted."))

        with st.expander(t("👤 Ich habe jemanden angelegt, aber die Person kann sich nicht anmelden",
                           "👤 I created a person but they cannot sign in")):
            st.markdown(t(
                "Stammdaten und Login sind zwei getrennte Schritte. Nach dem Anlegen unter "
                "**👥 Stammdaten** braucht die Person zusätzlich ein Konto:\n\n"
                "1. Tab **🔐 Benutzerkonten** öffnen\n"
                "2. Unter *Neues Konto anlegen* die Rolle *Mitarbeiter* wählen\n"
                "3. Die Person zuordnen und das Konto anlegen\n\n"
                "Oben im Tab warnt die App, wenn Mitarbeitende noch kein Login haben.",
                "Employee records and logins are two separate steps. After creating the person "
                "under **👥 Employees**, they also need an account:\n\n"
                "1. Open the **🔐 User accounts** tab\n"
                "2. Under *Create a new account*, choose the role *Employee*\n"
                "3. Link the person and create the account\n\n"
                "The tab warns you at the top if employees are still without a login."))

        with st.expander(t("🕒 Eine Zeit wurde falsch erfasst",
                           "🕒 A time entry is wrong")):
            st.markdown(t(
                "Mitarbeitende korrigieren ihre Zeiten selbst unter **📊 Meine Zeiten** – direkt "
                "in der Tabelle, solange der Eintrag innerhalb ihres Änderungszeitraums liegt "
                "(Vorgabe: 24 Stunden).\n\n"
                "Liegt der Eintrag weiter zurück oder ist er bereits freigegeben, kann nur die "
                "Leitung eingreifen. Den erlaubten Zeitraum stellst du pro Person unter "
                "**👥 Stammdaten** in der Spalte *Nachtrag-Limit* ein.",
                "Employees correct their own entries under **📊 My times** – directly in the "
                "table, as long as the entry is within their editing window (default: 24 hours).\n\n"
                "If the entry is older or already released, only management can change it. "
                "Set the window per person under **👥 Employees**, column *Edit window*."))

        with st.expander(t("💾 Wie prüfe ich, ob die Datensicherung läuft?",
                           "💾 How do I check that backups are running?")):
            backups = sorted(BACKUP_DIR.glob("zeiterfassung_*.db"), reverse=True) if BACKUP_DIR.exists() else []
            if backups:
                neuestes = backups[0]
                alter = datetime.now() - datetime.fromtimestamp(neuestes.stat().st_mtime)
                if alter.days > 2:
                    st.error(t(f"Letztes Backup ist {alter.days} Tage alt – bitte den Support informieren.",
                               f"Last backup is {alter.days} days old – please contact support."))
                else:
                    st.success(t(
                        f"Letztes Backup: {datetime.fromtimestamp(neuestes.stat().st_mtime):%d.%m.%Y %H:%M} "
                        f"· insgesamt {len(backups)} Sicherungen vorhanden.",
                        f"Last backup: {datetime.fromtimestamp(neuestes.stat().st_mtime):%d.%m.%Y %H:%M} "
                        f"· {len(backups)} backups in total."))
            else:
                st.warning(t("Es wurde noch kein Backup gefunden – bitte den Support informieren.",
                             "No backup found yet – please contact support."))
            st.markdown(t(
                f"Die Sicherungen liegen im Ordner `backups`. Sie laufen täglich automatisch.\n\n"
                "**Wichtig:** Eine Sicherung auf derselben Festplatte schützt nicht vor einem "
                "Festplattendefekt. Zusätzlich sollte der Ordner regelmäßig auf ein Netzlaufwerk "
                "oder eine externe Platte kopiert werden.",
                "Backups are stored in the `backups` folder and run automatically every day.\n\n"
                "**Important:** A backup on the same hard drive does not protect against drive "
                "failure. The folder should also be copied to a network or external drive."))

        with st.expander(t("🚀 Die App startet nicht mehr", "🚀 The app does not start")):
            st.markdown(t(
                "1. Das schwarze Fenster (Eingabeaufforderung) ganz schließen und die App neu starten\n"
                "2. Hilft das nicht: den Rechner neu starten\n"
                "3. Weiterhin ein Problem: die Fehlermeldung abfotografieren oder abtippen und "
                "zusammen mit dem Statusbericht (unten) an den Support senden\n\n"
                "Die erfassten Daten sind davon nicht betroffen – sie liegen in der Datenbank "
                "und in den Sicherungen.",
                "1. Close the console window completely and start the app again\n"
                "2. If that does not help: restart the computer\n"
                "3. Still a problem: take a photo of the error message and send it together "
                "with the status report (below) to support\n\n"
                "Recorded data is not affected – it is stored in the database and backups."))

        st.markdown("---")
        st.markdown(f"#### {t('Support kontaktieren', 'Contact support')}")
        with st.container(border=True):
            s1, s2 = st.columns(2)
            s1.markdown(f"**{t('E-Mail', 'Email')}:** {SUPPORT_KONTAKT}")
            s2.markdown(f"**{t('Servicezeiten', 'Service hours')}:** {SUPPORT_ZEITEN}")
            st.caption(t(
                "Bitte immer den Statusbericht anhängen und kurz beschreiben, was du getan hast "
                "und was passiert ist. Das spart Rückfragen und damit Zeit auf beiden Seiten.",
                "Please always attach the status report and briefly describe what you did and "
                "what happened. This avoids follow-up questions and saves time on both sides."))

            st.download_button(
                t("📄 Statusbericht für den Support herunterladen",
                  "📄 Download status report for support"),
                data=diagnosebericht().encode("utf-8"),
                file_name=f"status_{datetime.now():%Y-%m-%d_%H-%M}.txt",
                mime="text/plain", use_container_width=True,
            )
            st.caption(t(
                "Der Bericht enthält technische Angaben zu Version, Datenbank und Sicherungen – "
                "keine Namen, Arbeitszeiten oder Passwörter.",
                "The report contains technical details about version, database and backups – "
                "no names, working times or passwords."))

        st.caption(f"MeineZeit · Version {APP_VERSION} ({APP_VERSIONSDATUM})")

    # --- Warnleiste nachträglich füllen ---
    if st.session_state.get("_einstellungen_offen"):
        anzahl = len(st.session_state["_einstellungen_offen"])
        warnleiste.warning(t(
            f"⚠️ Im Reiter „⚙️ Einstellungen“ sind {anzahl} Änderung(en) noch nicht "
            "gespeichert. Ohne Speichern gehen sie verloren.",
            f"⚠️ {anzahl} change(s) in the “⚙️ Settings” tab are not saved yet. "
            "They will be lost unless you save."))
