"""
Fachlogik der Zeiterfassung – bewusst ohne Streamlit, Pandas oder Datenbank.

Dieses Modul enthält die eigentlichen Regeln des Produkts: Feiertage je Bundesland,
Arbeitszeit- und Pausenberechnung, Arbeitstage, Soll-/Ist-Saldo und Urlaubskonto.

Es darf KEINE Oberflächen- oder Speicher-Abhängigkeiten bekommen. Genau dadurch
bleibt es beim Wechsel der Oberfläche (Streamlit -> Web-App) unverändert nutzbar
und lässt sich ohne laufende App testen.

    from logik import Regeln, berechne_arbeitszeit
    regeln = Regeln(bundesland="BY")
    brutto, pause, netto = berechne_arbeitszeit(time(8, 0), time(17, 0), regeln)
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, time, timedelta
from functools import lru_cache

# ============================================================
# 1. REGELWERK
# ============================================================

BUNDESLAENDER = {
    "BW": "Baden-Württemberg", "BY": "Bayern", "BE": "Berlin", "BB": "Brandenburg",
    "HB": "Bremen", "HH": "Hamburg", "HE": "Hessen", "MV": "Mecklenburg-Vorpommern",
    "NI": "Niedersachsen", "NW": "Nordrhein-Westfalen", "RP": "Rheinland-Pfalz",
    "SL": "Saarland", "SN": "Sachsen", "ST": "Sachsen-Anhalt",
    "SH": "Schleswig-Holstein", "TH": "Thüringen",
}


class ZeitFehler(ValueError):
    """Fachlicher Fehler bei der Zeiterfassung.

    Trägt einen Schlüssel statt eines fertigen Satzes, damit die Oberfläche die
    Meldung in ihrer eigenen Sprache formulieren kann.
    """

    def __init__(self, schluessel: str, text: str = ""):
        self.schluessel = schluessel
        super().__init__(text or schluessel)


@dataclass(frozen=True)
class Regeln:
    """Betriebliche Einstellungen, die in die Berechnung einfließen."""
    bundesland: str = "BY"
    feiertage_beruecksichtigen: bool = True
    urlaub_in_arbeitstagen: bool = True
    nachtschicht_erlaubt: bool = True
    pause_schwelle_1: float = 6.0     # § 4 ArbZG: über 6 Std. -> 30 Min.
    pause_dauer_1: int = 30
    pause_schwelle_2: float = 9.0     # über 9 Std. -> 45 Min.
    pause_dauer_2: int = 45

    @classmethod
    def aus_dict(cls, werte: dict) -> "Regeln":
        """Baut das Regelwerk aus der gespeicherten Konfiguration; Unbekanntes wird ignoriert."""
        bekannt = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in (werte or {}).items() if k in bekannt})


STANDARD_REGELN = Regeln()


# ============================================================
# 2. KALENDER UND FEIERTAGE
# ============================================================

def ostersonntag(jahr: int) -> date:
    """Gaußsche Osterformel."""
    a, b, c = jahr % 19, jahr // 100, jahr % 100
    d, e = b // 4, b % 4
    g = (b - (b + 8) // 25 + 1) // 3
    h = (19 * a + b - d - g + 15) % 30
    i, k = c // 4, c % 4
    l = (32 + 2 * e + 2 * i - h - k) % 7
    m = (a + 11 * h + 22 * l) // 451
    monat = (h + l - 7 * m + 114) // 31
    tag = ((h + l - 7 * m + 114) % 31) + 1
    return date(jahr, monat, tag)


def buss_und_bettag(jahr: int) -> date:
    """Mittwoch vor dem 23. November."""
    referenz = date(jahr, 11, 23)
    abstand = (referenz.weekday() - 2) % 7 or 7
    return referenz - timedelta(days=abstand)


# Regionale Feiertage: Kürzel -> Länder, in denen sie gelten
_REGIONAL = {
    "Heilige Drei Könige": ("BW", "BY", "ST"),
    "Internationaler Frauentag": ("BE", "MV"),
    "Fronleichnam": ("BW", "BY", "HE", "NW", "RP", "SL"),
    "Mariä Himmelfahrt": ("SL",),
    "Weltkindertag": ("TH",),
    "Reformationstag": ("BB", "HB", "HH", "MV", "NI", "SN", "ST", "SH", "TH"),
    "Allerheiligen": ("BW", "BY", "NW", "RP", "SL"),
    "Buß- und Bettag": ("SN",),
    "Ostersonntag": ("BB",),
    "Pfingstsonntag": ("BB",),
}


@lru_cache(maxsize=256)
def feiertage_benannt(jahr: int, bundesland: str = "BY") -> tuple[tuple[date, str], ...]:
    """Alle gesetzlichen Feiertage des Jahres als (Datum, Name), aufsteigend sortiert."""
    ostern = ostersonntag(jahr)
    bundesweit = {
        date(jahr, 1, 1): "Neujahr",
        ostern - timedelta(days=2): "Karfreitag",
        ostern + timedelta(days=1): "Ostermontag",
        date(jahr, 5, 1): "Tag der Arbeit",
        ostern + timedelta(days=39): "Christi Himmelfahrt",
        ostern + timedelta(days=50): "Pfingstmontag",
        date(jahr, 10, 3): "Tag der Deutschen Einheit",
        date(jahr, 12, 25): "1. Weihnachtstag",
        date(jahr, 12, 26): "2. Weihnachtstag",
    }
    regional = {
        "Heilige Drei Könige": date(jahr, 1, 6),
        "Internationaler Frauentag": date(jahr, 3, 8),
        "Ostersonntag": ostern,
        "Pfingstsonntag": ostern + timedelta(days=49),
        "Fronleichnam": ostern + timedelta(days=60),
        "Mariä Himmelfahrt": date(jahr, 8, 15),
        "Weltkindertag": date(jahr, 9, 20),
        "Reformationstag": date(jahr, 10, 31),
        "Allerheiligen": date(jahr, 11, 1),
        "Buß- und Bettag": buss_und_bettag(jahr),
    }
    treffer = dict(bundesweit)
    for name, tag in regional.items():
        if bundesland in _REGIONAL.get(name, ()):
            treffer[tag] = name
    return tuple(sorted(treffer.items()))


@lru_cache(maxsize=256)
def feiertage(jahr: int, bundesland: str = "BY") -> frozenset:
    """Gesetzliche Feiertage als Menge von Datumswerten."""
    return frozenset(tag for tag, _ in feiertage_benannt(jahr, bundesland))


def ist_feiertag(tag: date, regeln: Regeln = STANDARD_REGELN) -> bool:
    return regeln.feiertage_beruecksichtigen and tag in feiertage(tag.year, regeln.bundesland)


def ist_arbeitstag(tag: date, regeln: Regeln = STANDARD_REGELN) -> bool:
    """Montag bis Freitag, sofern kein gesetzlicher Feiertag."""
    if tag.weekday() >= 5:
        return False
    return not ist_feiertag(tag, regeln)


def arbeitstage_zwischen(von: date, bis: date, regeln: Regeln = STANDARD_REGELN) -> int:
    """Arbeitstage inklusive Start- und Enddatum."""
    if von is None or bis is None or bis < von:
        return 0
    if not regeln.urlaub_in_arbeitstagen:
        return (bis - von).days + 1
    return sum(1 for i in range((bis - von).days + 1)
               if ist_arbeitstag(von + timedelta(days=i), regeln))


# ============================================================
# 3. ARBEITSZEIT UND PAUSEN
# ============================================================

def pause_gesetzlich(brutto_stunden: float, regeln: Regeln = STANDARD_REGELN) -> int:
    """Gesetzliche Mindestpause in Minuten (Vorgabe nach § 4 ArbZG)."""
    if brutto_stunden > regeln.pause_schwelle_2:
        return int(regeln.pause_dauer_2)
    if brutto_stunden > regeln.pause_schwelle_1:
        return int(regeln.pause_dauer_1)
    return 0


def berechne_arbeitszeit(kommen: time, gehen: time, regeln: Regeln = STANDARD_REGELN,
                         pause_manuell: int | None = None) -> tuple[float, int, float]:
    """(Brutto-Stunden, Pause in Minuten, Netto-Stunden).

    Liegt die Gehen-Zeit vor der Kommen-Zeit, wird eine Schicht über Mitternacht
    angenommen – sofern das Regelwerk das erlaubt.
    """
    basis = date(2000, 1, 1)
    t_kommen = datetime.combine(basis, kommen)
    t_gehen = datetime.combine(basis, gehen)
    # Gleiche Zeiten sind KEINE Schicht über Mitternacht, sondern null Stunden.
    # Live-Stempeln speichert minutengenau: Wer versehentlich "Start" und in
    # derselben Minute "Feierabend" tippt, bekäme sonst 23,25 Stunden gebucht.
    if t_gehen == t_kommen:
        return 0.0, 0, 0.0
    if t_gehen < t_kommen:
        if not regeln.nachtschicht_erlaubt:
            raise ZeitFehler("gehen_vor_kommen", "Die Gehen-Zeit muss nach der Kommen-Zeit liegen.")
        t_gehen += timedelta(days=1)

    brutto = (t_gehen - t_kommen).total_seconds() / 3600.0
    if brutto > 24:
        raise ZeitFehler("zu_lang", "Die erfasste Zeitspanne ist länger als 24 Stunden.")

    pause = pause_gesetzlich(brutto, regeln)
    if pause_manuell is not None:
        pause = max(pause, int(pause_manuell))   # gesetzliche Pause ist die Untergrenze
    netto = max(0.0, brutto - pause / 60.0)
    return round(brutto, 2), pause, round(netto, 2)


def parse_zeit(wert) -> time | None:
    """Robustes Einlesen von 'HH:MM' oder 'HH:MM:SS'."""
    if isinstance(wert, time):
        return wert
    if isinstance(wert, datetime):
        return wert.time()
    if not isinstance(wert, str):
        return None
    for fmt in ("%H:%M", "%H:%M:%S"):
        try:
            return datetime.strptime(wert.strip(), fmt).time()
        except ValueError:
            continue
    return None


def wochenplan_soll(arbeitstag: bool, von, bis, pause_minuten: float = 0) -> float:
    """Sollstunden eines Wochentags aus Beginn, Ende und Pause.

    Wird für den Wochenarbeitszeitkalender verwendet: Die Sollzeit wird immer
    gerechnet und nie eingetippt, damit Plan und Berechnung nicht auseinanderlaufen.
    """
    if not arbeitstag:
        return 0.0
    start, ende = parse_zeit(von), parse_zeit(bis)
    if start is None or ende is None:
        return 0.0
    basis = date(2000, 1, 1)
    beginn_dt = datetime.combine(basis, start)
    ende_dt = datetime.combine(basis, ende)
    if ende_dt == beginn_dt:                       # gleiche Zeit = kein Arbeitstag
        return 0.0
    if ende_dt < beginn_dt:                        # Schicht über Mitternacht
        ende_dt += timedelta(days=1)
    brutto = (ende_dt - beginn_dt).total_seconds() / 3600.0
    netto = brutto - max(0.0, float(pause_minuten or 0)) / 60.0
    return round(max(0.0, netto), 2)


def wochensoll(plan: list) -> float:
    """Summe der Sollstunden einer Woche; erwartet Einträge mit den Feldern des Wochenplans."""
    summe = 0.0
    for eintrag in plan or []:
        summe += wochenplan_soll(eintrag.get("Arbeitstag", False), eintrag.get("Von"),
                                 eintrag.get("Bis"), eintrag.get("Pause_Min", 0))
    return round(summe, 2)


@dataclass
class Buchung:
    """Eine Zeitbuchung, unabhängig von der Speicherform."""
    id: str
    datum: date
    kommen: time
    gehen: time | None = None      # None = laufende Buchung ohne Ende
    netto: float = 0.0             # bezahlte Stunden ohne Pause


def _zeitfenster(buchung: Buchung, nachtschicht_erlaubt: bool = True):
    """Start und Ende als Zeitpunkte. Schichten über Mitternacht enden am Folgetag."""
    if buchung.datum is None or buchung.kommen is None:
        return None, None
    start = datetime.combine(buchung.datum, buchung.kommen)
    if buchung.gehen is None:
        return start, None
    ende = datetime.combine(buchung.datum, buchung.gehen)
    # Gleiche Zeiten ergeben ein leeres Fenster statt eines ganzen Tages –
    # sonst würde eine versehentliche Null-Buchung alles blockieren
    if ende < start and nachtschicht_erlaubt:
        ende += timedelta(days=1)
    return start, ende


def ueberschneidung(neu: Buchung, bestehende: list, nachtschicht_erlaubt: bool = True):
    """Prüft, ob sich eine Buchung mit einer bestehenden überschneidet.

    Gibt die erste kollidierende Buchung zurück oder None. Eine laufende Buchung
    ohne Ende gilt als offen und kollidiert mit allem, was danach beginnt.
    Buchungen, die exakt aneinander anschließen (Ende = Beginn), sind erlaubt.
    """
    neu_start, neu_ende = _zeitfenster(neu, nachtschicht_erlaubt)
    if neu_start is None:
        return None
    # Eine Buchung ohne Dauer belegt keine Zeit und kann nichts überschneiden
    if neu_ende is not None and neu_ende == neu_start:
        return None

    for alt in bestehende or []:
        if alt.id == neu.id:
            continue
        alt_start, alt_ende = _zeitfenster(alt, nachtschicht_erlaubt)
        if alt_start is None:
            continue
        if alt_ende is not None and alt_ende == alt_start:
            continue
        # Offene Buchungen: alles ab ihrem Beginn gilt als belegt
        offen_alt = alt_ende is None
        offen_neu = neu_ende is None
        if offen_alt and offen_neu:
            return alt
        if offen_alt:
            if neu_ende > alt_start:
                return alt
            continue
        if offen_neu:
            if neu_start < alt_ende:
                return alt
            continue
        if neu_start < alt_ende and alt_start < neu_ende:
            return alt
    return None


def nachtrag_grenze(limit_stunden: float, jetzt: datetime | None = None) -> datetime:
    """Frühester Zeitpunkt, den jemand noch rückwirkend erfassen oder ändern darf."""
    return (jetzt or datetime.now()) - timedelta(hours=max(0.0, float(limit_stunden)))


def darf_nachtragen(zeitpunkt: datetime, limit_stunden: float,
                    jetzt: datetime | None = None) -> bool:
    jetzt = jetzt or datetime.now()
    return nachtrag_grenze(limit_stunden, jetzt) <= zeitpunkt <= jetzt


# ------------------------------------------------------------
# Arbeitsschutz: Höchstarbeitszeit und Ruhezeit
# ------------------------------------------------------------
# § 3 ArbZG begrenzt die werktägliche Arbeitszeit auf acht Stunden, verlängerbar
# auf zehn. § 5 ArbZG verlangt nach Arbeitsende eine ununterbrochene Ruhezeit.
# Die Grenzwerte sind einstellbar, weil abweichende Tarifregelungen möglich sind.

STANDARD_HOECHSTARBEITSZEIT = 10.0
STANDARD_RUHEZEIT = 11.0


def tagessumme(buchungen: list, tag: date, ausser_id: str = "") -> float:
    """Summe der Nettostunden eines Tages."""
    summe = 0.0
    for b in buchungen or []:
        if ausser_id and b.id == ausser_id:
            continue
        if b.datum == tag:
            summe += float(b.netto or 0.0)
    return round(summe, 2)


def hoechstarbeitszeit_ueberschritten(stunden: float,
                                      grenze: float = STANDARD_HOECHSTARBEITSZEIT) -> float:
    """Überschreitung in Stunden; 0.0, wenn die Grenze eingehalten ist."""
    ueber = round(float(stunden) - float(grenze), 2)
    return ueber if ueber > 0 else 0.0


def ruhezeit_verletzung(neu: Buchung, bestehende: list,
                        mindest_stunden: float = STANDARD_RUHEZEIT,
                        nachtschicht_erlaubt: bool = True):
    """Prüft die Ruhezeit zur vorigen und zur folgenden Buchung.

    Gibt (bestehende Buchung, tatsächliche Ruhezeit in Stunden) zurück, wenn die
    Pause zwischen zwei Schichten kürzer ist als vorgeschrieben – sonst None.
    Überlappungen prüft `ueberschneidung`, hier geht es nur um die Lücke dazwischen.
    """
    neu_start, neu_ende = _zeitfenster(neu, nachtschicht_erlaubt)
    if neu_start is None or neu_ende is None:
        return None
    for alt in bestehende or []:
        if alt.id == neu.id:
            continue
        alt_start, alt_ende = _zeitfenster(alt, nachtschicht_erlaubt)
        if alt_start is None or alt_ende is None or alt_ende == alt_start:
            continue
        if alt_ende <= neu_start:
            luecke = (neu_start - alt_ende).total_seconds() / 3600.0
        elif neu_ende <= alt_start:
            luecke = (alt_start - neu_ende).total_seconds() / 3600.0
        else:
            continue                      # Überlappung, nicht Sache dieser Prüfung
        if luecke + 1e-9 < float(mindest_stunden):
            return alt, round(luecke, 2)
    return None


# ============================================================
# 4. ABWESENHEITEN UND SALDO
# ============================================================

@dataclass
class Abwesenheit:
    """Eine genehmigte oder beantragte Abwesenheit, unabhängig von der Speicherform."""
    start: date
    ende: date
    einheit: str = "Tage"        # "Tage" oder "Stunden"
    tage: int = 0
    stunden: float = 0.0
    art: str = "Urlaub"
    status: str = "Ausstehend"


@dataclass
class Saldo:
    ist: float
    soll: float

    @property
    def differenz(self) -> float:
        return round(self.ist - self.soll, 2)

    def als_tupel(self) -> tuple[float, float, float]:
        return self.ist, self.soll, self.differenz


def abwesenheitstage_im_zeitraum(abwesenheiten: list[Abwesenheit], von: date, bis: date,
                                 regeln: Regeln = STANDARD_REGELN) -> int:
    """Genehmigte ganztägige Abwesenheiten, die in den Zeitraum fallen."""
    tage = 0
    for abw in abwesenheiten:
        if abw.status != "Genehmigt" or abw.einheit != "Tage":
            continue
        if not isinstance(abw.start, date) or not isinstance(abw.ende, date):
            continue
        von_ue, bis_ue = max(abw.start, von), min(abw.ende, bis)
        if von_ue <= bis_ue:
            tage += sum(1 for i in range((bis_ue - von_ue).days + 1)
                        if ist_arbeitstag(von_ue + timedelta(days=i), regeln))
    return tage


def abwesenheitsstunden_im_zeitraum(abwesenheiten: list[Abwesenheit], von: date,
                                    bis: date) -> float:
    """Genehmigte stundenweise Abwesenheiten (z. B. halber Tag Freizeitausgleich)."""
    summe = 0.0
    for abw in abwesenheiten:
        if abw.status != "Genehmigt" or abw.einheit != "Stunden":
            continue
        if isinstance(abw.start, date) and von <= abw.start <= bis:
            summe += float(abw.stunden or 0)
    return round(summe, 2)


def berechne_saldo(ist_stunden: float, von: date, bis: date, wochenstunden: float,
                   abwesenheiten: list[Abwesenheit] | None = None,
                   regeln: Regeln = STANDARD_REGELN) -> Saldo:
    """Soll-/Ist-Vergleich für einen Zeitraum.

    Das Soll ergibt sich aus den Arbeitstagen abzüglich genehmigter Abwesenheiten.
    Stundenweise Abwesenheiten werden direkt vom Soll abgezogen.
    """
    abwesenheiten = abwesenheiten or []
    tagessoll = float(wochenstunden) / 5.0
    arbeitstage = sum(1 for i in range((bis - von).days + 1)
                      if ist_arbeitstag(von + timedelta(days=i), regeln))

    abwesend_tage = abwesenheitstage_im_zeitraum(abwesenheiten, von, bis, regeln)
    abwesend_stunden = abwesenheitsstunden_im_zeitraum(abwesenheiten, von, bis)

    soll = max(0, arbeitstage - abwesend_tage) * tagessoll - abwesend_stunden
    return Saldo(ist=round(float(ist_stunden), 2), soll=round(max(0.0, soll), 2))


@dataclass
class Urlaubskonto:
    anspruch: int
    genehmigt: int
    ausstehend: int

    @property
    def verfuegbar(self) -> int:
        return self.anspruch - self.genehmigt - self.ausstehend

    def als_tupel(self) -> tuple[int, int, int, int]:
        return self.anspruch, self.genehmigt, self.ausstehend, self.verfuegbar


def urlaubskonto(urlaub_pro_jahr: int, resturlaub_vorjahr: int,
                 abwesenheiten: list[Abwesenheit] | None = None) -> Urlaubskonto:
    """Urlaubskonto in Tagen. Stundenweise Abwesenheiten zählen bewusst nicht mit."""
    abwesenheiten = abwesenheiten or []
    relevant = [a for a in abwesenheiten if a.art == "Urlaub" and a.einheit == "Tage"]
    return Urlaubskonto(
        anspruch=int(urlaub_pro_jahr or 0) + int(resturlaub_vorjahr or 0),
        genehmigt=sum(int(a.tage or 0) for a in relevant if a.status == "Genehmigt"),
        ausstehend=sum(int(a.tage or 0) for a in relevant if a.status == "Ausstehend"),
    )


# Status, bei denen eine Abwesenheit nicht mehr zählt. Eine Stornierung wirkt wie
# eine Ablehnung: Der Eintrag bleibt in der Historie sichtbar, belegt den Tag aber
# nicht mehr und gilt nicht als Überschneidung.
STATUS_UNWIRKSAM = frozenset({"Abgelehnt", "Storniert"})


def abwesend_an(abwesenheiten: list, tag: date, nur_genehmigt: bool = False) -> list:
    """Alle Abwesenheiten, die diesen Tag berühren."""
    treffer = []
    for abw in abwesenheiten or []:
        if nur_genehmigt and abw.status != "Genehmigt":
            continue
        if abw.status in STATUS_UNWIRKSAM:
            continue
        if not isinstance(abw.start, date) or not isinstance(abw.ende, date):
            continue
        if abw.start <= tag <= abw.ende:
            treffer.append(abw)
    return treffer


def abwesenheits_ueberschneidungen(eintraege: list) -> list:
    """Findet Tage, an denen sich mehrere Abwesenheiten überlappen.

    `eintraege` sind Paare aus Name und Abwesenheit. Zurück kommt je Tag die Liste
    der betroffenen Namen – Grundlage für die Warnung in der Kalenderübersicht.
    """
    belegung: dict = {}
    for name, abw in eintraege or []:
        if abw.status in STATUS_UNWIRKSAM:
            continue
        if not isinstance(abw.start, date) or not isinstance(abw.ende, date):
            continue
        tag = abw.start
        while tag <= abw.ende:
            belegung.setdefault(tag, set()).add(name)
            tag += timedelta(days=1)
    return sorted((tag, sorted(namen)) for tag, namen in belegung.items() if len(namen) > 1)


# ============================================================
# 5. BENUTZERNAMEN
# ============================================================

_UMLAUTE = {"ä": "ae", "ö": "oe", "ü": "ue", "ß": "ss",
            "Ä": "ae", "Ö": "oe", "Ü": "ue", "é": "e", "è": "e"}


def ohne_umlaute(text: str) -> str:
    text = "".join(_UMLAUTE.get(zeichen, zeichen) for zeichen in str(text))
    return "".join(z for z in text.lower() if z.isalnum() or z.isspace())


def benutzername_vorschlag(name: str, vergeben=()) -> str:
    """Aus 'Anna Müller' wird 'a.mueller'; bei Dopplung mit Zähler."""
    teile = ohne_umlaute(name).split()
    if len(teile) >= 2:
        basis = f"{teile[0][0]}.{teile[-1]}"
    elif teile:
        basis = teile[0]
    else:
        basis = "benutzer"
    vergeben = {str(v).lower() for v in vergeben}
    kandidat, zaehler = basis, 1
    while kandidat in vergeben:
        zaehler += 1
        kandidat = f"{basis}{zaehler}"
    return kandidat
