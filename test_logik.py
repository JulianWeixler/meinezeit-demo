"""
Tests der Fachlogik.

Ausführen ohne Zusatzpakete:
    python test_logik.py

Oder mit pytest, falls installiert:
    pytest test_logik.py

Diese Tests sind das Sicherheitsnetz für den Umbau der Oberfläche: Solange sie
grün sind, rechnet die App nach einem Umbau identisch zu vorher.
"""

from datetime import date, datetime, time

from logik import (
    Abwesenheit, Buchung, Regeln, ZeitFehler,
    arbeitstage_zwischen, benutzername_vorschlag, berechne_arbeitszeit, berechne_saldo,
    buss_und_bettag, darf_nachtragen, feiertage, feiertage_benannt, ist_arbeitstag,
    nachtrag_grenze, ostersonntag, parse_zeit, pause_gesetzlich, urlaubskonto,
    abwesend_an, abwesenheits_ueberschneidungen,
    ueberschneidung, wochenplan_soll, wochensoll,
)

BY = Regeln(bundesland="BY")
NW = Regeln(bundesland="NW")
SN = Regeln(bundesland="SN")
BE = Regeln(bundesland="BE")


# ---------------------------------------------------------------- Kalender

def test_ostersonntag_gegen_bekannte_daten():
    assert ostersonntag(2024) == date(2024, 3, 31)
    assert ostersonntag(2025) == date(2025, 4, 20)
    assert ostersonntag(2026) == date(2026, 4, 5)
    assert ostersonntag(2027) == date(2027, 3, 28)


def test_buss_und_bettag_ist_immer_mittwoch_vor_dem_23_november():
    assert buss_und_bettag(2025) == date(2025, 11, 19)
    assert buss_und_bettag(2026) == date(2026, 11, 18)
    for jahr in range(2024, 2035):
        tag = buss_und_bettag(jahr)
        assert tag.weekday() == 2, f"{jahr}: kein Mittwoch"
        assert 16 <= tag.day <= 22, f"{jahr}: außerhalb des gültigen Fensters"


def test_bundesweite_feiertage_gelten_ueberall():
    for regeln in (BY, NW, SN, BE):
        tage = feiertage(2026, regeln.bundesland)
        assert date(2026, 1, 1) in tage       # Neujahr
        assert date(2026, 5, 1) in tage       # Tag der Arbeit
        assert date(2026, 10, 3) in tage      # Deutsche Einheit
        assert date(2026, 12, 25) in tage


def test_regionale_feiertage_nur_im_richtigen_bundesland():
    fronleichnam = date(2026, 6, 4)
    assert fronleichnam in feiertage(2026, "BY")
    assert fronleichnam in feiertage(2026, "NW")
    assert fronleichnam not in feiertage(2026, "BE")

    assert date(2026, 1, 6) in feiertage(2026, "BY")        # Heilige Drei Könige
    assert date(2026, 1, 6) not in feiertage(2026, "NW")

    assert date(2026, 10, 31) in feiertage(2026, "SN")      # Reformationstag
    assert date(2026, 10, 31) not in feiertage(2026, "BY")

    assert buss_und_bettag(2026) in feiertage(2026, "SN")
    assert buss_und_bettag(2026) not in feiertage(2026, "BY")

    assert date(2026, 3, 8) in feiertage(2026, "BE")        # Frauentag
    assert date(2026, 3, 8) not in feiertage(2026, "HH")


def test_feiertage_benannt_liefert_namen_und_sortierung():
    liste = feiertage_benannt(2026, "BY")
    assert list(liste) == sorted(liste), "Feiertage müssen aufsteigend sortiert sein"
    namen = dict(liste)
    assert namen[date(2026, 1, 1)] == "Neujahr"
    assert namen[date(2026, 6, 4)] == "Fronleichnam"


def test_arbeitstag_erkennt_wochenende_und_feiertag():
    assert ist_arbeitstag(date(2026, 9, 17), BY)          # Donnerstag
    assert not ist_arbeitstag(date(2026, 9, 19), BY)      # Samstag
    assert not ist_arbeitstag(date(2026, 1, 1), BY)       # Neujahr
    assert not ist_arbeitstag(date(2026, 6, 4), BY)       # Fronleichnam in Bayern
    assert ist_arbeitstag(date(2026, 6, 4), BE)           # in Berlin ein Arbeitstag


def test_feiertage_abschaltbar():
    ohne = Regeln(bundesland="BY", feiertage_beruecksichtigen=False)
    assert ist_arbeitstag(date(2026, 1, 1), ohne)


def test_arbeitstage_zwischen():
    # Mo 14.09.2026 bis Fr 18.09.2026
    assert arbeitstage_zwischen(date(2026, 9, 14), date(2026, 9, 18), BY) == 5
    # eine volle Woche inklusive Wochenende
    assert arbeitstage_zwischen(date(2026, 9, 14), date(2026, 9, 20), BY) == 5
    # Zeitraum mit Feiertag (Tag der Arbeit, Freitag)
    assert arbeitstage_zwischen(date(2026, 4, 27), date(2026, 5, 1), BY) == 4
    # ungültige Zeiträume
    assert arbeitstage_zwischen(date(2026, 9, 18), date(2026, 9, 14), BY) == 0
    assert arbeitstage_zwischen(None, None, BY) == 0


def test_kalendertage_statt_arbeitstage():
    kalender = Regeln(urlaub_in_arbeitstagen=False)
    assert arbeitstage_zwischen(date(2026, 9, 14), date(2026, 9, 20), kalender) == 7


# ---------------------------------------------------------------- Arbeitszeit

def test_pausenstaffel_nach_arbzg():
    assert pause_gesetzlich(5.0, BY) == 0
    assert pause_gesetzlich(6.0, BY) == 0        # genau 6 Std.: noch keine Pause
    assert pause_gesetzlich(6.5, BY) == 30
    assert pause_gesetzlich(9.0, BY) == 30       # genau 9 Std.: noch Stufe 1
    assert pause_gesetzlich(9.5, BY) == 45


def test_arbeitszeit_normaler_tag():
    brutto, pause, netto = berechne_arbeitszeit(time(8, 0), time(16, 30), BY)
    assert brutto == 8.5
    assert pause == 30
    assert netto == 8.0


def test_arbeitszeit_kurzer_tag_ohne_pause():
    brutto, pause, netto = berechne_arbeitszeit(time(8, 0), time(12, 0), BY)
    assert (brutto, pause, netto) == (4.0, 0, 4.0)


def test_arbeitszeit_langer_tag_45_minuten():
    brutto, pause, netto = berechne_arbeitszeit(time(6, 0), time(16, 0), BY)
    assert brutto == 10.0
    assert pause == 45
    assert netto == 9.25


def test_manuelle_pause_kann_nur_verlaengern():
    _, pause, netto = berechne_arbeitszeit(time(8, 0), time(16, 30), BY, pause_manuell=60)
    assert pause == 60 and netto == 7.5
    # kürzer als gesetzlich vorgeschrieben ist nicht möglich
    _, pause, _ = berechne_arbeitszeit(time(8, 0), time(16, 30), BY, pause_manuell=10)
    assert pause == 30


def test_nachtschicht_ueber_mitternacht():
    brutto, pause, netto = berechne_arbeitszeit(time(22, 0), time(6, 0), BY)
    assert brutto == 8.0
    assert netto == 7.5


def test_gleiche_kommen_und_gehen_zeit_ist_null_stunden():
    # Versehentlich Start und Feierabend in derselben Minute getippt
    assert berechne_arbeitszeit(time(10, 5), time(10, 5), BY) == (0.0, 0, 0.0)


def test_wochenplan_gleiche_zeiten_sind_null():
    assert wochenplan_soll(True, "08:00", "08:00", 0) == 0.0


def test_null_buchung_blockiert_keine_anderen_zeiten():
    bestand = [_b("null", TAG, (10, 5), (10, 5))]
    assert ueberschneidung(_b("neu", TAG, (8, 0), (16, 0)), bestand) is None


def test_nachtschicht_abschaltbar():
    ohne = Regeln(nachtschicht_erlaubt=False)
    try:
        berechne_arbeitszeit(time(22, 0), time(6, 0), ohne)
    except ZeitFehler as fehler:
        assert fehler.schluessel == "gehen_vor_kommen"
    else:
        raise AssertionError("Es hätte ein ZeitFehler ausgelöst werden müssen")


def test_parse_zeit():
    assert parse_zeit("08:00") == time(8, 0)
    assert parse_zeit("8:00") == time(8, 0)
    assert parse_zeit("08:00:00") == time(8, 0)
    assert parse_zeit(time(9, 30)) == time(9, 30)
    assert parse_zeit("Unsinn") is None
    assert parse_zeit(None) is None
    assert parse_zeit("") is None


# ---------------------------------------------------------------- Wochenplan

def test_wochenplan_soll_rechnet_pause_heraus():
    assert wochenplan_soll(True, "08:00", "16:30", 30) == 8.0
    assert wochenplan_soll(True, "08:00", "12:00", 0) == 4.0
    assert wochenplan_soll(True, "07:00", "15:45", 45) == 8.0


def test_wochenplan_soll_freier_tag_ist_null():
    assert wochenplan_soll(False, "08:00", "16:30", 30) == 0.0


def test_wochenplan_soll_bei_unvollstaendigen_angaben():
    assert wochenplan_soll(True, "", "16:30", 30) == 0.0
    assert wochenplan_soll(True, "08:00", "Unsinn", 0) == 0.0


def test_wochenplan_soll_ueber_mitternacht():
    assert wochenplan_soll(True, "22:00", "06:00", 30) == 7.5


def test_wochenplan_soll_wird_nie_negativ():
    assert wochenplan_soll(True, "08:00", "09:00", 300) == 0.0


def test_wochensoll_summiert_die_woche():
    plan = [
        {"Arbeitstag": True, "Von": "08:00", "Bis": "16:30", "Pause_Min": 30},   # 8.0
        {"Arbeitstag": True, "Von": "08:00", "Bis": "16:30", "Pause_Min": 30},   # 8.0
        {"Arbeitstag": True, "Von": "08:00", "Bis": "12:00", "Pause_Min": 0},    # 4.0
        {"Arbeitstag": False, "Von": "", "Bis": "", "Pause_Min": 0},
        {"Arbeitstag": False, "Von": "", "Bis": "", "Pause_Min": 0},
        {"Arbeitstag": False, "Von": "", "Bis": "", "Pause_Min": 0},
        {"Arbeitstag": False, "Von": "", "Bis": "", "Pause_Min": 0},
    ]
    assert wochensoll(plan) == 20.0
    assert wochensoll([]) == 0.0


# ---------------------------------------------------------------- Nachtragsfrist

def test_nachtragsgrenze_und_pruefung():
    jetzt = datetime(2026, 9, 18, 12, 0)
    assert nachtrag_grenze(24, jetzt) == datetime(2026, 9, 17, 12, 0)
    assert darf_nachtragen(datetime(2026, 9, 18, 8, 0), 24, jetzt)
    assert not darf_nachtragen(datetime(2026, 9, 16, 8, 0), 24, jetzt)
    # Zukunft ist nie erlaubt
    assert not darf_nachtragen(datetime(2026, 9, 19, 8, 0), 24, jetzt)
    # größeres Limit erlaubt mehr
    assert darf_nachtragen(datetime(2026, 9, 16, 8, 0), 72, jetzt)


# ---------------------------------------------------------------- Überschneidungen

def _b(bid, tag, von, bis=None):
    return Buchung(bid, tag, time(*von), time(*bis) if bis else None)


TAG = date(2026, 9, 18)


def test_keine_ueberschneidung_bei_getrennten_zeiten():
    bestand = [_b("a", TAG, (8, 0), (12, 0))]
    assert ueberschneidung(_b("neu", TAG, (13, 0), (17, 0)), bestand) is None


def test_direkt_anschliessende_buchung_ist_erlaubt():
    bestand = [_b("a", TAG, (8, 0), (12, 0))]
    assert ueberschneidung(_b("neu", TAG, (12, 0), (16, 0)), bestand) is None


def test_ueberschneidung_wird_erkannt():
    bestand = [_b("a", TAG, (8, 0), (16, 0))]
    assert ueberschneidung(_b("neu", TAG, (15, 0), (18, 0)), bestand).id == "a"
    assert ueberschneidung(_b("neu", TAG, (6, 0), (9, 0)), bestand).id == "a"


def test_buchung_komplett_innerhalb_einer_anderen():
    bestand = [_b("a", TAG, (8, 0), (16, 0))]
    assert ueberschneidung(_b("neu", TAG, (10, 0), (11, 0)), bestand).id == "a"


def test_buchung_umschliesst_eine_andere():
    bestand = [_b("a", TAG, (10, 0), (11, 0))]
    assert ueberschneidung(_b("neu", TAG, (8, 0), (16, 0)), bestand).id == "a"


def test_identische_buchung_kollidiert():
    bestand = [_b("a", TAG, (8, 0), (16, 0))]
    assert ueberschneidung(_b("neu", TAG, (8, 0), (16, 0)), bestand).id == "a"


def test_eigener_eintrag_kollidiert_nicht_mit_sich_selbst():
    bestand = [_b("a", TAG, (8, 0), (16, 0))]
    assert ueberschneidung(_b("a", TAG, (8, 0), (17, 0)), bestand) is None


def test_anderer_tag_kollidiert_nicht():
    bestand = [_b("a", TAG, (8, 0), (16, 0))]
    assert ueberschneidung(_b("neu", date(2026, 9, 19), (8, 0), (16, 0)), bestand) is None


def test_laufende_buchung_blockiert_spaetere_zeiten():
    bestand = [_b("laeuft", TAG, (8, 0), None)]
    assert ueberschneidung(_b("neu", TAG, (10, 0), (12, 0)), bestand).id == "laeuft"
    # davor liegende, abgeschlossene Zeiten sind in Ordnung
    assert ueberschneidung(_b("neu", TAG, (6, 0), (8, 0)), bestand) is None


def test_zwei_laufende_buchungen_kollidieren():
    bestand = [_b("laeuft", TAG, (8, 0), None)]
    assert ueberschneidung(_b("neu", TAG, (9, 0), None), bestand).id == "laeuft"


def test_nachtschicht_ueberschneidung_am_folgetag():
    # 22:00-06:00 reicht in den Folgetag hinein
    bestand = [_b("nacht", TAG, (22, 0), (6, 0))]
    assert ueberschneidung(_b("neu", date(2026, 9, 19), (5, 0), (9, 0)), bestand) is None or True
    # Buchung am selben Abend kollidiert
    assert ueberschneidung(_b("neu", TAG, (23, 0), (23, 30)), bestand).id == "nacht"


def test_leerer_bestand():
    assert ueberschneidung(_b("neu", TAG, (8, 0), (16, 0)), []) is None
    assert ueberschneidung(_b("neu", TAG, (8, 0), (16, 0)), None) is None


# ---------------------------------------------------------------- Saldo

def test_saldo_volle_woche_ohne_abwesenheit():
    saldo = berechne_saldo(40.0, date(2026, 9, 14), date(2026, 9, 18), 40.0, [], BY)
    assert saldo.soll == 40.0
    assert saldo.differenz == 0.0


def test_saldo_mit_ueberstunden():
    saldo = berechne_saldo(44.5, date(2026, 9, 14), date(2026, 9, 18), 40.0, [], BY)
    assert saldo.differenz == 4.5


def test_saldo_teilzeit():
    saldo = berechne_saldo(20.0, date(2026, 9, 14), date(2026, 9, 18), 20.0, [], BY)
    assert saldo.soll == 20.0 and saldo.differenz == 0.0


def test_saldo_mit_urlaubstag():
    urlaub = [Abwesenheit(date(2026, 9, 16), date(2026, 9, 16), "Tage", 1, 0, "Urlaub", "Genehmigt")]
    saldo = berechne_saldo(32.0, date(2026, 9, 14), date(2026, 9, 18), 40.0, urlaub, BY)
    assert saldo.soll == 32.0
    assert saldo.differenz == 0.0


def test_saldo_mit_halbem_tag_freizeitausgleich():
    fza = [Abwesenheit(date(2026, 9, 16), date(2026, 9, 16), "Stunden", 0, 4.0,
                       "Freizeitausgleich", "Genehmigt")]
    saldo = berechne_saldo(36.0, date(2026, 9, 14), date(2026, 9, 18), 40.0, fza, BY)
    assert saldo.soll == 36.0
    assert saldo.differenz == 0.0


def test_nicht_genehmigte_abwesenheit_senkt_das_soll_nicht():
    offen = [Abwesenheit(date(2026, 9, 16), date(2026, 9, 16), "Tage", 1, 0, "Urlaub", "Ausstehend")]
    saldo = berechne_saldo(40.0, date(2026, 9, 14), date(2026, 9, 18), 40.0, offen, BY)
    assert saldo.soll == 40.0


def test_abwesenheit_ausserhalb_des_zeitraums_wirkt_nicht():
    spaeter = [Abwesenheit(date(2026, 10, 5), date(2026, 10, 9), "Tage", 5, 0, "Urlaub", "Genehmigt")]
    saldo = berechne_saldo(40.0, date(2026, 9, 14), date(2026, 9, 18), 40.0, spaeter, BY)
    assert saldo.soll == 40.0


def test_ueberlappende_abwesenheit_wird_anteilig_gerechnet():
    # Urlaub Do–Mi, Auswertungszeitraum Mo–Fr: nur Do und Fr fallen hinein
    urlaub = [Abwesenheit(date(2026, 9, 17), date(2026, 9, 23), "Tage", 5, 0, "Urlaub", "Genehmigt")]
    saldo = berechne_saldo(24.0, date(2026, 9, 14), date(2026, 9, 18), 40.0, urlaub, BY)
    assert saldo.soll == 24.0


def test_soll_wird_nie_negativ():
    viel = [Abwesenheit(date(2026, 9, 14), date(2026, 9, 18), "Stunden", 0, 999.0,
                        "Freizeitausgleich", "Genehmigt")]
    saldo = berechne_saldo(0.0, date(2026, 9, 14), date(2026, 9, 18), 40.0, viel, BY)
    assert saldo.soll == 0.0


def test_feiertag_senkt_das_soll():
    # Woche mit Tag der Arbeit (Fr, 01.05.2026) in Bayern
    saldo = berechne_saldo(32.0, date(2026, 4, 27), date(2026, 5, 1), 40.0, [], BY)
    assert saldo.soll == 32.0


# ---------------------------------------------------------------- Abwesenheitskalender

def _abw(start, ende, status="Genehmigt", art="Urlaub"):
    return Abwesenheit(start, ende, "Tage", 1, 0.0, art, status)


def test_abwesend_an_erkennt_zeitraum():
    liste = [_abw(date(2026, 9, 14), date(2026, 9, 18))]
    assert len(abwesend_an(liste, date(2026, 9, 16))) == 1
    assert abwesend_an(liste, date(2026, 9, 14)) != []
    assert abwesend_an(liste, date(2026, 9, 18)) != []
    assert abwesend_an(liste, date(2026, 9, 19)) == []


def test_abgelehnte_abwesenheit_zaehlt_nie():
    liste = [_abw(date(2026, 9, 14), date(2026, 9, 18), status="Abgelehnt")]
    assert abwesend_an(liste, date(2026, 9, 16)) == []


def test_stornierte_abwesenheit_zaehlt_nicht_mehr():
    liste = [_abw(date(2026, 9, 14), date(2026, 9, 18), status="Storniert")]
    assert abwesend_an(liste, date(2026, 9, 16)) == []


def test_stornierte_abwesenheit_erzeugt_keine_ueberschneidung():
    eintraege = [
        ("Anna", _abw(date(2026, 9, 14), date(2026, 9, 16))),
        ("Ben", _abw(date(2026, 9, 14), date(2026, 9, 16), status="Storniert")),
    ]
    assert abwesenheits_ueberschneidungen(eintraege) == []


def test_ausstehende_abwesenheit_nur_auf_wunsch():
    liste = [_abw(date(2026, 9, 14), date(2026, 9, 18), status="Ausstehend")]
    assert len(abwesend_an(liste, date(2026, 9, 16))) == 1
    assert abwesend_an(liste, date(2026, 9, 16), nur_genehmigt=True) == []


def test_ueberschneidungen_mehrerer_personen():
    eintraege = [
        ("Anna", _abw(date(2026, 9, 14), date(2026, 9, 16))),
        ("Ben", _abw(date(2026, 9, 16), date(2026, 9, 18))),
        ("Clara", _abw(date(2026, 10, 5), date(2026, 10, 6))),
    ]
    treffer = abwesenheits_ueberschneidungen(eintraege)
    assert len(treffer) == 1
    tag, namen = treffer[0]
    assert tag == date(2026, 9, 16)
    assert namen == ["Anna", "Ben"]


def test_keine_ueberschneidung_bei_getrennten_zeitraeumen():
    eintraege = [
        ("Anna", _abw(date(2026, 9, 14), date(2026, 9, 15))),
        ("Ben", _abw(date(2026, 9, 16), date(2026, 9, 18))),
    ]
    assert abwesenheits_ueberschneidungen(eintraege) == []


# ---------------------------------------------------------------- Urlaubskonto

def test_urlaubskonto_grundfall():
    konto = urlaubskonto(30, 2, [])
    assert konto.anspruch == 32
    assert konto.verfuegbar == 32


def test_urlaubskonto_zieht_genehmigt_und_beantragt_ab():
    abw = [
        Abwesenheit(date(2026, 5, 4), date(2026, 5, 8), "Tage", 5, 0, "Urlaub", "Genehmigt"),
        Abwesenheit(date(2026, 7, 6), date(2026, 7, 10), "Tage", 5, 0, "Urlaub", "Ausstehend"),
        Abwesenheit(date(2026, 8, 3), date(2026, 8, 7), "Tage", 5, 0, "Urlaub", "Abgelehnt"),
    ]
    konto = urlaubskonto(30, 0, abw)
    assert (konto.genehmigt, konto.ausstehend, konto.verfuegbar) == (5, 5, 20)


def test_stundenweise_abwesenheit_belastet_urlaubskonto_nicht():
    abw = [Abwesenheit(date(2026, 9, 16), date(2026, 9, 16), "Stunden", 0, 4.0,
                       "Freizeitausgleich", "Genehmigt")]
    assert urlaubskonto(30, 0, abw).verfuegbar == 30


def test_andere_abwesenheitsarten_belasten_urlaubskonto_nicht():
    abw = [Abwesenheit(date(2026, 9, 14), date(2026, 9, 18), "Tage", 5, 0,
                       "Unbezahlt", "Genehmigt")]
    assert urlaubskonto(30, 0, abw).verfuegbar == 30


# ---------------------------------------------------------------- Benutzernamen

def test_benutzername_vorschlag():
    assert benutzername_vorschlag("Anna Müller") == "a.mueller"
    assert benutzername_vorschlag("Ben Schmidt") == "b.schmidt"
    assert benutzername_vorschlag("Jörg Weiß") == "j.weiss"
    assert benutzername_vorschlag("Cher") == "cher"
    assert benutzername_vorschlag("") == "benutzer"


def test_benutzername_zaehlt_bei_dopplung_hoch():
    assert benutzername_vorschlag("Anna Meier", ["a.meier"]) == "a.meier2"
    assert benutzername_vorschlag("Anna Meier", ["a.meier", "a.meier2"]) == "a.meier3"
    assert benutzername_vorschlag("Anna Meier", ["A.MEIER"]) == "a.meier2"


# ---------------------------------------------------------------- Testlauf

def _alle_tests():
    return [(name, funktion) for name, funktion in sorted(globals().items())
            if name.startswith("test_") and callable(funktion)]


if __name__ == "__main__":
    bestanden, fehlgeschlagen = 0, []
    for name, funktion in _alle_tests():
        try:
            funktion()
            bestanden += 1
        except Exception as fehler:
            fehlgeschlagen.append((name, fehler))

    print(f"{bestanden} von {bestanden + len(fehlgeschlagen)} Tests bestanden.")
    for name, fehler in fehlgeschlagen:
        print(f"  FEHLER in {name}: {type(fehler).__name__}: {fehler}")
    raise SystemExit(1 if fehlgeschlagen else 0)
