# wp2shell — WordPress SQLi/RCE Testlabor

Dieses Projekt testet die Schwachstellenkette **CVE-2026-63030** (REST `/batch/v1`
Route-Verwechslung) kombiniert mit **CVE-2026-60137** (SQL-Injection in
`WP_Query::author__not_in`) in WordPress 6.9.0–6.9.4 und 7.0.0–7.0.1.

Der Code ist in drei klar getrennte Dateien aufgeteilt.

## Die drei Dateien

### `wp2shell_core.py` — Kernmodul
Enthält die Klasse `Target` mit der gesamten Logik: SQLi-Erkennung (UNION,
Boolean-Differential, Zeit-basiertes Orakel), Admin-Erstellung, Webshell-Upload,
Befehlsausführung und WAF-Bypass-Techniken. Wird von den beiden anderen Dateien
importiert (`from wp2shell_core import Target`). **Wird zwingend benötigt** —
nicht löschen.

### `wp2shell_check.py` — Nur Erkennung
Prüft, ob ein Ziel verwundbar ist, **ohne** etwas zu verändern (rein lesend).
Erkennt automatisch per UNION-Reflektion, Boolean-Differential oder
Zeit-Orakel. Zeigt zusätzlich die WordPress-Versionsvermutung an.

### `wp2shell_rce.py` — Ausnutzung (Exploit)
Führt die komplette Angriffskette aus: Schwachstelle erkennen → Admin-Konto
anlegen → Plugin-Webshell hochladen → Betriebssystembefehle ausführen.
Zwischenspeichert erstellten Admin und Plugin pro Ziel in
`~/.wp2shell/state.json`, damit wiederholte Aufrufe nur eine Anfrage benötigen.

### Docker starten
## Ausführung

Alles wird aus dem Projektordner in PowerShell ausgeführt.

```powershell
cd C:\Users\edu_s\Desktop\LaboratorioWP
```

### WordPress lokal mit Docker starten

Die Compose-Datei startet WordPress und MySQL lokal auf `http://localhost:8080`.

Starten:

```powershell
docker compose up -d
```

Logs ansehen:

```powershell
docker compose logs -f
```

Stoppen:

```powershell
docker compose down
```

Im Browser danach `http://localhost:8080` aufrufen und die erste
WordPress-Einrichtung abschließen. Dabei legst du den WordPress-Admin selbst
fest, zum Beispiel:

- Admin-Benutzername: frei wählbar, z. B. `admin`
- Admin-Passwort: frei wählbar, z. B. ein starkes Testpasswort
- Admin-E-Mail: frei wählbar, z. B. `admin@example.local`

Die Datenbank-Zugangsdaten musst du im Browser normalerweise nicht eingeben,
weil sie bereits in `docker-compose.yml` gesetzt sind:

- Datenbankname: `wordpress_db`
- Datenbank-Benutzer: `wp_user`
- Datenbank-Passwort: `secret_password`
- MySQL-Root-Passwort: `root_password`

Wenn du alles neu initialisieren willst, inklusive Datenbank-Volume:

```powershell
docker compose down -v
docker compose up -d
```
### Ab hier Schwachstelle check und nutzen

### Syntax prüfen

```powershell
python -m py_compile .\wp2shell_core.py .\wp2shell_check.py .\wp2shell_rce.py
```

### Ziel auf Verwundbarkeit prüfen

```powershell
python .\wp2shell_check.py http://localhost:8080
```

Mit Beweis (liest `@@version` und `current_user()`, rein lesend):

```powershell
python .\wp2shell_check.py http://localhost:8080 --proof
```

Alle Optionen anzeigen:

```powershell
python .\wp2shell_check.py --help
```

### Befehle über RCE ausführen

```powershell
python .\wp2shell_rce.py http://localhost:8080 -c "whoami"
python .\wp2shell_rce.py http://localhost:8080 -c "id"
```

Neue Angriffskette erzwingen (statt zwischengespeicherter Shell):

```powershell
python .\wp2shell_rce.py http://localhost:8080 -c "whoami" --fresh
```

### Webshell entfernen und Zustand vergessen

```powershell
python .\wp2shell_rce.py http://localhost:8080 --cleanup
```

## Wichtige Hinweise

- Nur gegen Systeme ausführen, die du selbst kontrollierst.
- Bei entfernten Zielen ist `--authorized` erforderlich (explizite Erlaubnis
  vorausgesetzt).
- Der Zustand (Admin-Zugangsdaten, Plugin-Pfad) wird lokal in
  `~/.wp2shell/state.json` gespeichert.
