# 🔒 Produktionsboard - Sicherheits Konfiguration

## Wichtig: Setup für Produktion

Dieses Projekt verwendet Umgebungsvariablen (`.env`) zum Schutz von Secrets. **Bevor Sie das System starten**, müssen Sie Schritt 1-3 durchführen.

### 1️⃣  `.env`-Datei erstellen

```bash
# Kopiere die Beispiel-Datei
cp .env.example .env

# Öffne .env und ersetze alle Placeholder-Werte:
# FLASK_SECRET_KEY=<neuer_sicherer_Schlüssel>
# SMTP_PASSWORD=<dein_echtes_Passwort>
# RESET_LINK_DOMAIN=<deine_produktions_domain>
```

⚠️ **Wichtig**: 
- Nutze einen sicheren Random-String für `FLASK_SECRET_KEY` (mind. 32 Zeichen)
- `.env` wird durch `.gitignore` geschützt und sollte **NICHT** in Git eingecheckt werden
- **Nie** `.env` in Quellcode-Repos teilen

### 2️⃣  Abhängigkeiten installieren

```bash
pip install -r requirements.txt
```

Neu hinzugefügte Packages:
- `python-dotenv`: Lädt `.env`-Variablen
- `Flask-WTF`: CSRF-Protection für Formulare
- `waitress`: WSGI-Server (für Production)

### 3️⃣  Server starten

**Optionen:**
```bash
# Option A: Mit Flask (Dev/Test)
python app.py

# Option B: Mit Waitress (Production recommended) 
python start_server.py

# Option C: Über Windows Batch
./Server\ -Autostart.bat
```

---

## 🔐 Sicherheits-Verbesserungen (P0)

✅ **Umgesetzt:**
- Secrets entfernt und zu `.env` ausgelagert
- CSRF-Protection aktiviert (`Flask-WTF`)
- Secret Key dynamisch geladen
- SMTP-Credentials verschlüsselt
- `web.config`: `allowDoubleEscaping=false` (XSS-Prevention)
- `.gitignore`: `.env` und `*.db` ausgeschlossen

✋ **Noch TODO (mittelfristig):**
- Input-Validierung verstärken
- Rate-Limiting auf Login/Reset
- HTTPS erzwingen
- SQL-Injection-risiken prüfen
- Security-Header hinzufügen (HSTS, X-Frame-Options, CSP)

---

## 📋 Neue DB-Tabelle: `announcements`

Die `announcements`-Tabelle wurde zu `init_db()` hinzugefügt. Beim Start werden fehlende Tabellen automatisch erstellt.

**Schema:**
```sql
CREATE TABLE announcements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    content TEXT,
    source TEXT,
    attachment_path TEXT,
    expires_at DATETIME,
    created_by INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(created_by) REFERENCES users(id)
)
```

---

## 🚀 Deploy-Checkliste

- [ ] `.env` mit echten Werten erstellt
- [ ] `pip install -r requirements.txt` ausgeführt
- [ ] Server lokal getestet
- [ ] IIS/web.config angepasst (falls Windows Server)
- [ ] `.gitignore` vor Git-Push geprüft
- [ ] Backups der aktuellen `users.db` erstellt

---

## 📞 Support

Bei Fragen zu den Sicherheits-Updates siehe den Changelog in diesem Repository.
