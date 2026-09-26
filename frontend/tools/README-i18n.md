# Mehrsprachigkeit (i18n)

Die Oberfläche ist deutsch geschrieben; **Schlüssel ist der deutsche Originaltext**:

```jsx
import { t } from '../i18n'
<button>{t('Firewall-Regel hinzufügen')}</button>
t('Regel „{0}“ bearbeiten', rule.name)   // Platzhalter {0}, {1} …
```

Übersetzungen liegen in `src/i18n/<code>.js` (`{ 'Deutscher Text': 'Übersetzung' }`), registriert in `LANGS` in
`src/i18n/index.js`. Fehlt ein Eintrag, erscheint der deutsche Text. Die Sprache wird beim Laden gewählt
(localStorage `fwm.lang`, sonst Browsersprache); der Umschalter lädt die Seite neu.

## Neue Texte

1. Text in `t('…')` einpacken (auch Fehlermeldungen: `throw new Error(t('…'))`).
2. `npm run i18n:check` zeigt je Sprache fehlende Einträge, unbenutzte Einträge und abweichende Platzhalter.
3. Übersetzung in `src/i18n/en.js` ergänzen (oder als JSON-Datei mit `npm run i18n:merge -- en datei.json`).

Nicht übersetzen: Datenwerte der Firewall-APIs (`'Enable'`, `'Accept'`, XML-Feldnamen …), Objektnamen, Werte von
`<option>` ohne `value`-Attribut. `npm run i18n:shadow` findet `t(…)`-Aufrufe, bei denen eine lokale Variable `t`
die Übersetzungsfunktion verdeckt.

## Weitere Sprache hinzufügen

1. `src/i18n/fr.js` anlegen: `export default { … }` – am einfachsten `en.js` kopieren und die Werte übersetzen
   (die Schlüssel bleiben deutsch).
2. In `src/i18n/index.js` importieren und in `LANGS` eintragen (`fr: { label: 'Français', locale: 'fr-FR', dict: fr }`).
3. `npm run i18n:check` muss für die neue Sprache „0 fehlen“ melden.

## Texte aus dem Backend

Feste Meldungen (HTTPException mit festem Text), Objekttyp-/Bereichsnamen, Rechte und Beschreibungen der eingebauten
Rollen übersetzt das Frontend beim Anzeigen (`api()` übersetzt Fehlermeldungen). Die Liste steht in
`tools/i18n-backend-keys.json`; neu erzeugen (im Projektordner):

```bash
docker compose exec -T backend python - > frontend/tools/i18n-backend-keys.json <<'PY'
import ast, pathlib, json
out = set()
for f in pathlib.Path('app').rglob('*.py'):
    for n in ast.walk(ast.parse(f.read_text())):
        if isinstance(n, ast.Call) and getattr(n.func, 'id', None) == 'HTTPException' and len(n.args) >= 2 \
                and isinstance(n.args[1], ast.Constant) and isinstance(n.args[1].value, str):
            out.add(n.args[1].value)
from app.sophos import entities
from app import permissions
for e, label, sec in entities.XML_MANAGED + entities.REST_MANAGED:
    out |= {label, sec}
out |= set(permissions.PERMISSIONS.values()) | {d for _, d, _ in permissions.BUILTIN_ROLES}
print(json.dumps(sorted(out), ensure_ascii=False, indent=1))
PY
```

Das Backend übersetzt seine Meldungen selbst (siehe `backend/app/i18n.py`, Wörterbuch `backend/app/locales/<code>.json`,
Prüfung `python backend/tools/i18n_check.py`) anhand von `Accept-Language`. Benachrichtigungen gehen in der Sprache, die der
Empfänger zuletzt in der Oberfläche gewählt hat; Teams/Slack und Ausroll-Protokolle in der Standardsprache (Einstellungen).

Weitere Sprache im Backend: `backend/app/locales/<code>.json` anlegen (Kopie von `en.json`, Werte übersetzen) und den Code in
`LANGS` in `backend/app/i18n.py` ergänzen.
