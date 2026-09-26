/**
 * Mehrsprachigkeit ohne Zusatzbibliothek.
 *
 * Schlüssel ist der deutsche Originaltext: t('Firewall-Regel hinzufügen'). Deutsch braucht daher kein Wörterbuch;
 * jede weitere Sprache ist eine Datei „<code>.js“ mit { 'Deutscher Text': 'Übersetzung' } und ein Eintrag in LANGS.
 * Platzhalter: t('Regel „{0}“ bearbeiten', name). Fehlende Übersetzungen fallen auf Deutsch zurück
 * (Prüfung: npm run i18n:check).
 *
 * Die Sprache wird beim Laden festgelegt (localStorage, sonst Browsersprache); ein Wechsel lädt die Seite neu.
 * So funktionieren auch Texte in Konstanten auf Modulebene.
 */
import en from './en'

export const LANGS = {
  de: { label: 'Deutsch', locale: 'de-DE', dict: null },
  en: { label: 'English', locale: 'en-GB', dict: en },
}

const KEY = 'fwm.lang'

function detect() {
  try {
    const saved = localStorage.getItem(KEY)
    if (saved && LANGS[saved]) return saved
  } catch { /* privater Modus */ }
  const nav = (typeof navigator !== 'undefined' && navigator.language ? navigator.language : 'de').slice(0, 2).toLowerCase()
  return LANGS[nav] ? nav : 'de'
}

export const lang = detect()
export const locale = LANGS[lang].locale
const dict = LANGS[lang].dict
if (typeof document !== 'undefined') document.documentElement.lang = lang

/** Übersetzt einen deutschen Text; {0}, {1} … werden durch die weiteren Argumente ersetzt. */
export function t(text, ...args) {
  let s = (dict && dict[text]) || text
  if (args.length) s = s.replace(/\{(\d+)\}/g, (m, i) => (args[i] ?? ''))
  return s
}

export function setLang(code) {
  if (!LANGS[code] || code === lang) return
  try { localStorage.setItem(KEY, code) } catch { /* privater Modus */ }
  // Angemeldet: Sprache auch am Benutzer speichern (für Benachrichtigungen), danach neu laden
  let token = null
  try { token = localStorage.getItem('fwm_token') } catch { /* privater Modus */ }
  const save = token ? fetch('/api/auth/language', { method: 'PUT', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify({ language: code }) }).catch(() => {}) : Promise.resolve()
  save.finally(() => window.location.reload())
}
