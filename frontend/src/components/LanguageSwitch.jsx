import { LANGS, lang, setLang, t } from '../i18n'

/** Sprachauswahl (lädt die Seite in der gewählten Sprache neu). */
export default function LanguageSwitch({ compact }) {
  return (
    <label className={`lang-switch ${compact ? 'compact' : ''}`} title={t('Sprache')}>
      <span aria-hidden="true">🌐</span>
      <select value={lang} onChange={(e) => setLang(e.target.value)} aria-label={t('Sprache')}>
        {Object.entries(LANGS).map(([code, l]) => <option key={code} value={code}>{l.label}</option>)}
      </select>
    </label>
  )
}
