import { useState } from 'react'
import { api } from '../api'
import { ErrorBox } from './ui'
import { t } from '../i18n'

const KIND = { endpoint: t("Pfad-Variante"), undocumented: t("Nicht dokumentiert") }

/** Probelauf: ausschließlich lesende Aufrufe, Ergebnis als Prüfliste. */
export default function Diagnose({ path, intro }) {
  const [result, setResult] = useState(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const run = async () => {
    setBusy(true)
    setError('')
    try { setResult(await api(path, { method: 'POST' })) } catch (e) { setError(e.message) }
    setBusy(false)
  }
  return (
    <div className="stack">
      <div className="row">
        <button onClick={run} disabled={busy}>{busy ? t("Probelauf läuft …") : t("Probelauf starten")}</button>
        <span className="muted small">{intro || t("Nur lesende Aufrufe – an der Konfiguration wird nichts geändert.")}</span>
      </div>
      <ErrorBox error={error} />
      {result && (
        <>
          <div className={`alert ${result.ok ? 'ok' : 'error'} small`}>
            {result.passed} {t("Prüfung(en) bestanden")}{result.failed ? `, ${result.failed} fehlgeschlagen` : ''}.
          </div>
          <div className="table-wrap">
            <table>
              <thead><tr><th /><th>{t("Prüfung")}</th><th>{t("Aufruf")}</th><th>{t("Ergebnis")}</th></tr></thead>
              <tbody>
                {result.steps.map((s, i) => (
                  <tr key={i}>
                    <td>{s.ok === true ? <span className="text-ok">✓</span> : s.ok === false ? <span className="text-error">✗</span> : <span className="muted">i</span>}</td>
                    <td>{s.name}{KIND[s.kind] && <div><span className="badge b-info">{KIND[s.kind]}</span></div>}</td>
                    <td className="mono small">{s.method} {s.path}</td>
                    <td className={`small ${s.ok === false ? 'text-error' : ''}`}>{s.detail}{s.ms != null && <span className="muted"> · {s.ms} {t("ms")}</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  )
}
