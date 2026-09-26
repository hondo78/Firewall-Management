import { useState } from 'react'
import { useAuth } from '../App'
import { api, setToken } from '../api'
import { ErrorBox, Field, Modal } from './ui'
import { t } from '../i18n'

/** Erneute Anmeldung vor sensiblen Aktionen (Genehmigen) – danach wird die Aktion wiederholt. */
export function ReauthModal({ onDone, onClose }) {
  const { me } = useAuth()
  const [password, setPassword] = useState('')
  const [code, setCode] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  if (me.auth_source === 'oidc') {
    return (
      <Modal title={t("Bitte erneut anmelden")} onClose={onClose}>
        <div className="stack">
          <div className="muted">{t("Vor dem Genehmigen ist eine frische Anmeldung nötig. Sie werden zum Identity Provider weitergeleitet.")}</div>
          <div className="modal-foot"><button onClick={onClose}>{t("Abbrechen")}</button>
            <button className="primary" onClick={() => { window.location.href = '/api/auth/oidc/login' }}>{t("Über SSO neu anmelden")}</button></div>
        </div>
      </Modal>
    )
  }
  const submit = async (e) => {
    e.preventDefault()
    setBusy(true)
    setError('')
    try {
      const r = await api('/auth/reauth', { method: 'POST', body: { password, code } })
      setToken(r.token)
      onDone()
    } catch (err) { setError(err.message) } finally { setBusy(false) }
  }
  return (
    <Modal title={t("Bitte erneut anmelden")} onClose={onClose}>
      <form className="stack" onSubmit={submit}>
        <div className="muted small">{t("Ihre Anmeldung liegt länger zurück. Zur Bestätigung der Genehmigung bitte Passwort")}{me.totp_enabled ? t(" und Code") : ''} {t("eingeben.")}</div>
        <Field label={t("Passwort")}><input type="password" autoFocus value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" /></Field>
        {me.totp_enabled && <Field label={t("Code aus der Authenticator-App")}><input inputMode="numeric" value={code} onChange={(e) => setCode(e.target.value)} autoComplete="one-time-code" /></Field>}
        <ErrorBox error={error} />
        <div className="modal-foot"><button type="button" onClick={onClose}>{t("Abbrechen")}</button>
          <button className="primary" disabled={busy || !password}>{t("Bestätigen")}</button></div>
      </form>
    </Modal>
  )
}
