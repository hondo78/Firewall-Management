import { useState } from 'react'
import { useAuth } from '../App'
import { api, setToken } from '../api'
import { ErrorBox, Field, Modal } from './ui'

/** Erneute Anmeldung vor sensiblen Aktionen (Genehmigen) – danach wird die Aktion wiederholt. */
export function ReauthModal({ onDone, onClose }) {
  const { me } = useAuth()
  const [password, setPassword] = useState('')
  const [code, setCode] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  if (me.auth_source === 'oidc') {
    return (
      <Modal title="Bitte erneut anmelden" onClose={onClose}>
        <div className="stack">
          <div className="muted">Vor dem Genehmigen ist eine frische Anmeldung nötig. Sie werden zum Identity Provider weitergeleitet.</div>
          <div className="modal-foot"><button onClick={onClose}>Abbrechen</button>
            <button className="primary" onClick={() => { window.location.href = '/api/auth/oidc/login' }}>Über SSO neu anmelden</button></div>
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
    <Modal title="Bitte erneut anmelden" onClose={onClose}>
      <form className="stack" onSubmit={submit}>
        <div className="muted small">Ihre Anmeldung liegt länger zurück. Zur Bestätigung der Genehmigung bitte Passwort{me.totp_enabled ? ' und Code' : ''} eingeben.</div>
        <Field label="Passwort"><input type="password" autoFocus value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" /></Field>
        {me.totp_enabled && <Field label="Code aus der Authenticator-App"><input inputMode="numeric" value={code} onChange={(e) => setCode(e.target.value)} autoComplete="one-time-code" /></Field>}
        <ErrorBox error={error} />
        <div className="modal-foot"><button type="button" onClick={onClose}>Abbrechen</button>
          <button className="primary" disabled={busy || !password}>Bestätigen</button></div>
      </form>
    </Modal>
  )
}
