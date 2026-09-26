import { useEffect, useState } from 'react'
import { api } from '../api'
import { ErrorBox, Field } from '../components/ui'
import { t } from '../i18n'
import LanguageSwitch from '../components/LanguageSwitch'

export default function Login({ onLogin }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [code, setCode] = useState('')
  const [mfaToken, setMfaToken] = useState(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [sso, setSso] = useState(null)

  useEffect(() => {
    api('/auth/oidc/info').then(setSso).catch(() => {})
    // Rückkehr vom Identity Provider: Einmal-Code gegen Sitzung tauschen
    const q = new URLSearchParams(window.location.search)
    if (q.get('oidc_error')) setError(t("SSO: {0}", q.get('oidc_error')))
    if (q.get('oidc')) {
      api('/auth/oidc/exchange', { method: 'POST', body: { code: q.get('oidc') } })
        .then((r) => { window.history.replaceState(null, '', '/'); onLogin(r.token, r.user) })
        .catch((e) => setError(e.message))
    }
  }, [])  // eslint-disable-line react-hooks/exhaustive-deps -- nur beim Laden der Seite

  const submit = async (e) => {
    e.preventDefault()
    setBusy(true)
    setError('')
    try {
      if (mfaToken) {
        const r = await api('/auth/login/totp', { method: 'POST', body: { mfa_token: mfaToken, code } })
        onLogin(r.token, r.user)
      } else {
        const r = await api('/auth/login', { method: 'POST', body: { username, password } })
        if (r.mfa_required) setMfaToken(r.mfa_token)
        else onLogin(r.token, r.user)
      }
    } catch (err) {
      setError(err.message)
      if (mfaToken && err.status === 401 && /abgelaufen/.test(err.message)) setMfaToken(null)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="center">
      <form className="panel login-box stack" onSubmit={submit}>
        <div className="brand">
          <span className="brand-mark" style={{ color: '#fff' }}>
            <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
              strokeLinecap="round"><path d="M5 8h14M5 12h14M5 16h9" /></svg>
          </span>
          <span>{t("Firewall-Management")}<small className="muted">{t("Sophos Firewall · Vier-Augen-Prinzip")}</small></span>
          <span style={{ marginLeft: 'auto' }}><LanguageSwitch /></span>
        </div>
        {!mfaToken ? <>
          <Field label={t("Benutzername")}>
            <input autoFocus autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} />
          </Field>
          <Field label={t("Passwort")}>
            <input type="password" autoComplete="current-password" value={password}
              onChange={(e) => setPassword(e.target.value)} />
          </Field>
        </> : (
          <Field label={t("Code aus der Authenticator-App")} hint={t("6 Ziffern – ändert sich alle 30 Sekunden")}>
            <input autoFocus inputMode="numeric" autoComplete="one-time-code" value={code} maxLength={7}
              onChange={(e) => setCode(e.target.value)} />
          </Field>
        )}
        <ErrorBox error={error} />
        <button className="primary" disabled={busy || (mfaToken ? code.replace(' ', '').length < 6 : !username || !password)}>
          {mfaToken ? t("Bestätigen") : t("Anmelden")}</button>
        {mfaToken && <button type="button" className="link small" onClick={() => { setMfaToken(null); setCode('') }}>{t("Zurück")}</button>}
        {sso?.enabled && !mfaToken && <>
          <div className="muted small" style={{ textAlign: 'center' }}>{t("oder")}</div>
          <button type="button" onClick={() => { window.location.href = '/api/auth/oidc/login' }}>{sso.label || t("Mit SSO anmelden")}</button>
        </>}
      </form>
    </div>
  )
}
