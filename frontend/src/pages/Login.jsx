import { useState } from 'react'
import { api } from '../api'
import { ErrorBox, Field } from '../components/ui'

export default function Login({ onLogin }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const submit = async (e) => {
    e.preventDefault()
    setBusy(true)
    setError('')
    try {
      const r = await api('/auth/login', { method: 'POST', body: { username, password } })
      onLogin(r.token, r.user)
    } catch (err) {
      setError(err.message)
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
          <span>Firewall-Management<small className="muted">Sophos Firewall · Vier-Augen-Prinzip</small></span>
        </div>
        <Field label="Benutzername">
          <input autoFocus autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} />
        </Field>
        <Field label="Passwort">
          <input type="password" autoComplete="current-password" value={password}
            onChange={(e) => setPassword(e.target.value)} />
        </Field>
        <ErrorBox error={error} />
        <button className="primary" disabled={busy || !username || !password}>Anmelden</button>
      </form>
    </div>
  )
}
