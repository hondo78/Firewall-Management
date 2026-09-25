import { useState } from 'react'
import { useAuth } from '../App'
import { api } from '../api'
import { ErrorBox, Field, useLoad } from '../components/ui'

export default function Profile() {
  const { me } = useAuth()
  const [groups] = useLoad(() => api('/groups'), [])
  const [form, setForm] = useState({ current_password: '', new_password: '', repeat: '' })
  const [msg, setMsg] = useState(null)
  const set = (k) => (e) => setForm({ ...form, [k]: e.target.value })
  const groupName = (id) => groups?.find((g) => g.id === id)?.name || id
  const save = async () => {
    setMsg(null)
    try {
      await api('/auth/password', { method: 'POST', body: { current_password: form.current_password, new_password: form.new_password } })
      setMsg({ kind: 'ok', text: 'Passwort geändert.' })
      setForm({ current_password: '', new_password: '', repeat: '' })
    } catch (e) { setMsg({ kind: 'error', text: e.message }) }
  }
  return (
    <>
      <div className="page-head"><h1>Mein Konto</h1></div>
      <div className="grid two">
        <div className="panel panel-pad">
          <h3 style={{ marginTop: 0 }}>{me.display_name || me.username}</h3>
          <div className="muted small">Benutzername: {me.username}</div>
          <h3>Meine Rechte</h3>
          {me.is_superadmin ? <div>Superadmin – alle Rechte auf allen Firewalls.</div> : (
            <table><tbody>
              {me.assignments.map((a) => <tr key={a.id}><td><b>{a.role}</b></td><td>{a.group_id ? `Gruppe „${groupName(a.group_id)}“` : 'alle Firewalls'}</td></tr>)}
              {!me.assignments.length && <tr><td className="muted">Keine Rollen zugewiesen.</td></tr>}
            </tbody></table>
          )}
        </div>
        <div className="panel panel-pad stack">
          <h3 style={{ margin: 0 }}>Passwort ändern</h3>
          <Field label="Aktuelles Passwort"><input type="password" value={form.current_password} onChange={set('current_password')} autoComplete="current-password" /></Field>
          <Field label="Neues Passwort" hint="mindestens 10 Zeichen"><input type="password" value={form.new_password} onChange={set('new_password')} autoComplete="new-password" /></Field>
          <Field label="Wiederholen"><input type="password" value={form.repeat} onChange={set('repeat')} autoComplete="new-password" /></Field>
          {msg && (msg.kind === 'error' ? <ErrorBox error={msg.text} /> : <div className="alert ok">{msg.text}</div>)}
          <div><button className="primary" disabled={form.new_password.length < 10 || form.new_password !== form.repeat} onClick={save}>Ändern</button></div>
        </div>
      </div>
    </>
  )
}
