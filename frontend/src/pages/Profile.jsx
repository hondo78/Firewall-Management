import { useEffect, useState } from 'react'
import { useAuth } from '../App'
import { api } from '../api'
import { ErrorBox, Field, useLoad } from '../components/ui'

export default function Profile() {
  const { me, setMe } = useAuth()
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
        <NotifyPrefs me={me} setMe={setMe} />
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

function NotifyPrefs({ me, setMe }) {
  const [email, setEmail] = useState(me.email || '')
  const [msg, setMsg] = useState(null)
  const [link, setLink] = useState(null)
  useEffect(() => {
    if (!link) return undefined
    // Nach dem Senden des Codes an den Bot: Status regelmäßig prüfen
    const t = setInterval(async () => {
      const m = await api('/auth/me')
      if (m.telegram_linked) { setMe(m); setLink(null) }
    }, 3000)
    return () => clearInterval(t)
  }, [link, setMe])
  const save = async (body) => {
    try { await api('/auth/notifications', { method: 'PUT', body }); setMe(await api('/auth/me')); setMsg({ kind: 'ok', text: 'Gespeichert.' }) } catch (e) { setMsg({ kind: 'error', text: e.message }) }
  }
  const startLink = async () => {
    try { setLink(await api('/auth/telegram-link', { method: 'POST' })) } catch (e) { setMsg({ kind: 'error', text: e.message }) }
  }
  const unlink = async () => { await api('/auth/telegram-link', { method: 'DELETE' }); setMe(await api('/auth/me')) }
  return (
    <div className="panel panel-pad stack">
      <h3 style={{ margin: 0 }}>Benachrichtigungen</h3>
      <Field label="E-Mail-Adresse"><div className="row" style={{ flexWrap: 'nowrap' }}>
        <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} />
        <button className="sm" onClick={() => save({ email })}>Speichern</button></div></Field>
      <label className="check"><input type="checkbox" checked={me.notify_email} onChange={(e) => save({ notify_email: e.target.checked })} />
        <span>E-Mails erhalten</span></label>
      <div>
        <b>Telegram:</b> {me.telegram_linked ? <>verknüpft <button className="link small" onClick={unlink}>trennen</button></>
          : link ? <span className="small">Code <b className="mono">{link.code}</b> – {link.url ? <a href={link.url} target="_blank" rel="noreferrer">Bot öffnen</a> : 'an den Bot senden'} mit <span className="mono">/start {link.code}</span> (10 min gültig) …</span>
            : <button className="sm" onClick={startLink}>Verknüpfen</button>}
      </div>
      {msg && <div className={`alert ${msg.kind} small`}>{msg.text}</div>}
    </div>
  )
}
