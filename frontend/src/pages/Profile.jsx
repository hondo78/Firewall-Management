import { useEffect, useState } from 'react'
import { useAuth } from '../App'
import { api, setToken } from '../api'
import { ErrorBox, Field, useLoad } from '../components/ui'
import { t } from '../i18n'

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
      setMsg({ kind: 'ok', text: t("Passwort geändert.") })
      setForm({ current_password: '', new_password: '', repeat: '' })
    } catch (e) { setMsg({ kind: 'error', text: e.message }) }
  }
  return (
    <>
      <div className="page-head"><h1>{t("Mein Konto")}</h1></div>
      <div className="grid two">
        <div className="panel panel-pad">
          <h3 style={{ marginTop: 0 }}>{me.display_name || me.username}</h3>
          <div className="muted small">{t("Benutzername:")} {me.username}</div>
          <h3>{t("Meine Rechte")}</h3>
          {me.is_superadmin ? <div>{t("Superadmin – alle Rechte auf allen Firewalls.")}</div> : (
            <table><tbody>
              {me.assignments.map((a) => <tr key={a.id}><td><b>{a.role}</b></td><td>{a.group_id ? t("Gruppe „{0}“", groupName(a.group_id)) : t("alle Firewalls")}</td></tr>)}
              {!me.assignments.length && <tr><td className="muted">{t("Keine Rollen zugewiesen.")}</td></tr>}
            </tbody></table>
          )}
        </div>
        <TotpPanel me={me} setMe={setMe} />
        <NotifyPrefs me={me} setMe={setMe} />
        <div className="panel panel-pad stack">
          <h3 style={{ margin: 0 }}>{t("Passwort ändern")}</h3>
          <Field label={t("Aktuelles Passwort")}><input type="password" value={form.current_password} onChange={set('current_password')} autoComplete="current-password" /></Field>
          <Field label={t("Neues Passwort")} hint={t("mindestens 10 Zeichen")}><input type="password" value={form.new_password} onChange={set('new_password')} autoComplete="new-password" /></Field>
          <Field label={t("Wiederholen")}><input type="password" value={form.repeat} onChange={set('repeat')} autoComplete="new-password" /></Field>
          {msg && (msg.kind === 'error' ? <ErrorBox error={msg.text} /> : <div className="alert ok">{msg.text}</div>)}
          <div><button className="primary" disabled={form.new_password.length < 10 || form.new_password !== form.repeat} onClick={save}>{t("Ändern")}</button></div>
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
    try { await api('/auth/notifications', { method: 'PUT', body }); setMe(await api('/auth/me')); setMsg({ kind: 'ok', text: t("Gespeichert.") }) } catch (e) { setMsg({ kind: 'error', text: e.message }) }
  }
  const startLink = async () => {
    try { setLink(await api('/auth/telegram-link', { method: 'POST' })) } catch (e) { setMsg({ kind: 'error', text: e.message }) }
  }
  const unlink = async () => { await api('/auth/telegram-link', { method: 'DELETE' }); setMe(await api('/auth/me')) }
  return (
    <div className="panel panel-pad stack">
      <h3 style={{ margin: 0 }}>{t("Benachrichtigungen")}</h3>
      <Field label="E-Mail-Adresse"><div className="row" style={{ flexWrap: 'nowrap' }}>
        <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} />
        <button className="sm" onClick={() => save({ email })}>{t("Speichern")}</button></div></Field>
      <label className="check"><input type="checkbox" checked={me.notify_email} onChange={(e) => save({ notify_email: e.target.checked })} />
        <span>{t("E-Mails erhalten")}</span></label>
      <div>
        <b>{t("Telegram:")}</b> {me.telegram_linked ? <>{t("verknüpft")} <button className="link small" onClick={unlink}>{t("trennen")}</button></>
          : link ? <span className="small">{t("Code")} <b className="mono">{link.code}</b> – {link.url ? <a href={link.url} target="_blank" rel="noreferrer">{t("Bot öffnen")}</a> : t("an den Bot senden")} {t("mit")} <span className="mono">{t("/start")} {link.code}</span> {t("(10 min gültig) …")}</span>
            : <button className="sm" onClick={startLink}>{t("Verknüpfen")}</button>}
      </div>
      {msg && <div className={`alert ${msg.kind} small`}>{msg.text}</div>}
    </div>
  )
}

function TotpPanel({ me, setMe }) {
  const [setup, setSetup] = useState(null)
  const [code, setCode] = useState('')
  const [pw, setPw] = useState('')
  const [msg, setMsg] = useState(null)
  if (me.auth_source === 'oidc') {
    return <div className="panel panel-pad"><h3 style={{ marginTop: 0 }}>{t("Zwei-Faktor-Anmeldung")}</h3>
      <div className="muted small">{t("Sie melden sich per SSO an – der zweite Faktor wird beim Identity Provider verwaltet.")}</div></div>
  }
  const start = async () => { setMsg(null); try { setSetup(await api('/auth/totp/setup', { method: 'POST' })) } catch (e) { setMsg({ kind: 'error', text: e.message }) } }
  const enable = async () => {
    try {
      const r = await api('/auth/totp/enable', { method: 'POST', body: { code } })
      setToken(r.token); setMe(r.user); setSetup(null); setCode('')
      setMsg({ kind: 'ok', text: t("Zwei-Faktor-Anmeldung ist aktiv.") })
    } catch (e) { setMsg({ kind: 'error', text: e.message }) }
  }
  const disable = async () => {
    try { await api('/auth/totp/disable', { method: 'POST', body: { password: pw, code } }); setMe(await api('/auth/me')); setPw(''); setCode(''); setMsg({ kind: 'ok', text: t("Deaktiviert.") }) } catch (e) { setMsg({ kind: 'error', text: e.message }) }
  }
  return (
    <div className="panel panel-pad stack" style={me.mfa_setup_required ? { borderColor: 'var(--warn)' } : undefined}>
      <h3 style={{ margin: 0 }}>{t("Zwei-Faktor-Anmeldung")}</h3>
      {me.totp_enabled && !setup ? <>
        <div><span className="badge b-ok">{t("aktiv")}</span> <span className="muted small">{t("Authenticator-App (TOTP)")}</span></div>
        {!me.mfa_required && <details><summary>{t("Deaktivieren")}</summary>
          <div className="stack" style={{ marginTop: 8 }}>
            <Field label={t("Passwort")}><input type="password" value={pw} onChange={(e) => setPw(e.target.value)} /></Field>
            <Field label={t("Aktueller Code")}><input inputMode="numeric" value={code} onChange={(e) => setCode(e.target.value)} /></Field>
            <div><button className="danger" onClick={disable}>{t("Deaktivieren")}</button></div>
          </div></details>}
        {me.mfa_required && <div className="muted small">{t("Für Ihre Rolle verpflichtend. Bei Verlust des Telefons setzt ein Administrator den zweiten Faktor zurück.")}</div>}
      </> : !setup ? <>
        <div className="muted small">{t("Schützt Ihr Konto zusätzlich mit einem Code aus einer Authenticator-App (z. B. Microsoft oder Google Authenticator, 1Password).")}</div>
        <div><button className="primary" onClick={start}>{t("Einrichten")}</button></div>
      </> : <>
        <div className="small">{t("1. QR-Code mit der Authenticator-App scannen (oder Schlüssel manuell eingeben):")}</div>
        {/* SVG stammt vom eigenen Backend (segno) */}
        <div style={{ background: '#fff', padding: 8, borderRadius: 6, alignSelf: 'flex-start' }} dangerouslySetInnerHTML={{ __html: setup.qr_svg }} />
        <code className="small" style={{ wordBreak: 'break-all' }}>{setup.secret}</code>
        <Field label={t("2. Angezeigten Code eingeben")}><input autoFocus inputMode="numeric" value={code} onChange={(e) => setCode(e.target.value)} autoComplete="one-time-code" /></Field>
        <div className="row"><button className="primary" disabled={code.length < 6} onClick={enable}>{t("Aktivieren")}</button><button onClick={() => setSetup(null)}>{t("Abbrechen")}</button></div>
      </>}
      {msg && <div className={`alert ${msg.kind} small`}>{msg.text}</div>}
    </div>
  )
}
