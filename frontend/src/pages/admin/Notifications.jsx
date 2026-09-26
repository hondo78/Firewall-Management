import { useEffect, useState } from 'react'
import { api } from '../../api'
import { ErrorBox, Field, useLoad } from '../../components/ui'
import { t } from '../../i18n'

function Secret({ label, isSet, value, onChange, onClear }) {
  return (
    <Field label={label} hint={isSet ? t("gesetzt – leer lassen = unverändert") : t("wird verschlüsselt gespeichert")}>
      <div className="row" style={{ flexWrap: 'nowrap' }}>
        <input type="password" value={value} onChange={onChange} autoComplete="new-password" />
        {isSet && <button className="ghost sm" onClick={onClear} title={t("Entfernen")}>×</button>}
      </div>
    </Field>
  )
}

export default function Notifications() {
  const [cfg, error, reload] = useLoad(() => api('/notifications/config'), [])
  const [form, setForm] = useState(null)
  const [msg, setMsg] = useState(null)
  const [test, setTest] = useState({})
  useEffect(() => {
    if (cfg) setForm({ ...cfg, email: { ...cfg.email, password: '' }, telegram: { ...cfg.telegram, bot_token: '' }, teams: { ...cfg.teams, webhook_url: '' }, slack: { ...cfg.slack, webhook_url: '' } })
  }, [cfg])
  if (error) return <ErrorBox error={error} />
  if (!form) return null
  const set = (ch, k, num) => (e) => setForm({ ...form, [ch]: { ...form[ch], [k]: e.target.type === 'checkbox' ? e.target.checked : num ? Number(e.target.value) : e.target.value } })
  const save = async (extra) => {
    setMsg(null)
    try {
      await api('/notifications/config', { method: 'PUT', body: { ...form, ...extra } })
      setMsg({ kind: 'ok', text: t("Gespeichert.") })
      reload()
    } catch (e) { setMsg({ kind: 'error', text: e.message }) }
  }
  const runTest = async (channel) => {
    setTest({ ...test, [channel]: { message: t("Sende …") } })
    try { setTest({ ...test, [channel]: await api('/notifications/test', { method: 'POST', body: { channel } }) }) } catch (e) { setTest({ ...test, [channel]: { ok: false, message: e.message } }) }
  }
  const TestResult = ({ ch }) => test[ch] ? <span className={`small ${test[ch].ok ? 'text-ok' : test[ch].ok === false ? 'text-error' : 'muted'}`}>{test[ch].message}</span> : null

  return (
    <>
      <div className="page-head"><h1>{t("Benachrichtigungen")}</h1>
        <span className="sub">{t("Genehmiger erfahren von neuen Anträgen, Antragsteller vom Ergebnis, Verwalter von Fehlern und ablaufenden API-Keys")}</span></div>
      <div className="stack" style={{ maxWidth: 820 }}>
        <div className="panel panel-pad stack">
          <Field label={t("Adresse der Oberfläche (für Links in Nachrichten)")} hint={t("z. B. http://firewall-management.example.local:8096")}>
            <input value={form.public_url} onChange={(e) => setForm({ ...form, public_url: e.target.value })} />
          </Field>
        </div>

        <div className="panel panel-pad stack">
          <label className="check"><input type="checkbox" checked={form.email.enabled} onChange={set('email', 'enabled')} /><b>{t("E-Mail (SMTP)")}</b></label>
          <div className="muted small">{t("An alle Benutzer mit hinterlegter E-Mail-Adresse, die E-Mails nicht abgeschaltet haben (Profil).")}</div>
          <div className="form-grid">
            <Field label="SMTP-Server"><input value={form.email.host} onChange={set('email', 'host')} placeholder="smtp.example.com" /></Field>
            <Field label={t("Port")}><input type="number" value={form.email.port} onChange={set('email', 'port', true)} /></Field>
            <Field label={t("Verschlüsselung")}>
              <select value={form.email.security} onChange={set('email', 'security')}>
                <option value="starttls">STARTTLS</option><option value="ssl">SSL/TLS</option><option value="none">{t("keine")}</option>
              </select>
            </Field>
            <Field label={t("Benutzer")}><input value={form.email.username} onChange={set('email', 'username')} autoComplete="off" /></Field>
            <Secret label={t("Passwort")} isSet={cfg.email.password_set} value={form.email.password} onChange={set('email', 'password')}
              onClear={() => save({ email: { ...form.email, clear_password: true } })} />
            <Field label={t("Absender")}><input value={form.email.sender} onChange={set('email', 'sender')} placeholder="firewall@example.com" /></Field>
          </div>
          <div className="row"><button className="sm" onClick={() => runTest('email')}>{t("Test an meine Adresse")}</button><TestResult ch="email" /></div>
        </div>

        <div className="panel panel-pad stack">
          <label className="check"><input type="checkbox" checked={form.teams.enabled} onChange={set('teams', 'enabled')} /><b>{t("Microsoft Teams")}</b></label>
          <div className="muted small">{t("Karte in einen Kanal: in Teams einen Workflow „Beim Empfang einer Webhook-Anforderung in einem Kanal posten“ anlegen und dessen URL eintragen.")}</div>
          <Secret label={t("Webhook-URL")} isSet={cfg.teams.webhook_url_set} value={form.teams.webhook_url} onChange={set('teams', 'webhook_url')}
            onClear={() => save({ teams: { ...form.teams, clear_webhook_url: true } })} />
          <div className="row"><button className="sm" onClick={() => runTest('teams')}>{t("Testkarte senden")}</button><TestResult ch="teams" /></div>
        </div>

        <div className="panel panel-pad stack">
          <label className="check"><input type="checkbox" checked={form.slack.enabled} onChange={set('slack', 'enabled')} /><b>{t("Slack")}</b></label>
          <div className="muted small">{t("Nachricht in einen Kanal: unter")} <b>{t("api.slack.com/apps")}</b> {t("eine App anlegen, „Incoming Webhooks“ aktivieren, „Add New Webhook to Workspace“ → Kanal wählen und die Webhook-URL (https://hooks.slack.com/services/…) hier eintragen. Gesendet werden neue Anträge, Ausrollen/Fehler, Änderungen außerhalb des Tools, fehlgeschlagene Sicherungen und ablaufende API-Keys.")}</div>
          <Secret label={t("Webhook-URL")} isSet={cfg.slack.webhook_url_set} value={form.slack.webhook_url} onChange={set('slack', 'webhook_url')}
            onClear={() => save({ slack: { ...form.slack, clear_webhook_url: true } })} />
          <Field label={t("Bei neuen Anträgen erwähnen")} hint={t("Damit Genehmiger sofort benachrichtigt werden")}>
            <select value={form.slack.mention} onChange={set('slack', 'mention')} style={{ maxWidth: 320 }}>
              <option value="">{t("niemanden")}</option>
              <option value="here">{t("@here (alle Aktiven im Kanal)")}</option>
              <option value="channel">{t("@channel (alle im Kanal)")}</option>
            </select>
          </Field>
          <div className="row"><button className="sm" onClick={() => runTest('slack')}>{t("Testnachricht senden")}</button><TestResult ch="slack" /></div>
        </div>

        <div className="panel panel-pad stack">
          <label className="check"><input type="checkbox" checked={form.telegram.enabled} onChange={set('telegram', 'enabled')} /><b>{t("Telegram")}</b></label>
          <div className="muted small">{t("Persönliche Nachrichten an Benutzer, die ihren Chat im Profil verknüpft haben. Bot bei @BotFather anlegen. Kein öffentlicher Zugang nötig (Long Polling).")}</div>
          <div className="form-grid">
            <Secret label={t("Bot-Token")} isSet={cfg.telegram.bot_token_set} value={form.telegram.bot_token} onChange={set('telegram', 'bot_token')}
              onClear={() => save({ telegram: { ...form.telegram, clear_bot_token: true } })} />
            <Field label={t("Bot-Benutzername")} hint={t("ohne @, für den Verknüpfungslink")}><input value={form.telegram.bot_username} onChange={set('telegram', 'bot_username')} /></Field>
          </div>
          <label className="check"><input type="checkbox" checked={form.telegram.allow_approve} onChange={set('telegram', 'allow_approve')} />
            <span>{t("Genehmigen per Knopf erlauben")} <span className="muted small">{t("(gleiche Rechte- und Vier-Augen-Prüfung wie im Web; Ablehnen nur im Web)")}</span></span></label>
          <div className="row"><button className="sm" onClick={() => runTest('telegram')}>{t("Test an meinen Chat")}</button><TestResult ch="telegram" /></div>
        </div>

        {msg && <div className={`alert ${msg.kind}`}>{msg.text}</div>}
        <div><button className="primary" onClick={() => save()}>{t("Speichern")}</button></div>
      </div>
    </>
  )
}
