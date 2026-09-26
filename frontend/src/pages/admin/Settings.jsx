import { useEffect, useState } from 'react'
import { api } from '../../api'
import { ErrorBox, Field, useLoad } from '../../components/ui'

export default function SettingsPage() {
  const [settings, error] = useLoad(() => api('/settings'), [])
  const [form, setForm] = useState(null)
  const [msg, setMsg] = useState(null)
  useEffect(() => { if (settings) setForm(settings) }, [settings])
  if (error) return <ErrorBox error={error} />
  if (!form) return null
  const save = async () => {
    try { setForm(await api('/settings', { method: 'PUT', body: form })); setMsg({ kind: 'ok', text: 'Gespeichert.' }) } catch (e) { setMsg({ kind: 'error', text: e.message }) }
  }
  return (
    <>
      <div className="page-head"><h1>Einstellungen</h1></div>
      <div className="panel panel-pad stack" style={{ maxWidth: 720 }}>
        <h3 style={{ margin: 0 }}>Genehmigungsprozess</h3>
        <Field label="Erforderliche Genehmigungen pro Antrag" hint="Unterschiedliche Personen, nie der Antragsteller. Gilt für neu eingereichte Anträge.">
          <select value={form.required_approvals} onChange={(e) => setForm({ ...form, required_approvals: Number(e.target.value) })} style={{ maxWidth: 200 }}>
            {[1, 2, 3].map((n) => <option key={n} value={n}>{n}</option>)}
          </select>
        </Field>
        <label className="check"><input type="checkbox" checked={form.auto_deploy} onChange={(e) => setForm({ ...form, auto_deploy: e.target.checked })} />
          <span>Genehmigte Anträge automatisch ausrollen <span className="muted small">(sonst manuell durch Berechtigte mit „change.deploy“)</span></span></label>
        <label className="check"><input type="checkbox" checked={form.require_ticket} onChange={(e) => setForm({ ...form, require_ticket: e.target.checked })} />
          <span>Ticket-Referenz beim Einreichen verpflichtend</span></label>
        <h3 style={{ margin: '10px 0 0' }}>Anmeldung & Sicherheit</h3>
        <Field label="Zwei-Faktor-Anmeldung verpflichtend für" hint="Betroffene müssen TOTP einrichten, bevor sie weiterarbeiten können. Vorher selbst einrichten!">
          <select value={form.require_mfa} onChange={(e) => setForm({ ...form, require_mfa: e.target.value })} style={{ maxWidth: 360 }}>
            <option value="none">niemanden (freiwillig)</option>
            <option value="privileged">Genehmigen, Ausrollen, Verwalten, Admins</option>
            <option value="all">alle Benutzer</option>
          </select>
        </Field>
        <Field label="Vor dem Genehmigen neu anmelden nach (Minuten)" hint="0 = aus. Genehmigen per Telegram ist davon ausgenommen (eigener Faktor: verknüpftes Telefon).">
          <input type="number" min={0} value={form.reauth_minutes} onChange={(e) => setForm({ ...form, reauth_minutes: Number(e.target.value) })} style={{ maxWidth: 200 }} />
        </Field>
        <label className="check"><input type="checkbox" checked={form.oidc_counts_as_mfa} onChange={(e) => setForm({ ...form, oidc_counts_as_mfa: e.target.checked })} />
          <span>SSO-Anmeldungen erfüllen die Zwei-Faktor-Pflicht <span className="muted small">(MFA erzwingt der Identity Provider)</span></span></label>
        <h3 style={{ margin: '10px 0 0' }}>Befristete Änderungen</h3>
        <label className="check"><input type="checkbox" checked={form.temp_revert_preapproved} onChange={(e) => setForm({ ...form, temp_revert_preapproved: e.target.checked })} />
          <span>Automatische Rücknahme nach Ablauf ohne erneute Freigabe ausrollen <span className="muted small">(die Befristung ist Teil der ursprünglichen Genehmigung)</span></span></label>
        <Field label="Maximale Befristung (Tage)" hint="0 = unbegrenzt">
          <input type="number" min={0} value={form.temp_max_days} onChange={(e) => setForm({ ...form, temp_max_days: Number(e.target.value) })} style={{ maxWidth: 200 }} />
        </Field>
        <h3 style={{ margin: '10px 0 0' }}>Synchronisation</h3>
        <Field label="Intervall (Minuten)" hint="Liest regelmäßig die Konfiguration aller Firewalls und erkennt Änderungen außerhalb dieses Tools. 0 = aus.">
          <input type="number" min={0} value={form.sync_interval_minutes} onChange={(e) => setForm({ ...form, sync_interval_minutes: Number(e.target.value) })} style={{ maxWidth: 200 }} />
        </Field>
        <h3 style={{ margin: '10px 0 0' }}>Automatische Sicherung</h3>
        <label className="check"><input type="checkbox" checked={form.backup_enabled} onChange={(e) => setForm({ ...form, backup_enabled: e.target.checked })} />
          <span>Konfiguration aller Firewalls automatisch sichern <span className="muted small">(liest per API – auf den Firewalls wird nichts geändert)</span></span></label>
        {form.backup_enabled && <div className="form-grid">
          <Field label="Häufigkeit">
            <select value={form.backup_frequency} onChange={(e) => setForm({ ...form, backup_frequency: e.target.value })}>
              <option value="daily">täglich</option><option value="weekly">wöchentlich</option><option value="monthly">monatlich</option>
            </select>
          </Field>
          {form.backup_frequency === 'weekly' && <Field label="Wochentag">
            <select value={form.backup_weekday} onChange={(e) => setForm({ ...form, backup_weekday: Number(e.target.value) })}>
              {['Montag', 'Dienstag', 'Mittwoch', 'Donnerstag', 'Freitag', 'Samstag', 'Sonntag'].map((d, i) => <option key={d} value={i}>{d}</option>)}
            </select>
          </Field>}
          {form.backup_frequency === 'monthly' && <Field label="Tag im Monat" hint="In kürzeren Monaten am letzten Tag">
            <input type="number" min={1} max={31} value={form.backup_monthday} onChange={(e) => setForm({ ...form, backup_monthday: Number(e.target.value) })} />
          </Field>}
          <Field label="Uhrzeit" hint="Zeitzone des Servers">
            <input type="time" value={form.backup_time} onChange={(e) => setForm({ ...form, backup_time: e.target.value })} />
          </Field>
          <Field label="Aufbewahren (je Firewall)" hint="Anzahl der neuesten Sicherungen; angeheftete bleiben immer">
            <input type="number" min={1} max={1000} value={form.backup_keep} onChange={(e) => setForm({ ...form, backup_keep: Number(e.target.value) })} />
          </Field>
        </div>}
        <label className="check"><input type="checkbox" checked={form.backup_to_directory} onChange={(e) => setForm({ ...form, backup_to_directory: e.target.checked })} />
          <span>Sicherungen zusätzlich als Datei ablegen <span className="muted small">(Verzeichnis <code>backups/</code> im Projektordner, gzip-JSON – z. B. für die Datensicherung des Servers)</span></span></label>
        {msg && <div className={`alert ${msg.kind}`}>{msg.text}</div>}
        <div><button className="primary" onClick={save}>Speichern</button></div>
      </div>
    </>
  )
}
