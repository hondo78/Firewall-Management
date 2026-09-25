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
        {msg && <div className={`alert ${msg.kind}`}>{msg.text}</div>}
        <div><button className="primary" onClick={save}>Speichern</button></div>
      </div>
    </>
  )
}
