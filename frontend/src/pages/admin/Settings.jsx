import { useEffect, useState } from 'react'
import { api } from '../../api'
import { ErrorBox, Field, useLoad } from '../../components/ui'
import { t } from '../../i18n'

export default function SettingsPage() {
  const [settings, error] = useLoad(() => api('/settings'), [])
  const [form, setForm] = useState(null)
  const [msg, setMsg] = useState(null)
  useEffect(() => { if (settings) setForm(settings) }, [settings])
  if (error) return <ErrorBox error={error} />
  if (!form) return null
  const save = async () => {
    try { setForm(await api('/settings', { method: 'PUT', body: form })); setMsg({ kind: 'ok', text: t("Gespeichert.") }) } catch (e) { setMsg({ kind: 'error', text: e.message }) }
  }
  return (
    <>
      <div className="page-head"><h1>{t("Einstellungen")}</h1></div>
      <div className="panel panel-pad stack" style={{ maxWidth: 720 }}>
        <h3 style={{ margin: 0 }}>{t("Genehmigungsprozess")}</h3>
        <Field label={t("Erforderliche Genehmigungen pro Antrag")} hint={t("Unterschiedliche Personen, nie der Antragsteller. Gilt für neu eingereichte Anträge.")}>
          <select value={form.required_approvals} onChange={(e) => setForm({ ...form, required_approvals: Number(e.target.value) })} style={{ maxWidth: 200 }}>
            {[1, 2, 3].map((n) => <option key={n} value={n}>{n}</option>)}
          </select>
        </Field>
        <label className="check"><input type="checkbox" checked={form.auto_deploy} onChange={(e) => setForm({ ...form, auto_deploy: e.target.checked })} />
          <span>{t("Genehmigte Anträge automatisch ausrollen")} <span className="muted small">{t("(sonst manuell durch Berechtigte mit „change.deploy“)")}</span></span></label>
        <label className="check"><input type="checkbox" checked={form.require_ticket} onChange={(e) => setForm({ ...form, require_ticket: e.target.checked })} />
          <span>{t("Ticket-Referenz beim Einreichen verpflichtend")}</span></label>
        <h3 style={{ margin: '10px 0 0' }}>{t("Anmeldung & Sicherheit")}</h3>
        <Field label={t("Zwei-Faktor-Anmeldung verpflichtend für")} hint={t("Betroffene müssen TOTP einrichten, bevor sie weiterarbeiten können. Vorher selbst einrichten!")}>
          <select value={form.require_mfa} onChange={(e) => setForm({ ...form, require_mfa: e.target.value })} style={{ maxWidth: 360 }}>
            <option value="none">{t("niemanden (freiwillig)")}</option>
            <option value="privileged">{t("Genehmigen, Ausrollen, Verwalten, Admins")}</option>
            <option value="all">{t("alle Benutzer")}</option>
          </select>
        </Field>
        <Field label={t("Vor dem Genehmigen neu anmelden nach (Minuten)")} hint={t("0 = aus. Genehmigen per Telegram ist davon ausgenommen (eigener Faktor: verknüpftes Telefon).")}>
          <input type="number" min={0} value={form.reauth_minutes} onChange={(e) => setForm({ ...form, reauth_minutes: Number(e.target.value) })} style={{ maxWidth: 200 }} />
        </Field>
        <label className="check"><input type="checkbox" checked={form.oidc_counts_as_mfa} onChange={(e) => setForm({ ...form, oidc_counts_as_mfa: e.target.checked })} />
          <span>{t("SSO-Anmeldungen erfüllen die Zwei-Faktor-Pflicht")} <span className="muted small">{t("(MFA erzwingt der Identity Provider)")}</span></span></label>
        <h3 style={{ margin: '10px 0 0' }}>{t("Befristete Änderungen")}</h3>
        <label className="check"><input type="checkbox" checked={form.temp_revert_preapproved} onChange={(e) => setForm({ ...form, temp_revert_preapproved: e.target.checked })} />
          <span>{t("Automatische Rücknahme nach Ablauf ohne erneute Freigabe ausrollen")} <span className="muted small">{t("(die Befristung ist Teil der ursprünglichen Genehmigung)")}</span></span></label>
        <Field label={t("Maximale Befristung (Tage)")} hint="0 = unbegrenzt">
          <input type="number" min={0} value={form.temp_max_days} onChange={(e) => setForm({ ...form, temp_max_days: Number(e.target.value) })} style={{ maxWidth: 200 }} />
        </Field>
        <h3 style={{ margin: '10px 0 0' }}>{t("Synchronisation")}</h3>
        <Field label={t("Intervall (Minuten)")} hint={t("Liest regelmäßig die Konfiguration aller Firewalls und erkennt Änderungen außerhalb dieses Tools. 0 = aus.")}>
          <input type="number" min={0} value={form.sync_interval_minutes} onChange={(e) => setForm({ ...form, sync_interval_minutes: Number(e.target.value) })} style={{ maxWidth: 200 }} />
        </Field>
        <h3 style={{ margin: '10px 0 0' }}>{t("Automatische Sicherung")}</h3>
        <label className="check"><input type="checkbox" checked={form.backup_enabled} onChange={(e) => setForm({ ...form, backup_enabled: e.target.checked })} />
          <span>{t("Konfiguration aller Firewalls automatisch sichern")} <span className="muted small">{t("(liest per API – auf den Firewalls wird nichts geändert)")}</span></span></label>
        {form.backup_enabled && <div className="form-grid">
          <Field label={t("Häufigkeit")}>
            <select value={form.backup_frequency} onChange={(e) => setForm({ ...form, backup_frequency: e.target.value })}>
              <option value="daily">{t("täglich")}</option><option value="weekly">{t("wöchentlich")}</option><option value="monthly">{t("monatlich")}</option>
            </select>
          </Field>
          {form.backup_frequency === 'weekly' && <Field label={t("Wochentag")}>
            <select value={form.backup_weekday} onChange={(e) => setForm({ ...form, backup_weekday: Number(e.target.value) })}>
              {[t("Montag"), t("Dienstag"), t("Mittwoch"), t("Donnerstag"), t("Freitag"), t("Samstag"), t("Sonntag")].map((d, i) => <option key={d} value={i}>{d}</option>)}
            </select>
          </Field>}
          {form.backup_frequency === 'monthly' && <Field label={t("Tag im Monat")} hint={t("In kürzeren Monaten am letzten Tag")}>
            <input type="number" min={1} max={31} value={form.backup_monthday} onChange={(e) => setForm({ ...form, backup_monthday: Number(e.target.value) })} />
          </Field>}
          <Field label={t("Uhrzeit")} hint={t("Zeitzone des Servers")}>
            <input type="time" value={form.backup_time} onChange={(e) => setForm({ ...form, backup_time: e.target.value })} />
          </Field>
          <Field label={t("Aufbewahren (je Firewall)")} hint={t("Anzahl der neuesten Sicherungen; angeheftete bleiben immer")}>
            <input type="number" min={1} max={1000} value={form.backup_keep} onChange={(e) => setForm({ ...form, backup_keep: Number(e.target.value) })} />
          </Field>
        </div>}
        <label className="check"><input type="checkbox" checked={form.backup_to_directory} onChange={(e) => setForm({ ...form, backup_to_directory: e.target.checked })} />
          <span>{t("Sicherungen zusätzlich als Datei ablegen")} <span className="muted small">{t("(Verzeichnis")} <code>{t("backups/")}</code> {t("im Projektordner, gzip-JSON – z. B. für die Datensicherung des Servers)")}</span></span></label>
        {msg && <div className={`alert ${msg.kind}`}>{msg.text}</div>}
        <div><button className="primary" onClick={save}>{t("Speichern")}</button></div>
      </div>
    </>
  )
}
