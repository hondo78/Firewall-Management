import { useState } from 'react'
import { api, ago } from '../../api'
import Diagnose from '../../components/Diagnose'
import { Empty, ErrorBox, Field, Modal, useLoad } from '../../components/ui'
import { t } from '../../i18n'

const TYPE = { tenant: t("Tenant"), partner: t("Partner"), organization: t("Organisation") }

function AccountModal({ account: initial, onClose, onSaved }) {
  // Nach dem Anlegen eines Partner-/Organisationskontos wird hier das gespeicherte Konto gehalten (Tenant-Auswahl)
  const [account, setAccount] = useState(initial)
  const [form, setForm] = useState({ name: account?.name || '', client_id: account?.client_id || '', client_secret: '',
    id_url: account?.id_url || '', api_url: account?.api_url || '', tenant_id: account?.tenant_id || '' })
  const [tenants, setTenants] = useState(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [advanced, setAdvanced] = useState(false)
  const set = (k) => (e) => setForm({ ...form, [k]: e.target.value })
  const save = async () => {
    setBusy(true)
    setError('')
    try {
      const r = await api(account ? `/central-accounts/${account.id}` : '/central-accounts', { method: account ? 'PUT' : 'POST', body: { ...form, client_secret: form.client_secret || null } })
      if (r.tenants?.length && !r.tenant_id) { setTenants(r.tenants); setAccount(r) } else onSaved()
    } catch (e) { setError(e.message) } finally { setBusy(false) }
  }
  return (
    <Modal title={account ? t("Central-Konto „{0}“", account.name) : t("Sophos-Central-Konto verbinden")} onClose={onClose}>
      <div className="stack">
        <div className="alert info small">{t("In Sophos Central unter")} <b>{t("Globale Einstellungen › API-Anmeldeinformationen")}</b> {t("einen Service Principal (Rolle „Service Principal Super Admin“ oder mit Firewall-Rechten) anlegen.")}</div>
        <Field label={t("Anzeigename")}><input value={form.name} onChange={set('name')} /></Field>
        <Field label={t("Client-ID")}><input value={form.client_id} onChange={set('client_id')} autoComplete="off" /></Field>
        <Field label={t("Client-Secret")} hint={account ? t("leer = unverändert") : t("wird verschlüsselt gespeichert")}>
          <input type="password" value={form.client_secret} onChange={set('client_secret')} autoComplete="new-password" /></Field>
        {tenants && (
          <Field label={t("Tenant")} hint={t("Partner-/Organisationskonto: bitte den zu verwaltenden Tenant wählen")}>
            <select value={form.tenant_id} onChange={set('tenant_id')}>
              <option value="">{t("– wählen –")}</option>
              {tenants.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
            </select>
          </Field>
        )}
        <button className="link small" style={{ alignSelf: 'flex-start' }} onClick={() => setAdvanced(!advanced)}>{t("Erweitert")}</button>
        {advanced && <>
          <Field label={t("Sophos-ID-URL")} hint={t("Standard: https://id.sophos.com")}><input value={form.id_url} onChange={set('id_url')} /></Field>
          <Field label={t("Central-API-URL")} hint={t("Standard: https://api.central.sophos.com")}><input value={form.api_url} onChange={set('api_url')} /></Field>
        </>}
        <ErrorBox error={error} />
      </div>
      <div className="modal-foot">
        <button onClick={onClose}>{t("Abbrechen")}</button>
        <button className="primary" disabled={busy || !form.name || !form.client_id || (!account && !form.client_secret) || (tenants && !form.tenant_id)} onClick={save}>
          {busy ? t("Prüfe Zugang …") : t("Speichern & prüfen")}</button>
      </div>
    </Modal>
  )
}

export default function CentralAccounts() {
  const [accounts, error, reload] = useLoad(() => api('/central-accounts'), [])
  const [edit, setEdit] = useState(null)
  const [msg, setMsg] = useState({})
  const [busy, setBusy] = useState(null)
  const syncInv = async (a) => {
    setBusy(a.id)
    try {
      const r = await api(`/central-accounts/${a.id}/sync`, { method: 'POST' })
      setMsg({ ...msg, [a.id]: { kind: 'ok', text: t("{0} Firewalls, {1} Gruppen – {2} neu übernommen.", r.firewalls, r.groups, r.created) } })
    } catch (e) { setMsg({ ...msg, [a.id]: { kind: 'error', text: e.message } }) }
    setBusy(null)
    reload()
  }
  const remove = async (a) => { await api(`/central-accounts/${a.id}`, { method: 'DELETE' }); reload() }
  return (
    <>
      <div className="page-head">
        <h1>{t("Sophos Central")}</h1>
        <span className="sub">{t("Firewalls und Gruppen aus Sophos Central übernehmen (Firewall Management API)")}</span>
        <button className="primary right" onClick={() => setEdit({})}>{t("Konto verbinden")}</button>
      </div>
      <ErrorBox error={error} />
      {accounts && !accounts.length && <div className="panel"><Empty>{t("Noch kein Sophos-Central-Konto verbunden.")}</Empty></div>}
      {accounts?.map((a) => (
        <div className="panel" key={a.id} style={{ marginBottom: 12 }}>
          <div className="panel-head">
            <h3>{a.name}</h3>
            <span className="badge b-info">{TYPE[a.id_type] || a.id_type || '?'}</span>
            <span className="muted small">{t("Client-ID")} {a.client_id} {t("· Region")} {a.data_region || '–'} {t("· Inventar")} {ago(a.last_sync_at)}</span>
            <div className="right row">
              <button className="sm" onClick={() => setEdit(a)}>{t("Bearbeiten")}</button>
              <button className="primary sm" disabled={busy === a.id} onClick={() => syncInv(a)}>{busy === a.id ? t("Lade …") : t("Firewalls übernehmen")}</button>
            </div>
          </div>
          <div className="panel-pad small">
            {a.last_error && <div className="alert error">{a.last_error}</div>}
            {msg[a.id] && <div className={`alert ${msg[a.id].kind}`}>{msg[a.id].text}</div>}
            <div className="muted">{t("Neu übernommene Firewalls nutzen zum Schreiben den Central-Import. Unter Firewall › Einstellungen kann stattdessen die lokale XML-API gewählt werden (nötig zum Löschen von Objekten).")}</div>
            <details style={{ marginTop: 8 }}>
              <summary>{t("Probelauf & Endpunkt-Prüfung")}</summary>
              <div style={{ marginTop: 8 }}>
                <Diagnose path={`/central-accounts/${a.id}/diagnose`}
                  intro={t("Nur lesende Aufrufe (Export-Test liest nur die Zonen einer Firewall). Prüft auch, welche Pfad-Variante die API kennt, und probiert nicht dokumentierte GET-Endpunkte.")} />
              </div>
            </details>
            <button className="link" style={{ color: 'var(--danger)', marginTop: 8 }} onClick={() => remove(a)}>{t("Verbindung entfernen")}</button>
          </div>
        </div>
      ))}
      {edit && <AccountModal account={edit.id ? edit : null} onClose={() => setEdit(null)} onSaved={() => { setEdit(null); reload() }} />}
    </>
  )
}
