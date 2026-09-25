import { useState } from 'react'
import { api, ago } from '../../api'
import Diagnose from '../../components/Diagnose'
import { Empty, ErrorBox, Field, Modal, useLoad } from '../../components/ui'

const TYPE = { tenant: 'Tenant', partner: 'Partner', organization: 'Organisation' }

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
    <Modal title={account ? `Central-Konto „${account.name}“` : 'Sophos-Central-Konto verbinden'} onClose={onClose}>
      <div className="stack">
        <div className="alert info small">In Sophos Central unter <b>Globale Einstellungen › API-Anmeldeinformationen</b> einen
          Service Principal (Rolle „Service Principal Super Admin“ oder mit Firewall-Rechten) anlegen.</div>
        <Field label="Anzeigename"><input value={form.name} onChange={set('name')} /></Field>
        <Field label="Client-ID"><input value={form.client_id} onChange={set('client_id')} autoComplete="off" /></Field>
        <Field label="Client-Secret" hint={account ? 'leer = unverändert' : 'wird verschlüsselt gespeichert'}>
          <input type="password" value={form.client_secret} onChange={set('client_secret')} autoComplete="new-password" /></Field>
        {tenants && (
          <Field label="Tenant" hint="Partner-/Organisationskonto: bitte den zu verwaltenden Tenant wählen">
            <select value={form.tenant_id} onChange={set('tenant_id')}>
              <option value="">– wählen –</option>
              {tenants.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
            </select>
          </Field>
        )}
        <button className="link small" style={{ alignSelf: 'flex-start' }} onClick={() => setAdvanced(!advanced)}>Erweitert</button>
        {advanced && <>
          <Field label="Sophos-ID-URL" hint="Standard: https://id.sophos.com"><input value={form.id_url} onChange={set('id_url')} /></Field>
          <Field label="Central-API-URL" hint="Standard: https://api.central.sophos.com"><input value={form.api_url} onChange={set('api_url')} /></Field>
        </>}
        <ErrorBox error={error} />
      </div>
      <div className="modal-foot">
        <button onClick={onClose}>Abbrechen</button>
        <button className="primary" disabled={busy || !form.name || !form.client_id || (!account && !form.client_secret) || (tenants && !form.tenant_id)} onClick={save}>
          {busy ? 'Prüfe Zugang …' : 'Speichern & prüfen'}</button>
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
      setMsg({ ...msg, [a.id]: { kind: 'ok', text: `${r.firewalls} Firewalls, ${r.groups} Gruppen – ${r.created} neu übernommen.` } })
    } catch (e) { setMsg({ ...msg, [a.id]: { kind: 'error', text: e.message } }) }
    setBusy(null)
    reload()
  }
  const remove = async (a) => { await api(`/central-accounts/${a.id}`, { method: 'DELETE' }); reload() }
  return (
    <>
      <div className="page-head">
        <h1>Sophos Central</h1>
        <span className="sub">Firewalls und Gruppen aus Sophos Central übernehmen (Firewall Management API)</span>
        <button className="primary right" onClick={() => setEdit({})}>Konto verbinden</button>
      </div>
      <ErrorBox error={error} />
      {accounts && !accounts.length && <div className="panel"><Empty>Noch kein Sophos-Central-Konto verbunden.</Empty></div>}
      {accounts?.map((a) => (
        <div className="panel" key={a.id} style={{ marginBottom: 12 }}>
          <div className="panel-head">
            <h3>{a.name}</h3>
            <span className="badge b-info">{TYPE[a.id_type] || a.id_type || '?'}</span>
            <span className="muted small">Client-ID {a.client_id} · Region {a.data_region || '–'} · Inventar {ago(a.last_sync_at)}</span>
            <div className="right row">
              <button className="sm" onClick={() => setEdit(a)}>Bearbeiten</button>
              <button className="primary sm" disabled={busy === a.id} onClick={() => syncInv(a)}>{busy === a.id ? 'Lade …' : 'Firewalls übernehmen'}</button>
            </div>
          </div>
          <div className="panel-pad small">
            {a.last_error && <div className="alert error">{a.last_error}</div>}
            {msg[a.id] && <div className={`alert ${msg[a.id].kind}`}>{msg[a.id].text}</div>}
            <div className="muted">Neu übernommene Firewalls nutzen zum Schreiben den Central-Import. Unter Firewall › Einstellungen kann
              stattdessen die lokale XML-API gewählt werden (nötig zum Löschen von Objekten).</div>
            <details style={{ marginTop: 8 }}>
              <summary>Probelauf &amp; Endpunkt-Prüfung</summary>
              <div style={{ marginTop: 8 }}>
                <Diagnose path={`/central-accounts/${a.id}/diagnose`}
                  intro="Nur lesende Aufrufe (Export-Test liest nur die Zonen einer Firewall). Prüft auch, welche Pfad-Variante die API kennt, und probiert nicht dokumentierte GET-Endpunkte." />
              </div>
            </details>
            <button className="link" style={{ color: 'var(--danger)', marginTop: 8 }} onClick={() => remove(a)}>Verbindung entfernen</button>
          </div>
        </div>
      ))}
      {edit && <AccountModal account={edit.id ? edit : null} onClose={() => setEdit(null)} onSaved={() => { setEdit(null); reload() }} />}
    </>
  )
}
