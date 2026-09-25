import { useState } from 'react'
import { api } from '../api'
import { ErrorBox, Field } from './ui'

/** Anlegen/Bearbeiten der Anbindung einer Firewall. */
export default function FirewallForm({ fw, groups, onSaved, onCancel }) {
  const [form, setForm] = useState({
    name: fw?.name || '', group_id: fw?.group_id || '', connector: fw?.connector || 'xmlapi',
    api_url: fw?.api_url || '', api_username: fw?.api_username || '', api_password: '',
    verify_tls: fw?.verify_tls ?? true,
  })
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const set = (k) => (e) => setForm({ ...form, [k]: e.target.type === 'checkbox' ? e.target.checked : e.target.value })
  const fromCentral = !!fw?.central_id

  const save = async () => {
    setBusy(true)
    setError('')
    try {
      const body = { ...form, group_id: form.group_id || null, api_password: form.api_password || null }
      const saved = await api(fw ? `/firewalls/${fw.id}` : '/firewalls', { method: fw ? 'PUT' : 'POST', body })
      onSaved(saved)
    } catch (e) { setError(e.message) } finally { setBusy(false) }
  }

  return (
    <>
      <div className="stack">
        <div className="form-grid">
          <Field label="Anzeigename"><input value={form.name} onChange={set('name')} /></Field>
          <Field label="Gruppe" hint="Bestimmt, wer die Firewall sieht und bearbeiten darf">
            <select value={form.group_id} onChange={set('group_id')} disabled={fromCentral && !!fw?.group_id && groups.find((g) => g.id === fw.group_id)?.central}>
              <option value="">– ohne Gruppe –</option>
              {groups.map((g) => <option key={g.id} value={g.id}>{g.name}</option>)}
            </select>
          </Field>
        </div>
        {fromCentral && (
          <Field label="Schreibweg für Konfigurationsänderungen">
            <select value={form.connector} onChange={set('connector')}>
              <option value="central">Sophos Central – Import/Export (kein Löschen möglich)</option>
              <option value="xmlapi">Lokale XML-API der Firewall (volle Unterstützung)</option>
            </select>
          </Field>
        )}
        {(form.connector === 'xmlapi' || !fromCentral) && <>
          <div className="alert info small">
            Auf der Firewall unter <b>Backup &amp; firmware › API</b> die API aktivieren und die IP dieses Servers
            erlauben. Empfohlen: eigener Administrator mit passendem Geräteprofil.
          </div>
          <div className="form-grid">
            <Field label="API-Adresse" hint="z. B. 10.0.0.1 oder https://fw.example.local:4444">
              <input value={form.api_url} onChange={set('api_url')} placeholder="https://firewall:4444" />
            </Field>
            <Field label="API-Benutzer"><input value={form.api_username} onChange={set('api_username')} autoComplete="off" /></Field>
            <Field label="Passwort" hint={fw?.has_api_password ? 'leer lassen = unverändert' : 'wird verschlüsselt gespeichert'}>
              <input type="password" value={form.api_password} onChange={set('api_password')} autoComplete="new-password" />
            </Field>
          </div>
          <label className="check"><input type="checkbox" checked={form.verify_tls} onChange={set('verify_tls')} />
            <span>TLS-Zertifikat prüfen <span className="muted small">(bei selbstsignierten Zertifikaten deaktivieren)</span></span></label>
        </>}
        <ErrorBox error={error} />
      </div>
      <div className="modal-foot">
        {onCancel && <button onClick={onCancel}>Abbrechen</button>}
        <button className="primary" disabled={busy || !form.name} onClick={save}>{busy ? 'Speichere …' : 'Speichern'}</button>
      </div>
    </>
  )
}
