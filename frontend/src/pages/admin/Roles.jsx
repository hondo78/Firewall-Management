import { useState } from 'react'
import { api } from '../../api'
import { ErrorBox, Field, Modal, useLoad } from '../../components/ui'

function RoleModal({ role, perms, onClose, onSaved }) {
  const [form, setForm] = useState({ name: role?.name || '', description: role?.description || '', permissions: role?.permissions || [] })
  const [error, setError] = useState('')
  const toggle = (k) => setForm({ ...form, permissions: form.permissions.includes(k) ? form.permissions.filter((p) => p !== k) : [...form.permissions, k] })
  const save = async () => {
    try { await api(role ? `/roles/${role.id}` : '/roles', { method: role ? 'PUT' : 'POST', body: form }); onSaved() } catch (e) { setError(e.message) }
  }
  const remove = async () => {
    try { await api(`/roles/${role.id}`, { method: 'DELETE' }); onSaved() } catch (e) { setError(e.message) }
  }
  return (
    <Modal title={role ? `Rolle „${role.name}“` : 'Neue Rolle'} onClose={onClose} wide>
      <div className="stack">
        <div className="form-grid">
          <Field label="Name"><input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></Field>
          <Field label="Beschreibung"><input value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} /></Field>
        </div>
        <h3>Rechte</h3>
        <div className="perm-grid">
          {perms.map((p) => (
            <label key={p.key} className="check panel panel-pad" style={{ padding: 10 }}>
              <input type="checkbox" checked={form.permissions.includes(p.key)} onChange={() => toggle(p.key)} />
              <span><b className="mono">{p.key}</b><div className="small muted">{p.label}</div></span>
            </label>
          ))}
        </div>
        {form.permissions.includes('change.create') && form.permissions.includes('change.approve') && (
          <div className="alert info small">Diese Rolle darf beantragen und genehmigen – eigene Anträge kann sie trotzdem nie selbst genehmigen.</div>
        )}
        <ErrorBox error={error} />
      </div>
      <div className="modal-foot">
        {role && !role.builtin && <button className="danger" onClick={remove}>Löschen</button>}
        <button onClick={onClose}>Abbrechen</button>
        <button className="primary" disabled={!form.name} onClick={save}>Speichern</button>
      </div>
    </Modal>
  )
}

export default function Roles() {
  const [roles, error, reload] = useLoad(() => api('/roles'), [])
  const [perms] = useLoad(() => api('/permissions'), [])
  const [edit, setEdit] = useState(null)
  return (
    <>
      <div className="page-head">
        <h1>Rollen &amp; Rechte</h1>
        <span className="sub">Rollen werden Benutzern global oder je Firewall-Gruppe zugewiesen</span>
        <button className="primary right" onClick={() => setEdit({})}>Neue Rolle</button>
      </div>
      <ErrorBox error={error} />
      {roles && perms && (
        <div className="panel table-wrap">
          <table>
            <thead><tr><th>Rolle</th>{perms.map((p) => <th key={p.key} title={p.label} style={{ textAlign: 'center' }}>{p.key.replace('.', ' ')}</th>)}<th>Zuweisungen</th></tr></thead>
            <tbody>
              {roles.map((r) => (
                <tr key={r.id} className="clickable" onClick={() => setEdit(r)}>
                  <td><b>{r.name}</b>{r.builtin && <span className="badge" style={{ marginLeft: 6 }}>vordefiniert</span>}<div className="small muted">{r.description}</div></td>
                  {perms.map((p) => <td key={p.key} style={{ textAlign: 'center' }}>{r.permissions.includes(p.key) ? <span className="text-ok">✓</span> : <span className="muted">·</span>}</td>)}
                  <td>{r.assignments}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {edit && perms && <RoleModal role={edit.id ? edit : null} perms={perms} onClose={() => setEdit(null)} onSaved={() => { setEdit(null); reload() }} />}
    </>
  )
}
