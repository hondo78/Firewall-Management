import { useState } from 'react'
import { api } from '../../api'
import { ErrorBox, Field, Modal, useLoad } from '../../components/ui'
import { t } from '../../i18n'

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
    <Modal title={role ? t("Rolle „{0}“", role.name) : t("Neue Rolle")} onClose={onClose} wide>
      <div className="stack">
        <div className="form-grid">
          <Field label={t("Name")}><input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></Field>
          <Field label={t("Beschreibung")}><input value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} /></Field>
        </div>
        <h3>{t("Rechte")}</h3>
        <div className="perm-grid">
          {perms.map((p) => (
            <label key={p.key} className="check panel panel-pad" style={{ padding: 10 }}>
              <input type="checkbox" checked={form.permissions.includes(p.key)} onChange={() => toggle(p.key)} />
              <span><b className="mono">{p.key}</b><div className="small muted">{t(p.label)}</div></span>
            </label>
          ))}
        </div>
        {form.permissions.includes('change.create') && form.permissions.includes('change.approve') && (
          <div className="alert info small">{t("Diese Rolle darf beantragen und genehmigen – eigene Anträge kann sie trotzdem nie selbst genehmigen.")}</div>
        )}
        <ErrorBox error={error} />
      </div>
      <div className="modal-foot">
        {role && !role.builtin && <button className="danger" onClick={remove}>{t("Löschen")}</button>}
        <button onClick={onClose}>{t("Abbrechen")}</button>
        <button className="primary" disabled={!form.name} onClick={save}>{t("Speichern")}</button>
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
        <h1>{t("Rollen & Rechte")}</h1>
        <span className="sub">{t("Rollen werden Benutzern global oder je Firewall-Gruppe zugewiesen")}</span>
        <button className="primary right" onClick={() => setEdit({})}>{t("Neue Rolle")}</button>
      </div>
      <ErrorBox error={error} />
      {roles && perms && (
        <div className="panel table-wrap">
          <table>
            <thead><tr><th>{t("Rolle")}</th>{perms.map((p) => <th key={p.key} title={p.label} style={{ textAlign: 'center' }}>{p.key.replace('.', ' ')}</th>)}<th>{t("Zuweisungen")}</th></tr></thead>
            <tbody>
              {roles.map((r) => (
                <tr key={r.id} className="clickable" onClick={() => setEdit(r)}>
                  <td><b>{r.name}</b>{r.builtin && <span className="badge" style={{ marginLeft: 6 }}>{t("vordefiniert")}</span>}<div className="small muted">{r.builtin ? t(r.description) : r.description}</div></td>
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
