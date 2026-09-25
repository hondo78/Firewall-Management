import { useState } from 'react'
import { useAuth } from '../../App'
import { api, fmt } from '../../api'
import { ErrorBox, Field, Modal, useLoad } from '../../components/ui'

function UserModal({ user, roles, groups, onClose, onSaved }) {
  const { me } = useAuth()
  const [form, setForm] = useState({
    username: user?.username || '', display_name: user?.display_name || '', email: user?.email || '', password: '',
    is_superadmin: user?.is_superadmin || false, active: user?.active ?? true,
    assignments: user?.assignments?.map((a) => ({ role_id: a.role_id, group_id: a.group_id })) || [],
  })
  const [error, setError] = useState('')
  const [confirmDelete, setConfirmDelete] = useState(false)
  const set = (k) => (e) => setForm({ ...form, [k]: e.target.type === 'checkbox' ? e.target.checked : e.target.value })
  const setA = (i, k, v) => setForm({ ...form, assignments: form.assignments.map((a, j) => (j === i ? { ...a, [k]: v || null } : a)) })

  const save = async () => {
    setError('')
    try {
      const body = { ...form, password: form.password || null }
      await api(user ? `/users/${user.id}` : '/users', { method: user ? 'PUT' : 'POST', body })
      onSaved()
    } catch (e) { setError(e.message) }
  }
  const deactivate = async () => {
    try { await api(`/users/${user.id}`, { method: 'DELETE' }); onSaved() } catch (e) { setError(e.message) }
  }

  return (
    <Modal title={user ? `Benutzer „${user.username}“` : 'Neuer Benutzer'} onClose={onClose} wide>
      <div className="stack">
        <div className="form-grid">
          <Field label="Benutzername"><input value={form.username} disabled={!!user} onChange={set('username')} autoComplete="off" /></Field>
          <Field label="Anzeigename"><input value={form.display_name} onChange={set('display_name')} /></Field>
          <Field label="E-Mail"><input value={form.email} onChange={set('email')} /></Field>
          <Field label={user ? 'Neues Passwort' : 'Passwort'} hint={user ? 'leer = unverändert' : 'mindestens 10 Zeichen'}>
            <input type="password" value={form.password} onChange={set('password')} autoComplete="new-password" />
          </Field>
        </div>
        <div className="row">
          <label className="check"><input type="checkbox" checked={form.active} onChange={set('active')} disabled={user?.id === me.id} /><span>Aktiv</span></label>
          <label className="check"><input type="checkbox" checked={form.is_superadmin} onChange={set('is_superadmin')} disabled={user?.id === me.id} />
            <span>Superadmin <span className="muted small">(alle Rechte – auch Superadmins können eigene Anträge nicht genehmigen)</span></span></label>
        </div>
        {!form.is_superadmin && <>
          <h3>Rollen</h3>
          <div className="muted small">Eine Rolle gilt für alle Firewalls oder nur für eine Firewall-Gruppe. Mehrere Zuweisungen addieren sich.</div>
          <table>
            <thead><tr><th>Rolle</th><th>Geltungsbereich</th><th /></tr></thead>
            <tbody>
              {form.assignments.map((a, i) => (
                <tr key={i}>
                  <td><select value={a.role_id} onChange={(e) => setA(i, 'role_id', e.target.value)}>
                    {roles.map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}</select></td>
                  <td><select value={a.group_id || ''} onChange={(e) => setA(i, 'group_id', e.target.value)}>
                    <option value="">Alle Firewalls (global)</option>
                    {groups.map((g) => <option key={g.id} value={g.id}>Gruppe: {g.name}</option>)}</select></td>
                  <td><button className="ghost" onClick={() => setForm({ ...form, assignments: form.assignments.filter((_, j) => j !== i) })}>×</button></td>
                </tr>
              ))}
            </tbody>
          </table>
          <div><button className="sm" onClick={() => setForm({ ...form, assignments: [...form.assignments, { role_id: roles[0]?.id, group_id: null }] })}>+ Rolle zuweisen</button></div>
        </>}
        <ErrorBox error={error} />
      </div>
      <div className="modal-foot">
        {user && user.id !== me.id && user.active && (confirmDelete
          ? <button className="danger solid" onClick={deactivate}>Wirklich deaktivieren</button>
          : <button className="danger" onClick={() => setConfirmDelete(true)}>Deaktivieren</button>)}
        <button onClick={onClose}>Abbrechen</button>
        <button className="primary" disabled={!form.username} onClick={save}>Speichern</button>
      </div>
    </Modal>
  )
}

export default function Users() {
  const [users, error, reload] = useLoad(() => api('/users'), [])
  const [roles] = useLoad(() => api('/roles'), [])
  const [groups] = useLoad(() => api('/groups'), [])
  const [edit, setEdit] = useState(null)
  const groupName = (id) => groups?.find((g) => g.id === id)?.name || '?'
  return (
    <>
      <div className="page-head">
        <h1>Benutzer</h1>
        <button className="primary right" onClick={() => setEdit({})}>Neuer Benutzer</button>
      </div>
      <ErrorBox error={error} />
      {users && (
        <div className="panel table-wrap">
          <table>
            <thead><tr><th>Benutzer</th><th>Rollen</th><th>Status</th><th>Letzte Anmeldung</th></tr></thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.id} className="clickable" onClick={() => setEdit(u)}>
                  <td><b>{u.username}</b>{u.display_name && <div className="small muted">{u.display_name}</div>}</td>
                  <td>{u.is_superadmin ? <span className="badge b-accent">Superadmin</span> : (
                    <span className="chips">{u.assignments.map((a) => <span key={a.id} className="chip">{a.role} · {a.group_id ? groupName(a.group_id) : 'global'}</span>)}
                      {!u.assignments.length && <span className="muted small">keine</span>}</span>
                  )}</td>
                  <td>{u.active ? <span className="badge b-ok">aktiv</span> : <span className="badge">deaktiviert</span>}</td>
                  <td className="small">{fmt(u.last_login_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {edit && roles && groups && <UserModal user={edit.id ? edit : null} roles={roles} groups={groups}
        onClose={() => setEdit(null)} onSaved={() => { setEdit(null); reload() }} />}
    </>
  )
}
