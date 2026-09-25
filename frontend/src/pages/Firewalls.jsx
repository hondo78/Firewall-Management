import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useAuth } from '../App'
import { ago, api, can, canAnywhere } from '../api'
import FirewallForm from '../components/FirewallForm'
import { Empty, ErrorBox, Field, Modal, useLoad } from '../components/ui'

export function SyncState({ fw }) {
  if (fw.last_sync_error) return <span className="text-error small" title={fw.last_sync_error}><span className="dot err" />Fehler</span>
  if (!fw.last_sync_at) return <span className="muted small"><span className="dot" />nie synchronisiert</span>
  const disconnected = fw.central_status?.connected === false
  return (
    <span className="small">
      <span className={`dot ${disconnected ? 'warn' : 'ok'}`} />
      {disconnected ? 'Central: getrennt' : 'OK'} · <span className="muted">{ago(fw.last_sync_at)}</span>
    </span>
  )
}

function GroupModal({ group, onClose, onSaved }) {
  const [name, setName] = useState(group?.name || '')
  const [description, setDescription] = useState(group?.description || '')
  const [error, setError] = useState('')
  const save = async () => {
    try {
      await api(group ? `/groups/${group.id}` : '/groups', { method: group ? 'PUT' : 'POST', body: { name, description } })
      onSaved()
    } catch (e) { setError(e.message) }
  }
  const remove = async () => {
    try { await api(`/groups/${group.id}`, { method: 'DELETE' }); onSaved() } catch (e) { setError(e.message) }
  }
  return (
    <Modal title={group ? 'Gruppe bearbeiten' : 'Neue Firewall-Gruppe'} onClose={onClose}>
      <div className="stack">
        <Field label="Name" hint={group?.central ? 'Aus Sophos Central – Name wird dort gepflegt' : ''}>
          <input value={name} disabled={group?.central} onChange={(e) => setName(e.target.value)} />
        </Field>
        <Field label="Beschreibung"><input value={description} onChange={(e) => setDescription(e.target.value)} /></Field>
        <div className="muted small">Gruppen steuern Berechtigungen: Rollen können auf einzelne Gruppen beschränkt werden.</div>
        <ErrorBox error={error} />
      </div>
      <div className="modal-foot">
        {group && !group.central && <button className="danger" onClick={remove}>Löschen</button>}
        <button onClick={onClose}>Abbrechen</button>
        <button className="primary" disabled={!name} onClick={save}>Speichern</button>
      </div>
    </Modal>
  )
}

export default function Firewalls() {
  const { me } = useAuth()
  const nav = useNavigate()
  const [fws, error, reload] = useLoad(() => api('/firewalls'), [])
  const [groups, , reloadGroups] = useLoad(() => api('/groups'), [])
  const [adding, setAdding] = useState(false)
  const [groupEdit, setGroupEdit] = useState(null)
  const [q, setQ] = useState('')
  const manage = can(me, 'firewall.manage')
  const mayAdd = canAnywhere(me, 'firewall.manage')

  const f = q.toLowerCase()
  const shown = (fws || []).filter((x) => !f || `${x.name} ${x.hostname} ${x.serial} ${x.model}`.toLowerCase().includes(f))
  const byGroup = new Map()
  for (const g of groups || []) byGroup.set(g.id, { group: g, items: [] })
  byGroup.set(null, { group: { id: null, name: 'Ohne Gruppe' }, items: [] })
  for (const fw of shown) (byGroup.get(fw.group_id) || byGroup.get(null)).items.push(fw)

  return (
    <>
      <div className="page-head">
        <h1>Firewalls</h1>
        <span className="sub">{fws?.length ?? 0} verwaltet</span>
        <div className="right row">
          <input placeholder="Suchen …" value={q} onChange={(e) => setQ(e.target.value)} style={{ width: 200 }} />
          {manage && <button onClick={() => setGroupEdit({})}>Neue Gruppe</button>}
          {mayAdd && <button className="primary" onClick={() => setAdding(true)}>Firewall hinzufügen</button>}
        </div>
      </div>
      <ErrorBox error={error} />
      {fws && !fws.length && (
        <div className="panel"><Empty>
          Noch keine Firewalls. {me.is_superadmin || me.permissions.global.includes('admin')
            ? <>Firewalls über <Link to="/admin/central">Sophos Central</Link> übernehmen oder direkt per XML-API hinzufügen.</>
            : 'Bitte einen Administrator, Firewalls anzubinden oder Ihnen Rechte zu geben.'}
        </Empty></div>
      )}
      {[...byGroup.values()].filter((g) => g.items.length || (manage && g.group.id)).map(({ group, items }) => (
        <div className="panel" key={group.id || 'none'} style={{ marginBottom: 14 }}>
          <div className="panel-head">
            <h3>{group.name}</h3>
            {group.central && <span className="badge b-info">Sophos Central</span>}
            <span className="muted small">{items.length} Firewall{items.length === 1 ? '' : 's'}</span>
            {manage && group.id && <button className="ghost sm right" onClick={() => setGroupEdit(group)}>Bearbeiten</button>}
          </div>
          {items.length > 0 && (
            <div className="table-wrap">
              <table>
                <thead><tr><th>Name</th><th>Modell / Firmware</th><th>Anbindung</th><th>Status</th><th>Offene Anträge</th></tr></thead>
                <tbody>
                  {items.map((fw) => (
                    <tr key={fw.id} className="clickable" onClick={() => nav(`/firewalls/${fw.id}`)}>
                      <td><Link to={`/firewalls/${fw.id}`} onClick={(e) => e.stopPropagation()}><b>{fw.name}</b></Link>
                        <div className="small muted">{fw.hostname || fw.api_url} {fw.serial && `· ${fw.serial}`}</div></td>
                      <td className="small">{fw.model?.split('_')[0] || '–'}<div className="muted">{fw.firmware || ''}</div></td>
                      <td><span className={`badge ${fw.connector === 'central' ? 'b-info' : 'b-accent'}`}>{fw.connector_label}</span></td>
                      <td><SyncState fw={fw} /></td>
                      <td>{fw.open_changes ? <span className="badge st-pending">{fw.open_changes}</span> : <span className="muted">–</span>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      ))}
      {adding && <Modal title="Firewall per XML-API hinzufügen" onClose={() => setAdding(false)} wide>
        <FirewallForm groups={groups || []} onCancel={() => setAdding(false)}
          onSaved={(fw) => { setAdding(false); reload(); nav(`/firewalls/${fw.id}`) }} />
      </Modal>}
      {groupEdit && <GroupModal group={groupEdit.id ? groupEdit : null} onClose={() => setGroupEdit(null)}
        onSaved={() => { setGroupEdit(null); reloadGroups(); reload() }} />}
    </>
  )
}
