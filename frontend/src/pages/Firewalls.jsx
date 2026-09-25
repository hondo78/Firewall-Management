import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useAuth } from '../App'
import { ago, api, can } from '../api'
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

function DriftModal({ group, firewalls, onClose }) {
  const [ref, setRef] = useState(firewalls[0]?.id || '')
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  const [open, setOpen] = useState(null)
  const run = async (id) => {
    setRef(id)
    setError('')
    try { setData(await api(`/groups/${group.id}/drift?reference=${id}`)) } catch (e) { setError(e.message) }
  }
  return (
    <Modal title={`Abgleich „${group.name}“`} onClose={onClose} wide>
      <div className="stack">
        <Field label="Referenz (Standard-Konfiguration)">
          <select value={ref} onChange={(e) => run(e.target.value)}>
            <option value="">– wählen –</option>
            {firewalls.map((f) => <option key={f.id} value={f.id}>{f.name}</option>)}
          </select>
        </Field>
        {!data && ref && <div><button className="primary" onClick={() => run(ref)}>Abgleichen</button></div>}
        <ErrorBox error={error} />
        {data && (
          <div className="table-wrap"><table>
            <thead><tr><th>Firewall</th><th>Abweichungen</th><th>Details</th></tr></thead>
            <tbody>{data.firewalls.map((row) => (
              <tr key={row.id}>
                <td><Link to={`/firewalls/${row.id}/compare`}>{row.name}</Link></td>
                <td>{row.error ? <span className="muted">{row.error}</span>
                  : row.total ? <span className="badge b-warn">{row.total}</span> : <span className="badge b-ok">keine</span>}</td>
                <td className="small">
                  {Object.entries(row.entities || {}).map(([e, c]) => (
                    <div key={e}>
                      <button className="link" onClick={() => setOpen(open === row.id + e ? null : row.id + e)}>{data.labels[e] || e}</button>:
                      {c.missing ? ` ${c.missing} fehlen` : ''}{c.extra ? ` · ${c.extra} zusätzlich` : ''}{c.different ? ` · ${c.different} abweichend` : ''}
                      {open === row.id + e && <div className="muted">{c.missing_names.length > 0 && <>Fehlen: {c.missing_names.join(', ')}<br /></>}
                        {c.different_names.length > 0 && <>Abweichend: {c.different_names.join(', ')}</>}</div>}
                    </div>))}
                </td>
              </tr>))}
            </tbody>
          </table></div>
        )}
        <div className="muted small">Vergleich der zwischengespeicherten Konfiguration nach Objektnamen. Fehlende Objekte lassen sich per Vorlage oder Sammelantrag nachziehen.</div>
      </div>
    </Modal>
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
  const [drift, setDrift] = useState(null)
  const [q, setQ] = useState('')
  const manage = can(me, 'firewall.manage')
  // Anlegen heißt Verbindung einrichten → nur Superadmin
  const mayAdd = !!me.is_superadmin

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
            ? <>Firewalls per REST-API (API-Key) hinzufügen oder über <Link to="/admin/central">Sophos Central</Link> übernehmen.</>
            : 'Bitte einen Superadmin, Firewalls anzubinden oder Ihnen Rechte zu geben.'}
        </Empty></div>
      )}
      {[...byGroup.values()].filter((g) => g.items.length || (manage && g.group.id)).map(({ group, items }) => (
        <div className="panel" key={group.id || 'none'} style={{ marginBottom: 14 }}>
          <div className="panel-head">
            <h3>{group.name}</h3>
            {group.central && <span className="badge b-info">Sophos Central</span>}
            <span className="muted small">{items.length} Firewall{items.length === 1 ? '' : 's'}</span>
            <div className="right row">
              {group.id && items.length >= 2 && <button className="ghost sm" onClick={() => setDrift({ group, items })}>Abgleich</button>}
              {manage && group.id && <button className="ghost sm" onClick={() => setGroupEdit(group)}>Bearbeiten</button>}
            </div>
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
      {adding && <Modal title="Firewall hinzufügen" onClose={() => setAdding(false)} wide>
        <FirewallForm groups={groups || []} onCancel={() => setAdding(false)}
          onSaved={(fw) => { setAdding(false); reload(); nav(`/firewalls/${fw.id}`) }} />
      </Modal>}
      {drift && <DriftModal group={drift.group} firewalls={drift.items} onClose={() => setDrift(null)} />}
      {groupEdit && <GroupModal group={groupEdit.id ? groupEdit : null} onClose={() => setGroupEdit(null)}
        onSaved={() => { setGroupEdit(null); reloadGroups(); reload() }} />}
    </>
  )
}
