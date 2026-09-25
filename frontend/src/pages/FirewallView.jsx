import { useCallback, useMemo, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { useAuth } from '../App'
import { ACTION_LABEL, api, can, crNo, download, fmt } from '../api'
import { FORM_ENTITIES, ObjectEditor, RuleEditor } from '../components/Editors'
import { PRIMARY_RULES, RULE_TABLE_ENTITIES, anyRuleView, anySummary, canonical, isRestEntity, oname } from '../components/entities'
import { RestObjectEditor, RestRuleEditor } from '../components/RestEditors'
import FirewallForm from '../components/FirewallForm'
import { Chips, DiffTable, Empty, ErrorBox, Field, Modal, Status, Tabs, useLoad } from '../components/ui'
import { SyncState } from './Firewalls'
import Diagnose from '../components/Diagnose'
import CentralTab from './firewall/CentralTab'
import CompareTab from './firewall/CompareTab'
import FirmwareTab from './firewall/FirmwareTab'

const PERM_SHORT = {
  'firewall.view': 'Lesen', 'change.create': 'Beantragen', 'change.approve': 'Genehmigen', 'change.deploy': 'Ausrollen',
  'firewall.manage': 'Verwalten', 'firmware.manage': 'Firmware',
}

// --- Entwurf -------------------------------------------------------------------------------------------------

export function OperationCard({ op, onRemove }) {
  return (
    <div className="op">
      <div className="op-head">
        <span className={`badge ${op.action === 'add' ? 'b-ok' : op.action === 'remove' ? 'b-danger' : 'b-warn'}`}>{ACTION_LABEL[op.action]}</span>
        <b>{op.label}</b><span>„{op.name}“</span>
        {op.position && <span className="muted small">Position: {{ top: 'ganz oben', bottom: 'ganz unten', after: `nach „${op.position.ref}“`, before: `vor „${op.position.ref}“` }[op.position.type]}</span>}
        {onRemove && <button className="ghost sm right" onClick={onRemove}>Aus Entwurf entfernen</button>}
      </div>
      <div className="op-body">
        {op.action === 'remove' ? <div className="muted small">Objekt wird gelöscht.</div> : <DiffTable rows={op.diff} />}
        <details><summary>API-Aufruf ({op.xml?.startsWith('<') ? 'XML' : 'REST'})</summary><pre className="xml">{op.xml}</pre></details>
      </div>
    </div>
  )
}

function SubmitModal({ draft, onClose, onDone, requireTicket }) {
  const [form, setForm] = useState({ title: draft.title || '', justification: '', ticket_ref: '', deploy_after: '' })
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const set = (k) => (e) => setForm({ ...form, [k]: e.target.value })
  const submit = async () => {
    setBusy(true)
    try {
      const body = { ...form, deploy_after: form.deploy_after ? new Date(form.deploy_after).toISOString() : null }
      const r = await api(`/changes/${draft.id}/submit`, { method: 'POST', body })
      onDone(r)
    } catch (e) { setError(e.message) } finally { setBusy(false) }
  }
  return (
    <Modal title={`Antrag ${crNo(draft.number)} einreichen`} onClose={onClose} wide>
      <div className="stack">
        <div className="alert info small">Nach dem Einreichen prüft ein Approver den Antrag (Vier-Augen-Prinzip). Sie können Ihren eigenen Antrag nicht genehmigen.</div>
        <div className="form-grid">
          <Field label="Titel"><input value={form.title} onChange={set('title')} autoFocus placeholder="z. B. Freigabe HTTPS für neuen Webserver" /></Field>
          <Field label={`Ticket-Referenz${requireTicket ? ' (Pflicht)' : ''}`}><input value={form.ticket_ref} onChange={set('ticket_ref')} placeholder="CHG-1234" /></Field>
          <Field label="Frühestens ausrollen ab" hint="leer = sofort nach Genehmigung">
            <input type="datetime-local" value={form.deploy_after} onChange={set('deploy_after')} />
          </Field>
        </div>
        <Field label="Begründung"><textarea rows={3} value={form.justification} onChange={set('justification')}
          placeholder="Warum wird die Änderung benötigt? Wer hat sie angefordert?" /></Field>
        <h3>{draft.operations.length} Änderung(en)</h3>
        {draft.operations.map((op, i) => <OperationCard key={i} op={op} />)}
        <ErrorBox error={error} />
      </div>
      <div className="modal-foot">
        <button onClick={onClose}>Abbrechen</button>
        <button className="primary" disabled={busy || !form.title || !form.justification} onClick={submit}>Zur Genehmigung einreichen</button>
      </div>
    </Modal>
  )
}

function DraftBar({ draft, onChanged, requireTicket }) {
  const nav = useNavigate()
  const { refreshCounts } = useAuth()
  const [show, setShow] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState('')
  if (!draft?.operations?.length) return null
  const removeOp = async (i) => {
    try { await api(`/changes/${draft.id}/operations/${i}`, { method: 'DELETE' }); onChanged() } catch (e) { setError(e.message) }
  }
  const discard = async () => {
    try { await api(`/changes/${draft.id}/withdraw`, { method: 'POST' }); setShow(false); onChanged() } catch (e) { setError(e.message) }
  }
  return (
    <>
      <div className="draftbar">
        <span className="badge b-accent">Entwurf {crNo(draft.number)}</span>
        <b>{draft.operations.length} Änderung{draft.operations.length === 1 ? '' : 'en'}</b>
        <span className="muted small">noch nicht aktiv – erst nach Genehmigung und Ausrollen</span>
        <div className="right row">
          <button onClick={() => setShow(true)}>Anzeigen</button>
          <button className="primary" onClick={() => setSubmitting(true)}>Einreichen …</button>
        </div>
      </div>
      {show && (
        <Modal title={`Entwurf ${crNo(draft.number)}`} onClose={() => setShow(false)} wide>
          {draft.operations.map((op, i) => <OperationCard key={i} op={op} onRemove={() => removeOp(i)} />)}
          <ErrorBox error={error} />
          <div className="modal-foot">
            <button className="danger" onClick={discard}>Entwurf verwerfen</button>
            <button onClick={() => setShow(false)}>Schließen</button>
            <button className="primary" onClick={() => { setShow(false); setSubmitting(true) }}>Einreichen …</button>
          </div>
        </Modal>
      )}
      {submitting && <SubmitModal draft={draft} requireTicket={requireTicket} onClose={() => setSubmitting(false)}
        onDone={(cr) => { setSubmitting(false); refreshCounts(); nav(`/changes/${cr.id}`) }} />}
    </>
  )
}

// --- Konfiguration (Config-Studio-Ansicht) -------------------------------------------------------------------

function PendingBadges({ pending, draftAction }) {
  return (
    <span className="chips">
      {draftAction && <span className={`badge ${draftAction === 'add' ? 'b-ok' : draftAction === 'remove' ? 'b-danger' : 'b-warn'}`}>
        Entwurf: {ACTION_LABEL[draftAction]}</span>}
      {(pending || []).filter((p) => p.status !== 'draft').map((p) => (
        <Link key={p.change_id} to={`/changes/${p.change_id}`} className={`badge st-${p.status}`} title={`${ACTION_LABEL[p.action]} – ${p.status}`}>
          {crNo(p.number)}
        </Link>
      ))}
    </span>
  )
}

function buildRows(entity, objects, preview, showDraft, draftOps) {
  const orig = objects[entity] || []
  if (!showDraft) return orig.map((o) => ({ obj: o, state: '' }))
  const origBy = Object.fromEntries(orig.map((o) => [oname(o), o]))
  const opBy = Object.fromEntries(draftOps.filter((o) => o.entity === entity).map((o) => [o.name, o.action]))
  const rows = (preview[entity] || []).map((o) => ({
    obj: o,
    state: !origBy[oname(o)] ? 'add' : (opBy[oname(o)] === 'update' || canonical(origBy[oname(o)]) !== canonical(o)) ? 'update' : '',
  }))
  orig.forEach((o, i) => {
    if (opBy[oname(o)] === 'remove') rows.splice(Math.min(i, rows.length), 0, { obj: o, state: 'remove' })
  })
  return rows
}

function ObjectDetail({ fw, entity, obj, onClose }) {
  const [d] = useLoad(() => api(`/firewalls/${fw.id}/objects/${entity}/${encodeURIComponent(oname(obj))}/xml`), [entity, oname(obj)])
  return (
    <Modal title={oname(obj)} onClose={onClose} wide>
      {d?.used_by?.length > 0 && <div className="alert info small">Verwendet von: {d.used_by.join(', ')}</div>}
      <pre className="xml">{d?.xml || 'Lade …'}</pre>
    </Modal>
  )
}

function RuleTable({ entity, rows, fw, mayEdit, pendingBy, draftBy, onEdit, onOp, onShow }) {
  const names = rows.filter((r) => r.state !== 'remove').map((r) => oname(r.obj))
  const rest = isRestEntity(entity)
  if (!rows.length) return <Empty>Keine Firewall-Regeln.</Empty>
  return (
    <div className="table-wrap">
      <table>
        <thead><tr><th>#</th><th>Regel</th><th>Quelle</th><th>Ziel</th><th>Dienste</th><th>Aktion</th><th /></tr></thead>
        <tbody>
          {rows.map(({ obj, state }, i) => {
            const v = anyRuleView(entity, obj)
            const name = oname(obj)
            const desc = rest ? obj.description : obj.Description
            const idx = names.indexOf(name)
            const cls = state ? `row-${state}` : !v.enabled ? 'row-disabled' : ''
            return (
              <tr key={`${name}-${state}`} className={cls}>
                <td className="muted small">{state === 'remove' ? '–' : idx + 1}</td>
                <td className="name">
                  <button className="link" style={{ color: 'inherit', textDecoration: 'none', fontWeight: 600 }} onClick={() => onShow(obj)}>{name}</button>
                  {!v.enabled && <span className="badge st-Disable" style={{ marginLeft: 6 }}>inaktiv</span>}
                  {v.type === 'waf' && <span className="badge b-info" style={{ marginLeft: 6 }}>WAF</span>}
                  {desc && <div className="small muted">{desc}</div>}
                  <div style={{ marginTop: 3 }}><PendingBadges pending={pendingBy[name]} draftAction={draftBy[name]} /></div>
                </td>
                <td><Chips items={v.srcZones} kind="zone" /><div style={{ marginTop: 3 }}><Chips items={v.srcNets} /></div></td>
                <td><Chips items={v.dstZones} kind="zone" /><div style={{ marginTop: 3 }}><Chips items={v.dstNets} /></div></td>
                <td><Chips items={v.services} />{v.schedule && v.schedule !== 'All The Time' && <div className="small muted">⏱ {v.schedule}</div>}</td>
                <td><span className={`badge st-${v.action}`}>{{ Accept: 'Zulassen', Drop: 'Verwerfen', Reject: 'Ablehnen' }[v.action] || v.action}</span>
                  {v.log && <div className="small muted">protokolliert</div>}</td>
                <td className="actions">
                  {mayEdit && state !== 'remove' && <>
                    <button className="ghost sm" title="Nach oben" disabled={idx <= 0}
                      onClick={() => onOp({ entity, action: 'update', name, data: obj, position: { type: 'before', ref: names[idx - 1] } })}>↑</button>
                    <button className="ghost sm" title="Nach unten" disabled={idx >= names.length - 1}
                      onClick={() => onOp({ entity, action: 'update', name, data: obj, position: { type: 'after', ref: names[idx + 1] } })}>↓</button>
                    <button className="ghost sm" onClick={() => onOp({ entity, action: 'update', name, data: rest ? { ...obj, enabled: !v.enabled } : { ...obj, Status: v.enabled ? 'Disable' : 'Enable' } })}>
                      {v.enabled ? 'Deaktivieren' : 'Aktivieren'}</button>
                    <button className="ghost sm" onClick={() => onEdit(obj)}>Bearbeiten</button>
                    {fw.capabilities.remove && <button className="ghost sm" style={{ color: 'var(--danger)' }}
                      onClick={() => onOp({ entity, action: 'remove', name })}>Löschen</button>}
                  </>}
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

function ObjectTable({ entity, rows, fw, mayEdit, pendingBy, draftBy, onEdit, onOp, onShow }) {
  if (!rows.length) return <Empty>Keine Objekte dieses Typs.</Empty>
  return (
    <div className="table-wrap">
      <table>
        <thead><tr><th>Name</th><th>Details</th><th>Beschreibung</th><th /></tr></thead>
        <tbody>
          {rows.map(({ obj, state }) => (
            <tr key={`${oname(obj)}-${state}`} className={state ? `row-${state}` : ''}>
              <td className="name"><button className="link" style={{ color: 'inherit', textDecoration: 'none', fontWeight: 600 }} onClick={() => onShow(obj)}>{oname(obj)}</button>
                <div><PendingBadges pending={pendingBy[oname(obj)]} draftAction={draftBy[oname(obj)]} /></div></td>
              <td className="small">{anySummary(entity, obj)}</td>
              <td className="small muted">{obj.Description || obj.description || ''}</td>
              <td className="actions">
                {mayEdit && state !== 'remove' && <>
                  <button className="ghost sm" onClick={() => onEdit(obj)}>Bearbeiten</button>
                  {fw.capabilities.remove && !obj.isInternal && <button className="ghost sm" style={{ color: 'var(--danger)' }}
                    onClick={() => onOp({ entity, action: 'remove', name: oname(obj) })}>Löschen</button>}
                  {obj.isInternal && <span className="badge" title="Eingebautes Objekt der Firewall">vordefiniert</span>}
                </>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function ConfigTab({ fw, cfg, draft, reload }) {
  const { me } = useAuth()
  const [entity, setEntity] = useState(PRIMARY_RULES[cfg.format] || 'FirewallRule')
  const isRuleTable = RULE_TABLE_ENTITIES.has(entity)
  const rest = cfg.format === 'rest'
  const [showDraft, setShowDraft] = useState(true)
  const [editing, setEditing] = useState(null)   // {obj|null}
  const [detail, setDetail] = useState(null)
  const [q, setQ] = useState('')
  const [msg, setMsg] = useState(null)
  const mayEdit = can(me, 'change.create', fw) && !!fw.last_sync_at
  const draftOps = draft?.operations || []
  const meta = cfg.entities.find((e) => e.entity === entity)

  const pendingBy = useMemo(() => {
    const out = {}
    for (const p of cfg.pending) if (p.entity === entity) out[p.name] = p.changes
    return out
  }, [cfg, entity])
  const draftBy = Object.fromEntries(draftOps.filter((o) => o.entity === entity).map((o) => [o.name, o.action]))
  const pendingEntities = new Set([...cfg.pending.map((p) => p.entity), ...draftOps.map((o) => o.entity)])

  const f = q.toLowerCase()
  const rows = buildRows(entity, cfg.objects, cfg.preview, showDraft, draftOps)
    .filter((r) => !f || JSON.stringify(r.obj).toLowerCase().includes(f))

  const addOp = useCallback(async (op) => {
    setMsg(null)
    const r = await api(`/firewalls/${fw.id}/draft/operations`, { method: 'POST', body: op })
    reload()
    return r
  }, [fw.id, reload])
  const quickOp = async (op) => {
    try {
      const r = await addOp(op)
      setMsg({ kind: r.warnings.length ? 'warn' : 'ok', text: r.warnings.length ? r.warnings.join(' · ') : `In Entwurf übernommen: ${ACTION_LABEL[op.action]} „${op.name}“` })
    } catch (e) { setMsg({ kind: 'error', text: e.message }) }
  }

  const sections = [...new Set(cfg.entities.map((e) => e.section))]
  const editorConfig = cfg.preview
  return (
    <div className="studio">
      <div className="panel entity-nav">
        {sections.map((s) => (
          <div key={s}>
            <div className="sec">{s}</div>
            {cfg.entities.filter((e) => e.section === s).map((e) => (
              <button key={e.entity} className={entity === e.entity ? 'active' : ''} onClick={() => { setEntity(e.entity); setQ('') }}>
                {e.label}{pendingEntities.has(e.entity) && <span className="p" title="Geplante Änderungen" />}<span className="n">{e.count}</span>
              </button>
            ))}
          </div>
        ))}
      </div>
      <div className="panel">
        <div className="panel-head">
          <h3>{meta?.label}</h3>
          <input placeholder="Filtern …" value={q} onChange={(e) => setQ(e.target.value)} style={{ width: 180 }} />
          {draftOps.length > 0 && <label className="check small"><input type="checkbox" checked={showDraft} onChange={(e) => setShowDraft(e.target.checked)} />mit meinem Entwurf</label>}
          <div className="right row">
            {mayEdit && (rest || entity === 'FirewallRule' || FORM_ENTITIES.includes(entity) || ['Zone', 'Schedule', 'MACHost', 'NATRule', 'FirewallRuleGroup'].includes(entity)) &&
              <button className="primary sm" onClick={() => setEditing({ obj: null })}>+ Neu</button>}
          </div>
        </div>
        {msg && <div style={{ padding: '0 16px' }}><div className={`alert ${msg.kind} small`}>{msg.text}</div></div>}
        {!fw.last_sync_at && <div className="alert warn" style={{ margin: 16 }}>Noch keine Konfiguration geladen – bitte „Jetzt synchronisieren“.</div>}
        {isRuleTable
          ? <RuleTable entity={entity} rows={rows} fw={fw} mayEdit={mayEdit} pendingBy={pendingBy} draftBy={draftBy}
            onEdit={(obj) => setEditing({ obj })} onOp={quickOp} onShow={setDetail} />
          : <ObjectTable entity={entity} rows={rows} fw={fw} mayEdit={mayEdit} pendingBy={pendingBy} draftBy={draftBy}
            onEdit={(obj) => setEditing({ obj })} onOp={quickOp} onShow={setDetail} />}
        {!fw.capabilities.remove && mayEdit && <div className="muted small" style={{ padding: '8px 16px' }}>
          Löschen ist über den Sophos-Central-Import nicht möglich – Regeln stattdessen deaktivieren oder die Firewall per REST-API anbinden.</div>}
      </div>
      {editing && rest && (entity.startsWith('firewallRules')
        ? <RestRuleEditor entity={entity} config={editorConfig} rule={editing.obj} onClose={() => setEditing(null)} onSubmit={addOp} />
        : <RestObjectEditor entity={entity} label={meta.label} config={editorConfig} object={editing.obj}
          onClose={() => setEditing(null)} onSubmit={addOp} />)}
      {editing && !rest && (entity === 'FirewallRule'
        ? <RuleEditor config={editorConfig} rule={editing.obj} onClose={() => setEditing(null)} onSubmit={addOp} />
        : <ObjectEditor entity={entity} label={meta.label} config={editorConfig} object={editing.obj}
          onClose={() => setEditing(null)} onSubmit={addOp} />)}
      {detail && <ObjectDetail fw={fw} entity={entity} obj={detail} onClose={() => setDetail(null)} />}
    </div>
  )
}

// --- Weitere Tabs --------------------------------------------------------------------------------------------

function ChangesTab({ fw }) {
  const [rows] = useLoad(() => api(`/firewalls/${fw.id}/changes`), [fw.id])
  if (!rows) return null
  if (!rows.length) return <div className="panel"><Empty>Noch keine Anträge für diese Firewall.</Empty></div>
  return (
    <div className="panel table-wrap">
      <table>
        <thead><tr><th>Nr.</th><th>Titel</th><th>Antragsteller</th><th>Status</th><th>Eingereicht</th><th>Ausgerollt</th></tr></thead>
        <tbody>{rows.map((c) => (
          <tr key={c.id}>
            <td><Link to={`/changes/${c.id}`}>{crNo(c.number)}</Link></td><td>{c.title}</td><td>{c.created_by}</td>
            <td><Status value={c.status} /></td><td className="small">{fmt(c.submitted_at)}</td><td className="small">{fmt(c.deployed_at)}</td>
          </tr>))}
        </tbody>
      </table>
    </div>
  )
}

function SettingsTab({ fw, onSaved }) {
  const nav = useNavigate()
  const [groups] = useLoad(() => api('/groups'), [])
  const [test, setTest] = useState(null)
  const [error, setError] = useState('')
  const [confirm, setConfirm] = useState(false)
  const runTest = async () => { setTest({ message: 'Teste …' }); setTest(await api(`/firewalls/${fw.id}/test`, { method: 'POST' })) }
  const remove = async () => {
    try { await api(`/firewalls/${fw.id}`, { method: 'DELETE' }); nav('/firewalls') } catch (e) { setError(e.message) }
  }
  return (
    <div className="grid two">
      <div className="panel panel-pad">
        <h3 style={{ marginTop: 0 }}>Anbindung</h3>
        {groups && <FirewallForm fw={fw} groups={groups} onSaved={onSaved} />}
      </div>
      <div className="stack">
        <div className="panel panel-pad stack">
          <h3 style={{ margin: 0 }}>Verbindungstest</h3>
          <div><button onClick={runTest}>Verbindung testen</button></div>
          {test && <div className={`alert ${test.ok === undefined ? 'info' : test.ok ? 'ok' : 'error'} small`}>{test.message}</div>}
        </div>
        <div className="panel panel-pad stack">
          <h3 style={{ margin: 0 }}>Probelauf</h3>
          <div className="muted small">Prüft Anmeldung, Leserechte und alle benötigten Endpunkte, bevor Änderungen ausgerollt werden.</div>
          <Diagnose path={`/firewalls/${fw.id}/diagnose`} />
        </div>
        {fw.central_id && <div className="panel panel-pad small">
          <h3 style={{ marginTop: 0 }}>Sophos Central</h3>
          <div>Firewall-ID: <code>{fw.central_id}</code></div>
          <div>Status: {Object.entries(fw.central_status || {}).filter(([, v]) => typeof v !== 'object').map(([k, v]) => `${k}: ${v}`).join(' · ')}</div>
          {fw.external_ips?.length > 0 && <div>Externe IPs: {fw.external_ips.join(', ')}</div>}
        </div>}
        <div className="panel panel-pad stack">
          <h3 style={{ margin: 0 }}>Aus der Verwaltung entfernen</h3>
          <div className="muted small">Die Firewall selbst bleibt unverändert. Anträge, Versionsstände und Audit-Log bleiben erhalten (archiviert); gespeicherte Zugangsdaten werden gelöscht.</div>
          {!confirm ? <div><button className="danger" onClick={() => setConfirm(true)}>Entfernen …</button></div>
            : <div className="row"><button className="danger solid" onClick={remove}>Wirklich entfernen</button><button onClick={() => setConfirm(false)}>Abbrechen</button></div>}
          <ErrorBox error={error} />
        </div>
      </div>
    </div>
  )
}

// --- Seite ---------------------------------------------------------------------------------------------------

export default function FirewallView() {
  const { id, tab = 'config' } = useParams()
  const nav = useNavigate()
  const { me } = useAuth()
  const [fw, error, reloadFw, setFw] = useLoad(() => api(`/firewalls/${id}`), [id])
  const [cfg, cfgError, reloadCfg] = useLoad(() => api(`/firewalls/${id}/config`), [id])
  const [draft, , reloadDraft] = useLoad(() => api(`/firewalls/${id}/draft`), [id])
  const [settings] = useLoad(() => api('/settings'), [])
  const [syncing, setSyncing] = useState(false)
  const [syncMsg, setSyncMsg] = useState(null)

  const reload = useCallback(() => { reloadCfg(); reloadDraft() }, [reloadCfg, reloadDraft])
  const sync = async () => {
    setSyncing(true)
    setSyncMsg(null)
    try {
      const r = await api(`/firewalls/${id}/sync`, { method: 'POST' })
      setSyncMsg({ kind: 'ok', text: r.changed ? 'Synchronisiert – Konfiguration hat sich geändert (neuer Versionsstand).' : 'Synchronisiert – keine Änderungen.' })
    } catch (e) { setSyncMsg({ kind: 'error', text: e.message }) }
    setSyncing(false)
    reloadFw()
    reload()
  }
  if (error) return <ErrorBox error={error} />
  if (!fw) return null
  const tabs = [['config', 'Konfiguration'], ['compare', 'Vergleich & Versionen'], ['changes', 'Anträge'],
    fw.central_id && ['firmware', 'Firmware'], fw.central_id && ['central', 'Lizenzen & Alerts'], can(me, 'firewall.manage', fw) && ['settings', 'Einstellungen']]

  return (
    <>
      <div className="page-head">
        <div>
          <div className="small"><Link to="/firewalls">Firewalls</Link>{fw.group && <span className="muted"> › {fw.group}</span>}</div>
          <h1>{fw.name}</h1>
        </div>
        <div className="right row">
          {fw.capabilities.format === 'rest'
            ? <button className="sm" onClick={() => download(`/firewalls/${fw.id}/export.json`, `Konfiguration-${fw.name}.json`)}
              title="Zwischengespeicherte Konfiguration im Format der REST-API">JSON-Export</button>
            : <button className="sm" onClick={() => download(`/firewalls/${fw.id}/export.xml`, `Entities-${fw.name}.xml`)}
            title="Zwischengespeicherte Konfiguration als Entities.xml – z. B. für Sophos Config Studio">Entities.xml</button>}
          <button className="primary sm" disabled={syncing} onClick={sync}>{syncing ? 'Synchronisiere …' : 'Jetzt synchronisieren'}</button>
        </div>
      </div>
      <div className="panel fw-head">
        <div className="meta">
          <div><span>Status</span><SyncState fw={fw} /></div>
          <div><span>Anbindung</span>{fw.connector_label}</div>
          {fw.connector === 'rest' && <div><span>API-Key gültig bis</span>{fw.api_key_expires_at
            ? <span className={new Date(fw.api_key_expires_at) - Date.now() < 30 * 86400000 ? 'text-error' : ''}>{fmt(fw.api_key_expires_at).split(',')[0]}</span>
            : <span className="muted">nicht hinterlegt</span>}</div>}
          <div><span>Modell</span>{fw.model?.split('_')[0] || '–'}</div>
          <div><span>Firmware</span>{fw.firmware || '–'}</div>
          <div><span>Seriennummer</span>{fw.serial || '–'}</div>
          <div><span>Hostname</span>{fw.hostname || fw.api_url || '–'}</div>
          <div><span>Ihre Rechte</span>{fw.permissions.length ? fw.permissions.map((p) => PERM_SHORT[p] || p).join(', ') : '–'}</div>
        </div>
      </div>
      {fw.last_sync_error && <div className="alert error small">Letzte Synchronisation fehlgeschlagen: {fw.last_sync_error}</div>}
      {syncMsg && <div className={`alert ${syncMsg.kind} small`}>{syncMsg.text}</div>}
      <Tabs tabs={tabs} value={tab} onChange={(t) => nav(`/firewalls/${id}/${t}`)} />
      {tab === 'config' && (cfgError ? <ErrorBox error={cfgError} /> : cfg && <ConfigTab key={cfg.format} fw={fw} cfg={cfg} draft={draft} reload={reload} />)}
      {tab === 'compare' && <CompareTab fw={fw} />}
      {tab === 'changes' && <ChangesTab fw={fw} />}
      {tab === 'firmware' && <FirmwareTab fw={fw} />}
      {tab === 'central' && <CentralTab fw={fw} />}
      {tab === 'settings' && <SettingsTab fw={fw} onSaved={(f) => { setFw({ ...fw, ...f }); reload() }} />}
      <DraftBar draft={draft} onChanged={reload} requireTicket={settings?.require_ticket} />
    </>
  )
}
