import { Fragment, useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { useAuth } from '../../App'
import { ACTION_LABEL, api, can, crNo, download, upload } from '../../api'
import { BULK, BULK_KIND, parseBulk } from '../../components/bulk'
import { COLUMNS, searchText } from '../../components/columns'
import { ObjectEditor, RuleEditor } from '../../components/Editors'
import { READ_ONLY_ENTITIES, RULE_TABLE_ENTITIES, PRIMARY_RULES, anyRuleView, asList, canonical, isRestEntity, oname } from '../../components/entities'
import Icon, { ENTITY_ICON } from '../../components/icons'
import { RestObjectEditor } from '../../components/RestEditors'
import { ObjectView } from '../../components/SophosPolicies'
import { FeatureBadges, RuleDetails, SophosNatEditor, SophosRuleEditor, natView } from '../../components/SophosRules'
import { DiffTable, Empty, ErrorBox, Modal, Seg, useLoad } from '../../components/ui'
import { OperationCard } from '../FirewallView'

/** Konfigurations-Editor im Stil des Sophos Firewall Config Studio. */

const SECTION_ICON = { 'Regeln & Richtlinien': 'rule', 'Hosts & Dienste': 'host', Netzwerk: 'zone', System: 'clock' }
const SEV_CLASS = { high: 'b-danger', medium: 'b-warn', info: '' }
const store = {
  get(k, d) { try { const v = localStorage.getItem(k); return v == null ? d : JSON.parse(v) } catch { return d } },
  set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)) } catch { /* privater Modus */ } },
}

/** Schließt ein Menü bei Klick außerhalb oder Escape. */
function useDismiss(open, setOpen) {
  const ref = useRef(null)
  useEffect(() => {
    if (!open) return undefined
    const onDown = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false) }
    const onKey = (e) => { if (e.key === 'Escape') { e.stopPropagation(); setOpen(false) } }
    document.addEventListener('mousedown', onDown)
    document.addEventListener('keydown', onKey, true)
    return () => { document.removeEventListener('mousedown', onDown); document.removeEventListener('keydown', onKey, true) }
  }, [open, setOpen])
  return ref
}

// --- Hilfen --------------------------------------------------------------------------------------------------

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

function Analysis({ findings }) {
  if (!findings?.length) return <span className="muted small">–</span>
  const worst = findings.find((f) => f.severity === 'high') || findings.find((f) => f.severity === 'medium') || findings[0]
  return (
    <span className={`badge ${SEV_CLASS[worst.severity]}`} title={findings.map((f) => `• ${f.message}`).join('\n')}>
      {findings.length === 1 ? { any_any: 'zu offen', wan_open: 'offen (WAN)', no_log_wan: 'ohne Log', shadowed: 'verdeckt', disabled: 'inaktiv', unused: 'ungenutzt', duplicate_address: 'doppelt' }[worst.code] || worst.code : `${findings.length} Hinweise`}
    </span>
  )
}

/** Chips mit Obergrenze – Rest als „+N“ (vollständige Liste im Tooltip). */
function FewChips({ items, kind, max = 4 }) {
  if (!items?.length) return <span className="chip any">Beliebig</span>
  const rest = items.length - max
  return (
    <span className="chips" title={rest > 0 ? items.join(', ') : undefined}>
      {items.slice(0, max).map((i) => <span key={i} className={`chip ${kind || ''}`}>{i}</span>)}
      {rest > 0 && <span className="chip more">+{rest}</span>}
    </span>
  )
}

function IconButton({ icon, title, onClick, danger, disabled }) {
  return (
    <button className={`icon-btn ${danger ? 'danger' : ''}`} title={title} aria-label={title} onClick={onClick} disabled={disabled}>
      <Icon name={icon} size={15} />
    </button>
  )
}

function StructuredView({ entity, obj }) {
  if (entity.startsWith('firewallRules')) return <><div style={{ marginBottom: 10 }}><FeatureBadges rule={obj} /></div><RuleDetails rule={obj} /></>
  if (entity === 'natRulesIpv4') {
    const n = natView(obj)
    const L = ({ label, children }) => <div className="sf-line"><span>{label}</span><div>{children}</div></div>
    return (
      <div className="sf-details">
        <div><h5>Original</h5><L label="Quelle">{n.oSrc.join(', ') || 'Beliebig'}</L><L label="Ziel">{n.oDst.join(', ') || 'Beliebig'}</L><L label="Dienste">{n.oSvc.join(', ') || 'Beliebig'}</L></div>
        <div><h5>Übersetzt</h5><L label="Quelle">{n.tSrc}</L><L label="Ziel">{n.tDst}</L><L label="Dienst">{n.tSvc}</L></div>
        <div><h5>Schnittstellen</h5><L label="Eingehend">{n.inIf || 'Beliebig'}</L><L label="Ausgehend">{n.outIf || 'Beliebig'}</L></div>
        <div><h5>Weitere</h5><L label="Status">{n.enabled ? 'aktiv' : 'inaktiv'}</L><L label="Verknüpfte Regel">{n.linked || '–'}</L></div>
      </div>
    )
  }
  return <ObjectView entity={entity} obj={obj} />
}

function ObjectDetail({ fw, entity, obj, onClose }) {
  const [d] = useLoad(() => api(`/firewalls/${fw.id}/objects/${entity}/${encodeURIComponent(oname(obj))}/xml`), [entity, oname(obj)])
  const view = isRestEntity(entity) ? StructuredView({ entity, obj }) : null
  const [mode, setMode] = useState(view ? 'view' : 'raw')
  const raw = isRestEntity(entity) ? 'JSON' : 'XML'
  return (
    <Modal title={oname(obj)} onClose={onClose} wide>
      {d?.used_by?.length > 0 && <div className="alert info small">Verwendet von: {d.used_by.join(', ')}</div>}
      {view && <div style={{ marginBottom: 10 }}><Seg options={[['view', 'Ansicht'], ['raw', raw]]} value={mode} onChange={setMode} /></div>}
      {mode === 'view' ? view : <pre className="xml">{d?.xml || 'Lade …'}</pre>}
    </Modal>
  )
}

// --- Seitenleiste --------------------------------------------------------------------------------------------

function Sidebar({ cfg, entity, onSelect, pendingEntities }) {
  const [q, setQ] = useState('')
  const [closed, setClosed] = useState(() => store.get('fwm.editor.closed', {}))
  const toggle = (s) => { const next = { ...closed, [s]: !closed[s] }; setClosed(next); store.set('fwm.editor.closed', next) }
  const f = q.toLowerCase()
  const sections = [...new Set(cfg.entities.map((e) => e.section))]
  return (
    <aside className="cs-sidebar">
      <div className="cs-menu-search"><Icon name="search" size={14} />
        <input placeholder="Menü durchsuchen …" value={q} onChange={(e) => setQ(e.target.value)} /></div>
      {sections.map((s) => {
        const items = cfg.entities.filter((e) => e.section === s && (!f || e.label.toLowerCase().includes(f)))
        if (!items.length) return null
        return (
          <div key={s}>
            <button className="cs-sec" onClick={() => toggle(s)} aria-expanded={!closed[s]}>
              <Icon name={SECTION_ICON[s] || 'host'} size={13} />{s}
              <Icon name="chevron" size={12} className={`cs-chev ${closed[s] && !f ? '' : 'open'}`} />
            </button>
            {(!closed[s] || f) && items.map((e) => (
              <button key={e.entity} className={`cs-item ${entity === e.entity ? 'active' : ''}`} onClick={() => onSelect(e.entity)}>
                <Icon name={ENTITY_ICON[e.entity] || 'host'} size={15} /><span className="lbl">{e.label}</span>
                {pendingEntities.has(e.entity) && <span className="p" title="Geplante Änderungen" />}
                <span className="n">{e.count}</span>
              </button>
            ))}
          </div>
        )
      })}
    </aside>
  )
}

// --- Dialoge -------------------------------------------------------------------------------------------------

function BulkAddModal({ entity, label, fmt, config, onClose, onAdd }) {
  const kind = BULK_KIND[entity]
  const def = BULK[kind]
  const [text, setText] = useState('')
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState(null)
  const portsAsText = (config.services || []).some((s) => asList(s.services).some((d) => typeof d.destinationPort === 'string'))
  const parsed = useMemo(() => parseBulk(kind, text, fmt, portsAsText), [kind, text, fmt, portsAsText])
  const ok = parsed.filter((p) => !p.error)
  const run = async () => {
    setBusy(true)
    const errors = []
    let added = 0
    for (const p of ok) {
      try { await onAdd({ entity, action: 'add', name: p.name, data: p.data }, true); added += 1 } catch (e) { errors.push(`${p.name}: ${e.message}`) }
    }
    setBusy(false)
    setResult({ added, errors })
  }
  return (
    <Modal title={`Mehrfach hinzufügen: ${label}`} onClose={onClose} wide>
      {!result ? <div className="stack">
        <div className="small"><b>{def.label}</b> – ein Eintrag je Zeile, optional „,Name“.</div>
        <textarea className="code" style={{ minHeight: 180 }} value={text} placeholder={def.placeholder} onChange={(e) => setText(e.target.value)} autoFocus />
        <div className="alert info small"><b>Unterstützte Formate</b>
          <table className="bulk-help"><tbody>{def.help.map(([ex, d]) => <tr key={ex}><td className="mono">{ex}</td><td>→ {d}</td></tr>)}</tbody></table>
          Tipp: Zeilen lassen sich direkt aus einer CSV-Datei einfügen.</div>
        {parsed.length > 0 && (
          <div className="table-wrap" style={{ maxHeight: 240, overflowY: 'auto' }}><table><tbody>
            {parsed.map((p, i) => <tr key={i}><td className="mono small">{p.line}</td>
              <td>{p.error ? <span className="text-error small">{p.error}</span> : <span className="small">{p.name}</span>}</td></tr>)}
          </tbody></table></div>
        )}
        <div className="modal-foot"><button onClick={onClose}>Abbrechen</button>
          <button className="primary" disabled={busy || !ok.length} onClick={run}>{busy ? 'Übernehme …' : `${ok.length} Einträge in den Entwurf`}</button></div>
      </div> : <div className="stack">
        <div className="alert ok">{result.added} Einträge in den Entwurf übernommen.</div>
        {result.errors.length > 0 && <div className="alert warn small">Übersprungen:<ul style={{ margin: '4px 0 0', paddingLeft: 18 }}>{result.errors.map((e) => <li key={e}>{e}</li>)}</ul></div>}
        <div className="modal-foot"><button className="primary" onClick={onClose}>Schließen</button></div>
      </div>}
    </Modal>
  )
}

const IMPORT_STATUS = [['new', 'Neu'], ['changed', 'Geändert'], ['same', 'Identisch'], ['unsupported', 'Nicht übernehmbar']]

function ImportModal({ fw, review, onClose, onApplied }) {
  const [tab, setTab] = useState(review.counts.new ? 'new' : 'changed')
  const [sel, setSel] = useState(() => new Set(review.items.filter((i) => i.status === 'new' || i.status === 'changed').map((i) => i.key)))
  const [q, setQ] = useState('')
  const [open, setOpen] = useState(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const f = q.toLowerCase()
  const list = review.items.filter((i) => i.status === tab && (!f || `${i.name} ${i.label}`.toLowerCase().includes(f)))
  const groups = list.reduce((m, i) => ({ ...m, [i.label]: [...(m[i.label] || []), i] }), {})
  const selectable = tab === 'new' || tab === 'changed'
  const toggle = (k) => { const n = new Set(sel); n.has(k) ? n.delete(k) : n.add(k); setSel(n) }
  const toggleAll = (items) => { const n = new Set(sel); const all = items.every((i) => n.has(i.key)); items.forEach((i) => (all ? n.delete(i.key) : n.add(i.key))); setSel(n) }
  const apply = async () => {
    setBusy(true)
    setError('')
    try { onApplied(await api(`/firewalls/${fw.id}/import/apply`, { method: 'POST', body: { token: review.token, keys: [...sel] } })) } catch (e) { setError(e.message) }
    setBusy(false)
  }
  return (
    <Modal title="Import prüfen" onClose={onClose} wide>
      <div className="stack">
        <div className="muted small">Vergleich der hochgeladenen Konfiguration{review.api_version && ` (API-Version ${review.api_version})`} mit dem aktuellen Stand von „{fw.name}“.
          Ausgewählte Objekte landen in Ihrem Entwurf und werden erst nach Vier-Augen-Freigabe ausgerollt. Die Datei wird nicht gespeichert.</div>
        <div className="seg" style={{ alignSelf: 'flex-start' }}>
          {IMPORT_STATUS.map(([k, l]) => <button key={k} className={tab === k ? 'active' : ''} onClick={() => setTab(k)}>{l} ({review.counts[k]})</button>)}
        </div>
        <input placeholder="Filtern …" value={q} onChange={(e) => setQ(e.target.value)} />
        <div className="table-wrap" style={{ maxHeight: 420, overflowY: 'auto' }}>
          {!list.length ? <Empty>Keine Einträge.</Empty> : <table><tbody>
            {Object.entries(groups).map(([label, items]) => (
              <Fragment key={label}>
                <tr className="group-row"><td colSpan={4}>
                  {selectable && <input type="checkbox" checked={items.every((i) => sel.has(i.key))} onChange={() => toggleAll(items)} style={{ marginRight: 8 }} />}
                  <b>{label}</b> <span className="muted small">({items.length})</span></td></tr>
                {items.map((i) => (
                  <Fragment key={i.key}>
                    <tr>
                      <td style={{ width: 28 }}>{selectable && <input type="checkbox" checked={sel.has(i.key)} onChange={() => toggle(i.key)} />}</td>
                      <td>{i.name}</td>
                      <td className="small muted">{i.reason || (i.diff?.length ? `${i.diff.length} Feld(er) abweichend` : '')}</td>
                      <td className="actions">{i.diff?.length > 0 && <button className="ghost sm" onClick={() => setOpen(open === i.key ? null : i.key)}>Unterschiede</button>}</td>
                    </tr>
                    {open === i.key && <tr><td colSpan={4}><DiffTable rows={i.diff} /></td></tr>}
                  </Fragment>
                ))}
              </Fragment>
            ))}
          </tbody></table>}
        </div>
        <ErrorBox error={error} />
        <div className="modal-foot">
          <button onClick={onClose}>Abbrechen</button>
          <button className="primary" disabled={busy || !sel.size} onClick={apply}>{busy ? 'Übernehme …' : `${sel.size} Objekte in den Entwurf`}</button>
        </div>
      </div>
    </Modal>
  )
}

function GettingStarted({ onHide }) {
  const steps = [
    ['Objekte bearbeiten', 'Links einen Objekttyp wählen und Hosts, Dienste oder Regeln anlegen, ändern oder löschen – alles landet im Entwurf.'],
    ['Konfiguration importieren', 'Optional eine Entities.xml (z. B. aus Config Studio) prüfen und Objekte übernehmen.'],
    ['Vorschau & Einreichen', 'API-Aufrufe in der Vorschau prüfen, mit Begründung einreichen – eine zweite Person genehmigt.'],
    ['Ausrollen', 'Nach der Freigabe rollt das Tool die Änderung per API aus und prüft vorher auf Abweichungen.'],
  ]
  return (
    <div className="cs-steps">
      <div className="row between"><b className="small"><Icon name="bulb" size={14} /> Erste Schritte</b>
        <button className="link small" onClick={onHide}>× Ausblenden</button></div>
      <div className="cs-steps-row">
        {steps.map(([t, d], i) => (
          <div key={t} className="cs-step"><span className="num">{i + 1}</span><div><b className="small">{t}</b><div className="muted small">{d}</div></div></div>
        ))}
      </div>
    </div>
  )
}

// --- Tabelle -------------------------------------------------------------------------------------------------

function ColumnPicker({ cols, visible, onChange }) {
  const [open, setOpen] = useState(false)
  const ref = useDismiss(open, setOpen)
  if (!cols.length) return null
  return (
    <div className="dropdown" ref={ref}>
      <button onClick={() => setOpen(!open)} aria-expanded={open}><Icon name="columns" size={14} /> Spalten</button>
      {open && <div className="dropdown-menu">
        {cols.map((c) => (
          <label key={c.key} className="check"><input type="checkbox" checked={visible.includes(c.key)}
            onChange={() => onChange(visible.includes(c.key) ? visible.filter((k) => k !== c.key) : [...visible, c.key])} />{c.label}</label>
        ))}
      </div>}
    </div>
  )
}

function EntityTable({ entity, meta, rows, fw, mayEdit, pendingBy, draftBy, findings, onEdit, onOp, onShow, onBulkDelete, onAdd, onBulkAdd }) {
  const isRule = RULE_TABLE_ENTITIES.has(entity)
  const isNat = entity === 'natRulesIpv4'
  const rest = isRestEntity(entity)
  const restRule = rest && isRule
  const [open, setOpen] = useState(new Set())
  const toggleOpen = (n) => { const s = new Set(open); s.has(n) ? s.delete(n) : s.add(n); setOpen(s) }
  const cols = COLUMNS[entity] || []
  const [visible, setVisible] = useState(() => store.get(`fwm.cols.${entity}`, cols.filter((c) => !c.hidden).map((c) => c.key)))
  const [q, setQ] = useState('')
  const [onlyFindings, setOnlyFindings] = useState(false)
  const [sel, setSel] = useState(new Set())
  const f = q.toLowerCase()
  const shown = rows.filter((r) => (!f || searchText(r.obj).includes(f)) && (!onlyFindings || findings[oname(r.obj)]?.length))
  const names = rows.filter((r) => r.state !== 'remove').map((r) => oname(r.obj))
  const deletable = (r) => r.state !== 'remove' && !r.obj.isInternal
  const toggle = (n) => { const s = new Set(sel); s.has(n) ? s.delete(n) : s.add(n); setSel(s) }
  const allSel = shown.length > 0 && shown.filter(deletable).every((r) => sel.has(oname(r.obj)))
  const toggleAll = () => setSel(allSel ? new Set() : new Set(shown.filter(deletable).map((r) => oname(r.obj))))
  const setCols = (v) => { setVisible(v); store.set(`fwm.cols.${entity}`, v) }
  const activeCols = cols.filter((c) => visible.includes(c.key))

  return (
    <div className="panel cs-table">
      <div className="panel-head">
        <Icon name={ENTITY_ICON[entity] || 'host'} size={18} className="text-accent" />
        <h3>{meta.label} <span className="muted" style={{ fontWeight: 400 }}>({rows.filter((r) => r.state !== 'remove').length})</span></h3>
        {mayEdit && <div className="right row">
          <button className="sm" disabled={!sel.size} onClick={() => setSel(new Set())}>Auswahl aufheben</button>
          {fw.capabilities.remove && <button className="sm danger" disabled={!sel.size}
            onClick={async () => { await onBulkDelete([...sel]); setSel(new Set()) }}><Icon name="trash" size={13} /> Löschen{sel.size ? ` (${sel.size})` : ''}</button>}
          {BULK_KIND[entity] && <button className="sm primary" onClick={onBulkAdd}><Icon name="bulk" size={13} /> Mehrfach hinzufügen</button>}
          <button className="sm primary" onClick={onAdd}><Icon name="plus" size={13} /> Hinzufügen</button>
        </div>}
      </div>
      <div className="cs-filter">
        <div className="cs-search"><Icon name="search" size={15} /><input placeholder="Einträge durchsuchen …" value={q} onChange={(e) => setQ(e.target.value)} /></div>
        <ColumnPicker cols={cols} visible={visible} onChange={setCols} />
      </div>
      {!rows.length ? <Empty>Noch keine {meta.label} vorhanden.</Empty> : (
        <div className="table-wrap">
          <table className="cs-grid">
            <thead><tr>
              {mayEdit && <th style={{ width: 30 }}><input type="checkbox" checked={allSel} onChange={toggleAll} aria-label="Alle auswählen" /></th>}
              <th style={{ width: 40 }}>#</th><th>Name</th>
              {isRule ? <><th>Quelle</th><th>Ziel</th><th>Dienste</th><th>Aktion</th>{restRule && <th>Sicherheit</th>}</>
                : isNat ? <><th>Original</th><th>Übersetzt</th><th>Schnittstellen</th><th>Firewall-Regel</th></>
                : activeCols.map((c) => <th key={c.key}>{c.label}</th>)}
              <th><button className={`th-filter ${onlyFindings ? 'on' : ''}`} onClick={() => setOnlyFindings(!onlyFindings)} title="Nur Objekte mit Hinweisen">
                Konfig-Analyse <Icon name="alert" size={12} /></button></th>
              <th className="actions">Aktionen</th>
            </tr></thead>
            <tbody>
              {shown.map(({ obj, state }) => {
                const name = oname(obj)
                const idx = names.indexOf(name)
                const desc = obj.description ?? obj.Description
                const v = isRule ? anyRuleView(entity, obj) : isNat ? natView(obj) : null
                const cls = state ? `row-${state}` : v && !v.enabled ? 'row-disabled' : ''
                const expanded = restRule && open.has(name)
                return (
                  <Fragment key={`${name}-${state}`}>
                  <tr className={cls}>
                    {mayEdit && <td><input type="checkbox" disabled={!deletable({ obj, state })} checked={sel.has(name)} onChange={() => toggle(name)} aria-label={`${name} auswählen`} /></td>}
                    <td className="muted small">{state === 'remove' ? '–' : idx + 1}</td>
                    <td className="name">
                      <span className="nowrap">
                        {restRule && <button className={`ghost expander ${expanded ? 'open' : ''}`} onClick={() => toggleOpen(name)} title="Details" aria-expanded={expanded}><Icon name="chevron" size={12} /></button>}
                        <button className="link cs-name" onClick={() => onShow(obj)}>{name}</button>
                      </span>
                      {obj.isInternal && <span className="badge" style={{ marginLeft: 6 }}>System</span>}
                      {v && !v.enabled && <span className="badge st-Disable" style={{ marginLeft: 6 }}>inaktiv</span>}
                      {v?.type === 'waf' && <span className="badge b-info" style={{ marginLeft: 6 }}>WAF</span>}
                      {desc && <div className="small muted">{desc}</div>}
                      {(pendingBy[name] || draftBy[name]) && <div style={{ marginTop: 3 }}><PendingBadges pending={pendingBy[name]} draftAction={draftBy[name]} /></div>}
                    </td>
                    {isRule && v.type === 'waf' ? <td colSpan={3} className="small muted">WAF-Regel (Webserver-Schutz)</td> : isRule ? <>
                      <td><FewChips items={v.srcZones} kind="zone" /><div style={{ marginTop: 3 }}><FewChips items={v.srcNets} /></div></td>
                      <td><FewChips items={v.dstZones} kind="zone" /><div style={{ marginTop: 3 }}><FewChips items={v.dstNets} /></div></td>
                      <td><FewChips items={v.services} />{v.schedule && v.schedule !== 'All The Time' && <div className="small muted">⏱ {v.schedule}</div>}</td>
                    </> : null}
                    {isRule ? <>
                      <td className="nowrap"><span className={`badge st-${v.action}`}>{{ Accept: 'Zulassen', Drop: 'Verwerfen', Reject: 'Ablehnen' }[v.action] || v.action}</span>
                        {v.log && <div className="small muted">protokolliert</div>}</td>
                      {restRule && <td><FeatureBadges rule={obj} /></td>}
                    </> : isNat ? <>
                      <td className="small"><div><span className="muted">Quelle</span> {v.oSrc.join(', ') || 'Beliebig'}</div>
                        <div><span className="muted">Ziel</span> {v.oDst.join(', ') || 'Beliebig'}</div>
                        <div><span className="muted">Dienst</span> {v.oSvc.join(', ') || 'Beliebig'}</div></td>
                      <td className="small"><div><span className="muted">Quelle</span> {v.tSrc === 'MASQ' ? <span className="badge b-info">MASQ</span> : v.tSrc}</div>
                        <div><span className="muted">Ziel</span> {v.tDst}</div><div><span className="muted">Dienst</span> {v.tSvc}</div></td>
                      <td className="small"><div><span className="muted">Ein</span> {v.inIf || 'Beliebig'}</div><div><span className="muted">Aus</span> {v.outIf || 'Beliebig'}</div></td>
                      <td className="small">{v.linked || <span className="muted">–</span>}</td>
                    </> : activeCols.map((c) => <td key={c.key} className="small">{String(c.get(obj) ?? '') || <span className="muted">–</span>}</td>)}
                    <td><Analysis findings={findings[name]} /></td>
                    <td className="actions">
                      {mayEdit && state !== 'remove' && <>
                        {(isRule || isNat) && <>
                          <IconButton icon="up" title="Nach oben" disabled={idx <= 0}
                            onClick={() => onOp({ entity, action: 'update', name, data: obj, position: { type: 'before', ref: names[idx - 1] } })} />
                          <IconButton icon="down" title="Nach unten" disabled={idx >= names.length - 1}
                            onClick={() => onOp({ entity, action: 'update', name, data: obj, position: { type: 'after', ref: names[idx + 1] } })} />
                          <IconButton icon="power" title={v.enabled ? 'Deaktivieren' : 'Aktivieren'}
                            onClick={() => onOp({ entity, action: 'update', name, data: rest ? { ...obj, enabled: !v.enabled } : { ...obj, Status: v.enabled ? 'Disable' : 'Enable' } })} />
                        </>}
                        <IconButton icon="edit" title="Bearbeiten" onClick={() => onEdit(obj)} />
                        {fw.capabilities.remove && !obj.isInternal && <IconButton icon="trash" title="Löschen" danger onClick={() => onOp({ entity, action: 'remove', name })} />}
                      </>}
                      <IconButton icon="code" title={rest ? 'JSON anzeigen' : 'XML anzeigen'} onClick={() => onShow(obj)} />
                    </td>
                  </tr>
                  {expanded && <tr className="sf-expand"><td colSpan={99}><RuleDetails rule={obj} /></td></tr>}
                  </Fragment>
                )
              })}
            </tbody>
          </table>
          {!shown.length && <Empty>Keine Treffer.</Empty>}
        </div>
      )}
      {!fw.capabilities.remove && mayEdit && <div className="muted small" style={{ padding: '8px 16px' }}>
        Löschen ist über den Sophos-Central-Import nicht möglich – Regeln stattdessen deaktivieren oder die Firewall per REST-API anbinden.</div>}
    </div>
  )
}

function TemplatePicker({ fw, format, onApplied, onError }) {
  const [tpls] = useLoad(() => api('/templates'), [])
  const list = (tpls || []).filter((t) => t.format === format)
  if (!list.length) return null
  const apply = async (id) => {
    if (!id) return
    try { onApplied(await api(`/firewalls/${fw.id}/templates/${id}/apply`, { method: 'POST' })) } catch (e) { onError(e.message) }
  }
  return (
    <select value="" onChange={(e) => apply(e.target.value)} style={{ width: 190 }} aria-label="Vorlage anwenden">
      <option value="">Vorlage anwenden …</option>
      {list.map((t) => <option key={t.id} value={t.id}>{t.name} ({t.operations.length})</option>)}
    </select>
  )
}

// --- Editor --------------------------------------------------------------------------------------------------

export default function Editor({ fw, cfg, draft, reload }) {
  const { me } = useAuth()
  const [entity, setEntity] = useState(() => {
    const saved = store.get(`fwm.editor.entity.${cfg.format}`, null)
    return cfg.entities.some((e) => e.entity === saved) ? saved : PRIMARY_RULES[cfg.format] || cfg.entities[0].entity
  })
  const [showDraft, setShowDraft] = useState(true)
  const [editing, setEditing] = useState(null)
  const [detail, setDetail] = useState(null)
  const [bulk, setBulk] = useState(false)
  const [msg, setMsg] = useState(null)
  const [steps, setSteps] = useState(() => store.get('fwm.editor.steps', true))
  const [preview, setPreview] = useState(false)
  const [review, setReview] = useState(null)
  const [gq, setGq] = useState('')
  const [dl, setDl] = useState(false)
  const dlRef = useDismiss(dl, setDl)
  const globalRef = useDismiss(gq.length > 1, () => setGq(''))
  const fileRef = useRef(null)
  const searchRef = useRef(null)
  const [analysis] = useLoad(() => api(`/firewalls/${fw.id}/analysis`), [fw.id, fw.last_sync_at])
  const mayEdit = can(me, 'change.create', fw) && !!fw.last_sync_at
  const draftOps = draft?.operations || []
  const meta = cfg.entities.find((e) => e.entity === entity) || cfg.entities[0]
  const rest = cfg.format === 'rest'
  const total = cfg.entities.reduce((n, e) => n + e.count, 0)

  const select = (e) => { setEntity(e); store.set(`fwm.editor.entity.${cfg.format}`, e) }
  useEffect(() => {
    const onKey = (e) => { if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); searchRef.current?.focus() } }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  const pendingBy = useMemo(() => Object.fromEntries(cfg.pending.filter((p) => p.entity === entity).map((p) => [p.name, p.changes])), [cfg, entity])
  const draftBy = Object.fromEntries(draftOps.filter((o) => o.entity === entity).map((o) => [o.name, o.action]))
  const pendingEntities = new Set([...cfg.pending.map((p) => p.entity), ...draftOps.map((o) => o.entity)])
  const findings = useMemo(() => {
    const out = {}
    for (const f of analysis?.findings || []) if (f.entity === entity) (out[f.name] ||= []).push(f)
    return out
  }, [analysis, entity])
  const rows = buildRows(entity, cfg.objects, cfg.preview, showDraft, draftOps)

  const addOp = useCallback(async (op, quiet) => {
    if (!quiet) setMsg(null)
    const r = await api(`/firewalls/${fw.id}/draft/operations`, { method: 'POST', body: op })
    if (!quiet) reload()
    return r
  }, [fw.id, reload])
  const quickOp = async (op) => {
    try {
      const r = await addOp(op)
      setMsg({ kind: r.warnings.length ? 'warn' : 'ok', text: r.warnings.length ? r.warnings.join(' · ') : `In Entwurf übernommen: ${ACTION_LABEL[op.action]} „${op.name}“` })
    } catch (e) { setMsg({ kind: 'error', text: e.message }) }
  }
  const bulkDelete = async (names) => {
    const errors = []
    for (const name of names) {
      try { await addOp({ entity, action: 'remove', name }, true) } catch (e) { errors.push(`${name}: ${e.message}`) }
    }
    reload()
    setMsg({ kind: errors.length ? 'warn' : 'ok', text: `${names.length - errors.length} zum Löschen in den Entwurf übernommen${errors.length ? ` · übersprungen: ${errors.join('; ')}` : ''}` })
  }
  const startImport = async (file) => {
    if (!file) return
    setMsg({ kind: 'info', text: `Lese ${file.name} …` })
    try { setReview(await upload(`/firewalls/${fw.id}/import/review`, file)); setMsg(null) } catch (e) { setMsg({ kind: 'error', text: e.message }) }
    if (fileRef.current) fileRef.current.value = ''
  }

  const gf = gq.trim().toLowerCase()
  const globalHits = useMemo(() => {
    if (gf.length < 2) return []
    const hits = []
    for (const e of cfg.entities) {
      for (const o of cfg.objects[e.entity] || []) {
        if (searchText(o).includes(gf)) hits.push({ entity: e.entity, label: e.label, name: oname(o) })
        if (hits.length >= 30) return hits
      }
    }
    return hits
  }, [gf, cfg])

  return (
    <div className="cs-editor">
      <Sidebar cfg={cfg} entity={entity} onSelect={select} pendingEntities={pendingEntities} />
      <div className="cs-main">
        <div className="cs-head">
          <h2 className="cs-title"><Icon name="shield" size={20} className="text-accent" /> Konfigurations-Editor <span className="muted">({total} Objekte)</span>
            <span className="badge b-info">{rest ? 'REST-API' : 'Entities.xml'}</span></h2>
          <div className="cs-toolbar">
            <div className="cs-global" ref={globalRef}>
              <Icon name="search" size={15} />
              <input ref={searchRef} placeholder="Globale Suche …" value={gq} onChange={(e) => setGq(e.target.value)} />
              <kbd>Strg K</kbd>
              {globalHits.length > 0 && (
                <div className="dropdown-menu wide">
                  {globalHits.map((h) => (
                    <button key={`${h.entity}:${h.name}`} onClick={() => { select(h.entity); setGq(''); setDetail({ entity: h.entity, obj: (cfg.objects[h.entity] || []).find((o) => oname(o) === h.name) }) }}>
                      <Icon name={ENTITY_ICON[h.entity] || 'host'} size={14} /> {h.name} <span className="muted small">· {h.label}</span>
                    </button>
                  ))}
                </div>
              )}
            </div>
            <div className="right row">
              {mayEdit && <TemplatePicker fw={fw} format={cfg.format} onError={(t) => setMsg({ kind: 'error', text: t })}
                onApplied={(r) => { reload(); setMsg({ kind: r.skipped.length ? 'warn' : 'ok', text: r.skipped.length ? `Vorlage übernommen, übersprungen: ${r.skipped.join('; ')}` : 'Vorlage in den Entwurf übernommen.' }) }} />}
              {mayEdit && <>
                <input ref={fileRef} type="file" accept=".xml,.tar,.gz,application/xml" hidden onChange={(e) => startImport(e.target.files[0])} />
                <button onClick={() => fileRef.current?.click()} title="Entities.xml oder Export-Archiv (.tar) vergleichen und übernehmen">
                  <Icon name="upload" size={14} /> Import prüfen</button>
              </>}
              <button className="primary" onClick={() => setPreview(true)} title="API-Aufrufe Ihres Entwurfs"><Icon name="eye" size={14} /> Vorschau{draftOps.length ? ` (${draftOps.length})` : ''}</button>
              <div className="dropdown" ref={dlRef}>
                <button className="primary" onClick={() => setDl(!dl)} aria-expanded={dl}><Icon name="download" size={14} /> Download</button>
                {dl && <div className="dropdown-menu">
                  <button onClick={() => { setDl(false); download(`/firewalls/${fw.id}/export.json`, `Konfiguration-${fw.name}.json`) }}>Konfiguration (JSON)</button>
                  {!rest && <button onClick={() => { setDl(false); download(`/firewalls/${fw.id}/export.xml`, `Entities-${fw.name}.xml`) }}>Entities.xml (Config Studio)</button>}
                  {draftOps.length > 0 && <button onClick={() => {
                    setDl(false)
                    const blob = new Blob([JSON.stringify(draftOps.map(({ entity: e, action, name, data, position }) => ({ entity: e, action, name, data, position })), null, 2)], { type: 'application/json' })
                    const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = `Entwurf-${fw.name}.json`; a.click()
                  }}>Entwurf (JSON)</button>}
                </div>}
              </div>
            </div>
          </div>
        </div>
        {steps && <GettingStarted onHide={() => { setSteps(false); store.set('fwm.editor.steps', false) }} />}
        {msg && <div className={`alert ${msg.kind} small`}>{msg.text}</div>}
        {!fw.last_sync_at && <div className="alert warn">Noch keine Konfiguration geladen – bitte „Jetzt synchronisieren“.</div>}
        {draftOps.length > 0 && <label className="check small" style={{ margin: '0 0 8px' }}><input type="checkbox" checked={showDraft} onChange={(e) => setShowDraft(e.target.checked)} />Tabelle mit meinem Entwurf anzeigen</label>}
        {READ_ONLY_ENTITIES.has(entity) && <div className="alert info small">{meta.label} werden direkt auf der Firewall gepflegt und hier nur angezeigt.</div>}
        <EntityTable key={entity} entity={entity} meta={meta} rows={rows} fw={fw} mayEdit={mayEdit && !READ_ONLY_ENTITIES.has(entity)} pendingBy={pendingBy} draftBy={draftBy}
          findings={findings} onEdit={(obj) => setEditing({ obj })} onOp={quickOp} onShow={(obj) => setDetail({ entity, obj })}
          onBulkDelete={bulkDelete} onAdd={() => setEditing({ obj: null })} onBulkAdd={() => setBulk(true)} />
      </div>

      {editing && rest && (entity.startsWith('firewallRules')
        ? <SophosRuleEditor entity={entity} config={cfg.preview} rule={editing.obj} onClose={() => setEditing(null)} onSubmit={addOp} />
        : entity === 'natRulesIpv4'
        ? <SophosNatEditor entity={entity} config={cfg.preview} rule={editing.obj} onClose={() => setEditing(null)} onSubmit={addOp} />
        : <RestObjectEditor entity={entity} label={meta.label} config={cfg.preview} object={editing.obj} onClose={() => setEditing(null)} onSubmit={addOp} />)}
      {editing && !rest && (entity === 'FirewallRule'
        ? <RuleEditor config={cfg.preview} rule={editing.obj} onClose={() => setEditing(null)} onSubmit={addOp} />
        : <ObjectEditor entity={entity} label={meta.label} config={cfg.preview} object={editing.obj} onClose={() => setEditing(null)} onSubmit={addOp} />)}
      {detail?.obj && <ObjectDetail fw={fw} entity={detail.entity} obj={detail.obj} onClose={() => setDetail(null)} />}
      {bulk && <BulkAddModal entity={entity} label={meta.label} fmt={cfg.format} config={cfg.preview} onAdd={addOp}
        onClose={() => { setBulk(false); reload() }} />}
      {review && <ImportModal fw={fw} review={review} onClose={() => setReview(null)}
        onApplied={(r) => { setReview(null); reload(); setMsg({ kind: r.skipped.length ? 'warn' : 'ok', text: `${r.added} Objekte in den Entwurf übernommen${r.skipped.length ? ` · übersprungen: ${r.skipped.slice(0, 5).join('; ')}${r.skipped.length > 5 ? ' …' : ''}` : ''}` }) }} />}
      {preview && (
        <Modal title="Vorschau: API-Aufrufe des Entwurfs" onClose={() => setPreview(false)} wide>
          {!draftOps.length ? <Empty>Ihr Entwurf ist leer.</Empty> : <>
            <div className="muted small" style={{ marginBottom: 8 }}>So werden die Änderungen nach der Genehmigung an „{fw.name}“ gesendet ({fw.connector_label}).</div>
            {draftOps.map((op, i) => <OperationCard key={i} op={op} open />)}
          </>}
        </Modal>
      )}
    </div>
  )
}
