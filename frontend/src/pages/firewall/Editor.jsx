import { Fragment, useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useAuth } from '../../App'
import { ACTION_LABEL, api, can, download, upload } from '../../api'
import { BULK, BULK_KIND, parseBulk } from '../../components/bulk'
import { COLUMNS, searchText } from '../../components/columns'
import { ObjectEditor, RuleEditor } from '../../components/Editors'
import { READ_ONLY_ENTITIES, RULE_TABLE_ENTITIES, SINGLETON_ENTITIES, PRIMARY_RULES, asList, canonical, isRestEntity, oname } from '../../components/entities'
import Icon, { ENTITY_ICON } from '../../components/icons'
import { RestObjectEditor } from '../../components/RestEditors'
import { ObjectView } from '../../components/SophosPolicies'
import { FeatureBadges, RuleDetails, SophosNatEditor, SophosRuleEditor, natView } from '../../components/SophosRules'
import { WafRuleEditor } from '../../components/SophosWaf'
import { DiffTable, Empty, ErrorBox, Modal, Seg, useLoad } from '../../components/ui'
import { OperationCard } from '../FirewallView'
import { Analysis, ColumnPicker, IconButton, PendingBadges, Pager, store, useDismiss, usePaging } from './tableParts'
import RuleTable from './RuleTable'
import { t } from '../../i18n'

/** Konfigurations-Editor im Stil des Sophos Firewall Config Studio. */

const SECTION_ICON = { 'Regeln & Richtlinien': 'rule', 'Hosts & Dienste': 'host', Netzwerk: 'zone', System: 'clock', Richtlinien: 'shield',
  'Benutzer & Schnittstellen': 'user', 'Webserver-Schutz': 'globe' }


// --- Hilfen --------------------------------------------------------------------------------------------------

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

/** Chips mit Obergrenze – Rest als „+N“ (vollständige Liste im Tooltip). */
function FewChips({ items, kind, max = 4 }) {
  if (!items?.length) return <span className="chip any">{t("Beliebig")}</span>
  const rest = items.length - max
  return (
    <span className="chips" title={rest > 0 ? items.join(', ') : undefined}>
      {items.slice(0, max).map((i) => <span key={i} className={`chip ${kind || ''}`}>{i}</span>)}
      {rest > 0 && <span className="chip more">+{rest}</span>}
    </span>
  )
}

function StructuredView({ entity, obj }) {
  if (entity.startsWith('firewallRules')) return <><div style={{ marginBottom: 10 }}><FeatureBadges rule={obj} /></div><RuleDetails rule={obj} /></>
  if (entity === 'natRulesIpv4') {
    const n = natView(obj)
    const L = ({ label, children }) => <div className="sf-line"><span>{label}</span><div>{children}</div></div>
    return (
      <div className="sf-details">
        <div><h5>{t("Original")}</h5><L label={t("Quelle")}>{n.oSrc.join(', ') || t("Beliebig")}</L><L label={t("Ziel")}>{n.oDst.join(', ') || t("Beliebig")}</L><L label={t("Dienste")}>{n.oSvc.join(', ') || t("Beliebig")}</L></div>
        <div><h5>{t("Übersetzt")}</h5><L label={t("Quelle")}>{n.tSrc}</L><L label={t("Ziel")}>{n.tDst}</L><L label={t("Dienst")}>{n.tSvc}</L></div>
        <div><h5>{t("Schnittstellen")}</h5><L label={t("Eingehend")}>{n.inIf || t("Beliebig")}</L><L label={t("Ausgehend")}>{n.outIf || t("Beliebig")}</L></div>
        <div><h5>{t("Weitere")}</h5><L label={t("Status")}>{n.enabled ? t("aktiv") : t("inaktiv")}</L><L label={t("Verknüpfte Regel")}>{n.linked || '–'}</L></div>
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
      {d?.used_by?.length > 0 && <div className="alert info small">{t("Verwendet von:")} {d.used_by.join(', ')}</div>}
      {view && <div style={{ marginBottom: 10 }}><Seg options={[['view', t("Ansicht")], ['raw', raw]]} value={mode} onChange={setMode} /></div>}
      {mode === 'view' ? view : <pre className="xml">{d?.xml || t("Lade …")}</pre>}
    </Modal>
  )
}

// --- Seitenleiste --------------------------------------------------------------------------------------------

function Sidebar({ cfg, entity, onSelect, pendingEntities, hidden }) {
  const [q, setQ] = useState('')
  const [closed, setClosed] = useState(() => store.get('fwm.editor.closed', {}))
  const toggle = (s) => { const next = { ...closed, [s]: !closed[s] }; setClosed(next); store.set('fwm.editor.closed', next) }
  const f = q.toLowerCase()
  const sections = [...new Set(cfg.entities.map((e) => e.section))]
  return (
    <aside className="cs-sidebar">
      <div className="cs-menu-search"><Icon name="search" size={14} />
        <input placeholder={t("Menü durchsuchen …")} value={q} onChange={(e) => setQ(e.target.value)} /></div>
      {sections.map((s) => {
        const items = cfg.entities.filter((e) => e.section === s && !hidden.has(e.entity) && (!f || e.label.toLowerCase().includes(f)))
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
                {pendingEntities.has(e.entity) && <span className="p" title={t("Geplante Änderungen")} />}
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
    <Modal title={t("Mehrfach hinzufügen: {0}", label)} onClose={onClose} wide>
      {!result ? <div className="stack">
        <div className="small"><b>{def.label}</b> {t("– ein Eintrag je Zeile, optional „,Name“.")}</div>
        <textarea className="code" style={{ minHeight: 180 }} value={text} placeholder={def.placeholder} onChange={(e) => setText(e.target.value)} autoFocus />
        <div className="alert info small"><b>{t("Unterstützte Formate")}</b>
          <table className="bulk-help"><tbody>{def.help.map(([ex, d]) => <tr key={ex}><td className="mono">{ex}</td><td>→ {d}</td></tr>)}</tbody></table>
          {t("Tipp: Zeilen lassen sich direkt aus einer CSV-Datei einfügen.")}</div>
        {parsed.length > 0 && (
          <div className="table-wrap" style={{ maxHeight: 240, overflowY: 'auto' }}><table><tbody>
            {parsed.map((p, i) => <tr key={i}><td className="mono small">{p.line}</td>
              <td>{p.error ? <span className="text-error small">{p.error}</span> : <span className="small">{p.name}</span>}</td></tr>)}
          </tbody></table></div>
        )}
        <div className="modal-foot"><button onClick={onClose}>{t("Abbrechen")}</button>
          <button className="primary" disabled={busy || !ok.length} onClick={run}>{busy ? t("Übernehme …") : t("{0} Einträge in den Entwurf", ok.length)}</button></div>
      </div> : <div className="stack">
        <div className="alert ok">{result.added} {t("Einträge in den Entwurf übernommen.")}</div>
        {result.errors.length > 0 && <div className="alert warn small">{t("Übersprungen:")}<ul style={{ margin: '4px 0 0', paddingLeft: 18 }}>{result.errors.map((e) => <li key={e}>{e}</li>)}</ul></div>}
        <div className="modal-foot"><button className="primary" onClick={onClose}>{t("Schließen")}</button></div>
      </div>}
    </Modal>
  )
}

const IMPORT_STATUS = [['new', t("Neu")], ['changed', t("Geändert")], ['same', t("Identisch")], ['unsupported', t("Nicht übernehmbar")]]

function ImportModal({ fw, review, onClose, onApplied }) {
  const [tab, setTab] = useState(review.counts.new ? 'new' : 'changed')
  const [sel, setSel] = useState(() => new Set(review.items.filter((i) => i.status === 'new' || i.status === 'changed').map((i) => i.key)))
  const [q, setQ] = useState('')
  const [open, setOpen] = useState(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const f = q.toLowerCase()
  const list = review.items.filter((i) => i.status === tab && (!f || `${i.name} ${i.label}`.toLowerCase().includes(f)))
  const groups = list.reduce((m, i) => ({ ...m, [t(i.label)]: [...(m[t(i.label)] || []), i] }), {})
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
    <Modal title={t("Import prüfen")} onClose={onClose} wide>
      <div className="stack">
        <div className="muted small">{t("Vergleich der hochgeladenen Konfiguration")}{review.api_version && t(" (API-Version {0})", review.api_version)} {t("mit dem aktuellen Stand von „")}{fw.name}{t("“. Ausgewählte Objekte landen in Ihrem Entwurf und werden erst nach Vier-Augen-Freigabe ausgerollt. Die Datei wird nicht gespeichert.")}</div>
        <div className="seg" style={{ alignSelf: 'flex-start' }}>
          {IMPORT_STATUS.map(([k, l]) => <button key={k} className={tab === k ? 'active' : ''} onClick={() => setTab(k)}>{l} ({review.counts[k]})</button>)}
        </div>
        <input placeholder={t("Filtern …")} value={q} onChange={(e) => setQ(e.target.value)} />
        <div className="table-wrap" style={{ maxHeight: 420, overflowY: 'auto' }}>
          {!list.length ? <Empty>{t("Keine Einträge.")}</Empty> : <table><tbody>
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
                      <td className="small muted">{i.reason || (i.diff?.length ? t("{0} Feld(er) abweichend", i.diff.length) : '')}</td>
                      <td className="actions">{i.diff?.length > 0 && <button className="ghost sm" onClick={() => setOpen(open === i.key ? null : i.key)}>{t("Unterschiede")}</button>}</td>
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
          <button onClick={onClose}>{t("Abbrechen")}</button>
          <button className="primary" disabled={busy || !sel.size} onClick={apply}>{busy ? t("Übernehme …") : t("{0} Objekte in den Entwurf", sel.size)}</button>
        </div>
      </div>
    </Modal>
  )
}

function GettingStarted({ onHide }) {
  const steps = [
    [t("Objekte bearbeiten"), t("Links einen Objekttyp wählen und Hosts, Dienste oder Regeln anlegen, ändern oder löschen – alles landet im Entwurf.")],
    [t("Konfiguration importieren"), t("Optional eine Entities.xml (z. B. aus Config Studio) prüfen und Objekte übernehmen.")],
    [t("Vorschau & Einreichen"), t("API-Aufrufe in der Vorschau prüfen, mit Begründung einreichen – eine zweite Person genehmigt.")],
    [t("Ausrollen"), t("Nach der Freigabe rollt das Tool die Änderung per API aus und prüft vorher auf Abweichungen.")],
  ]
  return (
    <div className="cs-steps">
      <div className="row between"><b className="small"><Icon name="bulb" size={14} /> {t("Erste Schritte")}</b>
        <button className="link small" onClick={onHide}>{t("× Ausblenden")}</button></div>
      <div className="cs-steps-row">
        {steps.map(([t, d], i) => (
          <div key={t} className="cs-step"><span className="num">{i + 1}</span><div><b className="small">{t}</b><div className="muted small">{d}</div></div></div>
        ))}
      </div>
    </div>
  )
}

// --- Tabelle -------------------------------------------------------------------------------------------------

function EntityTable({ entity, meta, rows, fw, mayEdit, pendingBy, draftBy, findings, onEdit, onOp, onShow, onBulkDelete, onAdd, onBulkAdd }) {
  const rest = isRestEntity(entity)
  const single = SINGLETON_ENTITIES.has(entity)
  const cols = COLUMNS[entity] || []
  const [visible, setVisible] = useState(() => store.get(`fwm.cols.${entity}`, cols.filter((c) => !c.hidden).map((c) => c.key)))
  const [q, setQ] = useState('')
  const [onlyFindings, setOnlyFindings] = useState(false)
  const [sel, setSel] = useState(new Set())
  const f = q.toLowerCase()
  const shown = rows.filter((r) => (!f || searchText(r.obj).includes(f)) && (!onlyFindings || findings[oname(r.obj)]?.length))
  const paging = usePaging(entity, shown.length)
  const pageRows = paging.slice(shown)
  const names = rows.filter((r) => r.state !== 'remove').map((r) => oname(r.obj))
  const deletable = (r) => r.state !== 'remove' && !r.obj.isInternal && !single
  const toggle = (n) => { const s = new Set(sel); s.has(n) ? s.delete(n) : s.add(n); setSel(s) }
  const allSel = pageRows.some(deletable) && pageRows.filter(deletable).every((r) => sel.has(oname(r.obj)))
  const toggleAll = () => {
    const s = new Set(sel)
    pageRows.filter(deletable).forEach((r) => (allSel ? s.delete(oname(r.obj)) : s.add(oname(r.obj))))
    setSel(s)
  }
  const setCols = (v) => { setVisible(v); store.set(`fwm.cols.${entity}`, v) }
  const activeCols = cols.filter((c) => visible.includes(c.key))

  return (
    <div className="panel cs-table">
      <div className="panel-head">
        <Icon name={ENTITY_ICON[entity] || 'host'} size={18} className="text-accent" />
        <h3>{meta.label} <span className="muted" style={{ fontWeight: 400 }}>({rows.filter((r) => r.state !== 'remove').length})</span></h3>
        {mayEdit && !single && <div className="right row">
          <button className="sm" disabled={!sel.size} onClick={() => setSel(new Set())}>{t("Auswahl aufheben")}</button>
          {fw.capabilities.remove && <button className="sm danger" disabled={!sel.size}
            onClick={async () => { await onBulkDelete([...sel]); setSel(new Set()) }}><Icon name="trash" size={13} /> {t("Löschen")}{sel.size ? ` (${sel.size})` : ''}</button>}
          {BULK_KIND[entity] && <button className="sm primary" onClick={onBulkAdd}><Icon name="bulk" size={13} /> {t("Mehrfach hinzufügen")}</button>}
          <button className="sm primary" onClick={onAdd}><Icon name="plus" size={13} /> {t("Hinzufügen")}</button>
        </div>}
      </div>
      <div className="cs-filter">
        <div className="cs-search"><Icon name="search" size={15} /><input placeholder={t("Einträge durchsuchen …")} value={q} onChange={(e) => { setQ(e.target.value); paging.setPage(0) }} /></div>
        <ColumnPicker cols={cols} visible={visible} onChange={setCols} />
      </div>
      {!rows.length ? <Empty>{t("Noch keine")} {meta.label} {t("vorhanden.")}</Empty> : (
        <div className="table-wrap">
          <table className="cs-grid">
            <thead><tr>
              {mayEdit && <th style={{ width: 30 }}><input type="checkbox" checked={allSel} onChange={toggleAll} aria-label={t("Alle auswählen")} /></th>}
              <th style={{ width: 40 }}>#</th><th>{t("Name")}</th>
              {activeCols.map((c) => <th key={c.key}>{c.label}</th>)}
              <th><button className={`th-filter ${onlyFindings ? 'on' : ''}`} onClick={() => setOnlyFindings(!onlyFindings)} title={t("Nur Objekte mit Hinweisen")}>
                {t("Konfig-Analyse")} <Icon name="alert" size={12} /></button></th>
              <th className="actions">{t("Aktionen")}</th>
            </tr></thead>
            <tbody>
              {pageRows.map(({ obj, state }) => {
                const name = oname(obj)
                const idx = names.indexOf(name)
                const desc = obj.description ?? obj.Description
                return (
                  <tr key={`${name}-${state}`} className={state ? `row-${state}` : ''}>
                    {mayEdit && <td><input type="checkbox" disabled={!deletable({ obj, state })} checked={sel.has(name)} onChange={() => toggle(name)} aria-label={t("{0} auswählen", name)} /></td>}
                    <td className="muted small">{state === 'remove' ? '–' : idx + 1}</td>
                    <td className="name">
                      <button className="link cs-name" onClick={() => (mayEdit && state !== 'remove' ? onEdit(obj) : onShow(obj))}>{name}</button>
                      {obj.isInternal && <span className="badge" style={{ marginLeft: 6 }}>{t("System")}</span>}
                      {desc && <div className="small muted">{desc}</div>}
                      {(pendingBy[name] || draftBy[name]) && <div style={{ marginTop: 3 }}><PendingBadges pending={pendingBy[name]} draftAction={draftBy[name]} /></div>}
                    </td>
                    {activeCols.map((c) => <td key={c.key} className="small">{String(c.get(obj) ?? '') || <span className="muted">–</span>}</td>)}
                    <td><Analysis findings={findings[name]} /></td>
                    <td className="actions">
                      {mayEdit && state !== 'remove' && <>
                        <IconButton icon="edit" title={t("Bearbeiten")} onClick={() => onEdit(obj)} />
                        {fw.capabilities.remove && !obj.isInternal && !single && <IconButton icon="trash" title={t("Löschen")} danger onClick={() => onOp({ entity, action: 'remove', name })} />}
                      </>}
                      <IconButton icon="code" title={rest ? t("Details / JSON") : t("Details / XML")} onClick={() => onShow(obj)} />
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
          {!shown.length && <Empty>{t("Keine Treffer.")}</Empty>}
        </div>
      )}
      {rows.length > 0 && <Pager total={shown.length} {...paging} />}
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
    <select value="" onChange={(e) => apply(e.target.value)} style={{ width: 190 }} aria-label={t("Vorlage anwenden")}>
      <option value="">{t("Vorlage anwenden …")}</option>
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

  const select = (e) => { setEntity(e); setEditing(null); store.set(`fwm.editor.entity.${cfg.format}`, e) }
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
      setMsg({ kind: r.warnings.length ? 'warn' : 'ok', text: r.warnings.length ? r.warnings.join(' · ') : t("In Entwurf übernommen: {0} „{1}“", ACTION_LABEL[op.action], op.name) })
    } catch (e) { setMsg({ kind: 'error', text: e.message }) }
  }
  const bulkDelete = async (names) => {
    const errors = []
    for (const name of names) {
      try { await addOp({ entity, action: 'remove', name }, true) } catch (e) { errors.push(`${name}: ${e.message}`) }
    }
    reload()
    setMsg({ kind: errors.length ? 'warn' : 'ok', text: t("{0} zum Löschen in den Entwurf übernommen{1}", names.length - errors.length, errors.length ? t(" · übersprungen: {0}", errors.join('; ')) : '') })
  }
  const bulkToggle = async (objs, on) => {
    const errors = []
    for (const obj of objs) {
      const data = isRestEntity(entity) ? { ...obj, enabled: on } : { ...obj, Status: on ? 'Enable' : 'Disable' }
      try { await addOp({ entity, action: 'update', name: oname(obj), data }, true) } catch (e) { errors.push(`${oname(obj)}: ${e.message}`) }
    }
    reload()
    setMsg({ kind: errors.length ? 'warn' : 'ok', text: t(on ? "{0} Regeln eingeschaltet (Entwurf){1}" : "{0} Regeln ausgeschaltet (Entwurf){1}", objs.length - errors.length, errors.length ? t(" · übersprungen: {0}", errors.join('; ')) : '') })
  }
  const addFor = (e) => { if (e !== entity) select(e); setEditing({ obj: null }) }
  // Firewall-/NAT-Regeln (REST) werden wie in SFOS als ganze Seite bearbeitet
  // Bearbeitet wird ggf. eine andere Entität als die angezeigte (WAF-Regel aus der Firewall-Regelliste)
  const editEntity = editing?.entity || entity
  const pageEdit = editing && rest && (editEntity.startsWith('firewallRules') || editEntity === 'natRulesIpv4' || editEntity === 'wafRules')
  const editRule = (obj) => {
    // WAF-Regel mit XML-API-Zugang → vollständiges WAF-Formular (Daten aus der XML-API)
    if (obj.ruleType === 'waf' && fw.waf_xml) {
      const waf = (cfg.preview.wafRules || []).find((w) => w.Name === obj.name)
      if (waf) { setEditing({ obj: waf, entity: 'wafRules' }); return }
    }
    setEditing({ obj })
  }
  const ruleList = RULE_TABLE_ENTITIES.has(entity) || entity === 'natRulesIpv4'
  const startImport = async (file) => {
    if (!file) return
    setMsg({ kind: 'info', text: t("Lese {0} …", file.name) })
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
      <Sidebar cfg={cfg} entity={entity} onSelect={select} pendingEntities={pendingEntities}
        hidden={new Set(fw.waf_xml ? [] : ['wafRules'])} />
      <div className="cs-main">
        <div className="cs-head">
          <h2 className="cs-title"><Icon name="shield" size={20} className="text-accent" /> {t("Konfigurations-Editor")} <span className="muted">({total} {t("Objekte)")}</span>
            <span className="badge b-info">{rest ? 'REST-API' : 'Entities.xml'}</span></h2>
          <div className="cs-toolbar">
            <div className="cs-global" ref={globalRef}>
              <Icon name="search" size={15} />
              <input ref={searchRef} placeholder={t("Globale Suche …")} value={gq} onChange={(e) => setGq(e.target.value)} />
              <kbd>{t("Strg K")}</kbd>
              {globalHits.length > 0 && (
                <div className="dropdown-menu wide">
                  {globalHits.map((h) => (
                    <button key={`${h.entity}:${h.name}`} onClick={() => { select(h.entity); setGq(''); setDetail({ entity: h.entity, obj: (cfg.objects[h.entity] || []).find((o) => oname(o) === h.name) }) }}>
                      <Icon name={ENTITY_ICON[h.entity] || 'host'} size={14} /> {h.name} <span className="muted small">· {t(h.label)}</span>
                    </button>
                  ))}
                </div>
              )}
            </div>
            <div className="right row">
              {mayEdit && <TemplatePicker fw={fw} format={cfg.format} onError={(t) => setMsg({ kind: 'error', text: t })}
                onApplied={(r) => { reload(); setMsg({ kind: r.skipped.length ? 'warn' : 'ok', text: r.skipped.length ? t("Vorlage übernommen, übersprungen: {0}", r.skipped.join('; ')) : t("Vorlage in den Entwurf übernommen.") }) }} />}
              {mayEdit && <>
                <input ref={fileRef} type="file" accept=".xml,.tar,.gz,application/xml" hidden onChange={(e) => startImport(e.target.files[0])} />
                <button onClick={() => fileRef.current?.click()} title={t("Entities.xml oder Export-Archiv (.tar) vergleichen und übernehmen")}>
                  <Icon name="upload" size={14} /> {t("Import prüfen")}</button>
              </>}
              <button className="primary" onClick={() => setPreview(true)} title={t("API-Aufrufe Ihres Entwurfs")}><Icon name="eye" size={14} /> {t("Vorschau")}{draftOps.length ? ` (${draftOps.length})` : ''}</button>
              <div className="dropdown" ref={dlRef}>
                <button className="primary" onClick={() => setDl(!dl)} aria-expanded={dl}><Icon name="download" size={14} /> {t("Download")}</button>
                {dl && <div className="dropdown-menu">
                  <button onClick={() => { setDl(false); download(`/firewalls/${fw.id}/export.json`, `Konfiguration-${fw.name}.json`) }}>{t("Konfiguration (JSON)")}</button>
                  {!rest && <button onClick={() => { setDl(false); download(`/firewalls/${fw.id}/export.xml`, `Entities-${fw.name}.xml`) }}>{t("Entities.xml (Config Studio)")}</button>}
                  {draftOps.length > 0 && <button onClick={() => {
                    setDl(false)
                    const blob = new Blob([JSON.stringify(draftOps.map(({ entity: e, action, name, data, position }) => ({ entity: e, action, name, data, position })), null, 2)], { type: 'application/json' })
                    const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = t("Entwurf-{0}.json", fw.name); a.click()
                  }}>{t("Entwurf (JSON)")}</button>}
                </div>}
              </div>
            </div>
          </div>
        </div>
        {steps && <GettingStarted onHide={() => { setSteps(false); store.set('fwm.editor.steps', false) }} />}
        {msg && <div className={`alert ${msg.kind} small`}>{msg.text}</div>}
        {!fw.last_sync_at && <div className="alert warn">{t("Noch keine Konfiguration geladen – bitte „Jetzt synchronisieren“.")}</div>}
        {draftOps.length > 0 && <label className="check small" style={{ margin: '0 0 8px' }}><input type="checkbox" checked={showDraft} onChange={(e) => setShowDraft(e.target.checked)} />{t("Tabelle mit meinem Entwurf anzeigen")}</label>}
        {READ_ONLY_ENTITIES.has(entity) && <div className="alert info small">{meta.label} {t("werden direkt auf der Firewall gepflegt und hier nur angezeigt.")}</div>}
        {pageEdit ? (editEntity === 'wafRules'
          ? <WafRuleEditor key={`waf:${editing.obj ? oname(editing.obj) : t("neu")}`} page config={cfg.preview} rule={editing.obj} onClose={() => setEditing(null)} onSubmit={addOp} />
          : entity === 'natRulesIpv4'
          ? <SophosNatEditor key={`${entity}:${editing.obj ? oname(editing.obj) : t("neu")}`} page entity={entity} config={cfg.preview} rule={editing.obj} onClose={() => setEditing(null)} onSubmit={addOp} />
          : <SophosRuleEditor key={`${entity}:${editing.obj ? oname(editing.obj) : t("neu")}`} page entity={entity} config={cfg.preview} rule={editing.obj} onClose={() => setEditing(null)} onSubmit={addOp}
            wafXml={fw.waf_xml} mayConfigure={!!fw.may_edit_connection} />)
        : ruleList
          ? <RuleTable key={entity} entity={entity} entities={cfg.entities} rows={rows} fw={fw} mayEdit={mayEdit} pendingBy={pendingBy} draftBy={draftBy}
            findings={findings} onSelect={select} onEdit={editRule} onAddFor={addFor}
            onAddWaf={fw.waf_xml ? () => setEditing({ obj: null, entity: 'wafRules' }) : null} onOp={quickOp}
            onShow={(obj) => setDetail({ entity, obj })} onBulkDelete={bulkDelete} onBulkToggle={bulkToggle} />
          : <EntityTable key={entity} entity={entity} meta={meta} rows={rows} fw={fw} mayEdit={mayEdit && !READ_ONLY_ENTITIES.has(entity)} pendingBy={pendingBy} draftBy={draftBy}
            findings={findings} onEdit={(obj) => setEditing({ obj })} onOp={quickOp} onShow={(obj) => setDetail({ entity, obj })}
            onBulkDelete={bulkDelete} onAdd={() => setEditing({ obj: null })} onBulkAdd={() => setBulk(true)} />}
      </div>

      {editing && rest && !pageEdit && <RestObjectEditor entity={editEntity} label={meta.label} config={cfg.preview} object={editing.obj} onClose={() => setEditing(null)} onSubmit={addOp} />}
      {editing && !rest && (entity === 'FirewallRule'
        ? <RuleEditor config={cfg.preview} rule={editing.obj} onClose={() => setEditing(null)} onSubmit={addOp} />
        : <ObjectEditor entity={entity} label={meta.label} config={cfg.preview} object={editing.obj} onClose={() => setEditing(null)} onSubmit={addOp} />)}
      {detail?.obj && <ObjectDetail fw={fw} entity={detail.entity} obj={detail.obj} onClose={() => setDetail(null)} />}
      {bulk && <BulkAddModal entity={entity} label={meta.label} fmt={cfg.format} config={cfg.preview} onAdd={addOp}
        onClose={() => { setBulk(false); reload() }} />}
      {review && <ImportModal fw={fw} review={review} onClose={() => setReview(null)}
        onApplied={(r) => { setReview(null); reload(); setMsg({ kind: r.skipped.length ? 'warn' : 'ok', text: t("{0} Objekte in den Entwurf übernommen{1}", r.added, r.skipped.length ? t(" · übersprungen: {0}{1}", r.skipped.slice(0, 5).join('; '), r.skipped.length > 5 ? ' …' : '') : '') }) }} />}
      {preview && (
        <Modal title={t("Vorschau: API-Aufrufe des Entwurfs")} onClose={() => setPreview(false)} wide>
          {!draftOps.length ? <Empty>{t("Ihr Entwurf ist leer.")}</Empty> : <>
            <div className="muted small" style={{ marginBottom: 8 }}>{t("So werden die Änderungen nach der Genehmigung an „")}{fw.name}{t("“ gesendet (")}{fw.connector_label}).</div>
            {draftOps.map((op, i) => <OperationCard key={i} op={op} open />)}
          </>}
        </Modal>
      )}
    </div>
  )
}
