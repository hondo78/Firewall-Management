import { useState } from 'react'
import { searchText } from '../../components/columns'
import { anyRuleView, isRestEntity, oname } from '../../components/entities'
import Icon from '../../components/icons'
import { FeatureBadges, natView } from '../../components/SophosRules'
import { Empty } from '../../components/ui'
import { Analysis, ColumnPicker, PendingBadges, Pager, RowMenu, store, useDismiss, usePaging } from './tableParts'

/**
 * Regelliste im Aufbau von SFOS „Regeln und Richtlinien“: Reiter Firewallregeln/NAT-Regeln und IPv4/IPv6,
 * Suche, „Hinzufügen ▾“, Ausschalten/Löschen für die Auswahl, Spalten per Zahnrad, Ziehen zum Umsortieren,
 * Zeilenmenü (⋮) und Seitenfuß.
 */

const ACTION = { Accept: 'Annehmen', Drop: 'Verwerfen', Reject: 'Ablehnen' }

/** Einträge untereinander wie in SFOS; ab vier Einträgen „+N“ (vollständig im Tooltip) */
function Stack({ items, any = 'Beliebig', max = 3 }) {
  if (!items?.length) return <span className="sf-any">{any}</span>
  const rest = items.length - max
  return (
    <div className="sf-cell-list" title={items.length > 1 ? items.join('\n') : undefined}>
      {items.slice(0, max).map((i) => <div key={i}>{i}</div>)}
      {rest > 0 && <div className="muted">+{rest} weitere</div>}
    </div>
  )
}

const col = (key, label, render, hidden) => ({ key, label, render, hidden })

const RULE_COLS = (rest) => [
  col('srcZones', 'Quellzonen', (v) => <Stack items={v.srcZones} />),
  col('dstZones', 'Zielzonen', (v) => <Stack items={v.dstZones} />),
  col('srcNets', 'Quellnetzwerke', (v) => <Stack items={v.srcNets} />),
  col('dstNets', 'Zielnetzwerke', (v) => <Stack items={v.dstNets} />),
  col('services', 'Dienste', (v) => <Stack items={v.services} />),
  col('action', 'Maßnahme', (v) => <><span className={`badge st-${v.action}`}>{ACTION[v.action] || v.action}</span>
    {v.log && <div className="small muted">protokolliert</div>}</>),
  rest && col('security', 'Sicherheit', (v, obj) => <FeatureBadges rule={obj} />),
  col('schedule', 'Zeitplan', (v) => (v.schedule && v.schedule !== 'All The Time' ? v.schedule : <span className="sf-any">Jederzeit</span>), true),
  col('analysis', 'Konfig-Analyse', (v, obj, f) => <Analysis findings={f} />),
].filter(Boolean)

const NAT_COLS = [
  col('oSrc', 'Ursprüngliche Quelle', (n) => <Stack items={n.oSrc} />),
  col('tSrc', 'Übersetzte Quelle', (n) => (n.tSrc === 'MASQ' ? <span className="badge b-info">MASQ</span> : n.tSrc === 'Original' ? <span className="sf-any">Original</span> : n.tSrc)),
  col('oDst', 'Ursprüngliches Ziel', (n) => <Stack items={n.oDst} />),
  col('tDst', 'Übersetztes Ziel', (n) => (n.tDst === 'Original' ? <span className="sf-any">Original</span> : n.tDst)),
  col('oSvc', 'Ursprünglicher Dienst', (n) => <Stack items={n.oSvc} />),
  col('tSvc', 'Übersetzter Dienst', (n) => (n.tSvc === 'Original' ? <span className="sf-any">Original</span> : n.tSvc)),
  col('inIf', 'Eingehende Schnittstelle', (n) => n.inIf || <span className="sf-any">Beliebig</span>, true),
  col('outIf', 'Ausgehende Schnittstelle', (n) => n.outIf || <span className="sf-any">Beliebig</span>),
  col('linked', 'Verknüpfte Firewall-Regel', (n) => n.linked || <span className="sf-any">–</span>),
  col('analysis', 'Konfig-Analyse', (n, obj, f) => <Analysis findings={f} />),
]

/** WAF-Regeln haben kein Ziel/keine Dienste – stattdessen WAF-Verweis zeigen */
function wafCell(v, obj, key) {
  if (v?.type !== 'waf') return null
  if (key === 'dstNets') return <span className="small">WAF: {obj.wafRule?.name || '–'}</span>
  if (key === 'services') return obj.wafService != null ? <span className="small">WAF-Dienst {obj.wafService}</span> : <span className="sf-any">–</span>
  if (key === 'dstZones' || key === 'security' || key === 'schedule') return <span className="sf-any">–</span>
  if (key === 'action') return <span className="badge b-info">Webserver-Schutz</span>
  return null
}

function AddMenu({ label, items }) {
  const [open, setOpen] = useState(false)
  const ref = useDismiss(open, setOpen)
  if (items.length === 1) return <button className="primary" onClick={items[0].onClick}><Icon name="plus" size={14} /> {label}</button>
  return (
    <div className="dropdown" ref={ref}>
      <button className="primary" onClick={() => setOpen(!open)} aria-expanded={open} aria-haspopup="menu">{label} <span aria-hidden="true">▾</span></button>
      {open && <div className="dropdown-menu" role="menu">
        {items.map((it) => <button key={it.label} role="menuitem" onClick={() => { setOpen(false); it.onClick() }}>{it.label}</button>)}
      </div>}
    </div>
  )
}

export default function RuleTable({ entity, entities, rows, fw, mayEdit, pendingBy, draftBy, findings, onSelect, onEdit, onAddFor,
  onOp, onShow, onBulkDelete, onBulkToggle }) {
  const rest = isRestEntity(entity)
  const isNat = entity === 'natRulesIpv4'
  const cols = isNat ? NAT_COLS : RULE_COLS(rest)
  const [visible, setVisible] = useState(() => store.get(`fwm.cols.${entity}`, cols.filter((c) => !c.hidden).map((c) => c.key)))
  const setCols = (v) => { setVisible(v); store.set(`fwm.cols.${entity}`, v) }
  const activeCols = cols.filter((c) => visible.includes(c.key))
  const [q, setQ] = useState('')
  const [sel, setSel] = useState(new Set())
  const [drag, setDrag] = useState(null)
  const [drop, setDrop] = useState(null)

  const f = q.toLowerCase()
  const shown = rows.filter((r) => !f || searchText(r.obj).includes(f))
  const paging = usePaging(entity, shown.length)
  const names = rows.filter((r) => r.state !== 'remove').map((r) => oname(r.obj))
  const view = (obj) => (isNat ? natView(obj) : anyRuleView(entity, obj))
  const selectable = (r) => r.state !== 'remove' && !r.obj.isInternal
  const toggle = (n) => { const s = new Set(sel); s.has(n) ? s.delete(n) : s.add(n); setSel(s) }
  const pageRows = paging.slice(shown)
  const allSel = pageRows.some(selectable) && pageRows.filter(selectable).every((r) => sel.has(oname(r.obj)))
  const toggleAll = () => {
    const s = new Set(sel)
    pageRows.filter(selectable).forEach((r) => (allSel ? s.delete(oname(r.obj)) : s.add(oname(r.obj))))
    setSel(s)
  }
  const selRows = rows.filter((r) => sel.has(oname(r.obj)) && r.state !== 'remove')
  const allOff = selRows.length > 0 && selRows.every((r) => !view(r.obj).enabled)
  const setEnabled = (obj, on) => (rest ? { ...obj, enabled: on } : { ...obj, Status: on ? 'Enable' : 'Disable' })
  const canDrag = mayEdit && !f

  // Reiter wie in SFOS (nur REST: Firewall-/NAT-Regeln und IPv4/IPv6)
  const has = (e) => entities.some((x) => x.entity === e)
  const fwTab = entity.startsWith('firewallRules')
  const count = (e) => entities.find((x) => x.entity === e)?.count ?? 0

  const moveTo = (name, obj, target, where) => {
    if (!target || target === name) return
    onOp({ entity, action: 'update', name, data: obj, position: { type: where === 'above' ? 'before' : 'after', ref: target } })
  }

  const addItems = isNat
    ? [{ label: 'NAT-Regel hinzufügen', onClick: () => onAddFor(entity) }]
    : rest
      ? [{ label: 'Neue Firewall-Regel (IPv4)', onClick: () => onAddFor('firewallRulesIpv4') },
        has('firewallRulesIpv6') && { label: 'Neue Firewall-Regel (IPv6)', onClick: () => onAddFor('firewallRulesIpv6') }].filter(Boolean)
      : [{ label: 'Firewall-Regel hinzufügen', onClick: () => onAddFor(entity) }]

  return (
    <div className="panel sf-rules">
      {rest && (has('natRulesIpv4') || has('firewallRulesIpv6')) && (
        <div className="sf-tabs" role="tablist">
          <button role="tab" aria-selected={fwTab} className={fwTab ? 'on' : ''} onClick={() => onSelect('firewallRulesIpv4')}>Firewallregeln</button>
          {has('natRulesIpv4') && <button role="tab" aria-selected={isNat} className={isNat ? 'on' : ''} onClick={() => onSelect('natRulesIpv4')}>NAT-Regeln</button>}
        </div>
      )}
      {rest && fwTab && has('firewallRulesIpv6') && (
        <div className="sf-subtabs" role="tablist">
          {[['firewallRulesIpv4', 'IPv4'], ['firewallRulesIpv6', 'IPv6']].map(([e, l]) => (
            <button key={e} role="tab" aria-selected={entity === e} className={entity === e ? 'on' : ''} onClick={() => onSelect(e)}>
              {l} <span className="muted small">({count(e)})</span></button>
          ))}
        </div>
      )}
      <div className="sf-toolbar">
        <div className="cs-search"><Icon name="search" size={15} />
          <input placeholder="Suchen …" value={q} onChange={(e) => { setQ(e.target.value); paging.setPage(0) }} aria-label="Regeln durchsuchen" /></div>
        <div className="right row">
          {mayEdit && <>
            <AddMenu label={isNat ? 'NAT-Regel hinzufügen' : 'Firewall-Regel hinzufügen'} items={addItems} />
            <button disabled={!selRows.length} onClick={async () => { await onBulkToggle(selRows.map((r) => r.obj), allOff); setSel(new Set()) }}>
              {allOff ? 'Einschalten' : 'Ausschalten'}{selRows.length ? ` (${selRows.length})` : ''}</button>
            {fw.capabilities.remove && <button className="danger" disabled={!selRows.length}
              onClick={async () => { await onBulkDelete(selRows.map((r) => oname(r.obj))); setSel(new Set()) }}>Löschen</button>}
          </>}
          <ColumnPicker cols={cols} visible={visible} onChange={setCols} label="" icon="settings" />
        </div>
      </div>

      {!rows.length ? <Empty>Noch keine Regeln vorhanden.</Empty> : (
        <div className="table-wrap">
          <table className="cs-grid sf-grid">
            <thead><tr>
              {canDrag && <th style={{ width: 22 }} aria-label="Ziehen" />}
              {mayEdit && <th style={{ width: 30 }}><input type="checkbox" checked={allSel} onChange={toggleAll} aria-label="Alle auswählen" /></th>}
              <th style={{ width: 36 }}>#</th><th>Name</th>
              {activeCols.map((c) => <th key={c.key}>{c.label}</th>)}
              <th className="actions" style={{ width: 44 }} />
            </tr></thead>
            <tbody>
              {pageRows.map(({ obj, state }) => {
                const name = oname(obj)
                const idx = names.indexOf(name)
                const v = view(obj)
                const desc = obj.description ?? obj.Description
                const live = state !== 'remove'
                const dropCls = drop?.name === name ? `drop-${drop.where}` : ''
                const cls = [state && `row-${state}`, !v.enabled && 'sf-off', dropCls, drag === name && 'dragging'].filter(Boolean).join(' ')
                const edit = () => (mayEdit && live ? onEdit(obj) : onShow(obj))
                return (
                  <tr key={`${name}-${state}`} className={cls}
                    onDragOver={canDrag && drag && live ? (e) => {
                      e.preventDefault()
                      const r = e.currentTarget.getBoundingClientRect()
                      setDrop({ name, where: e.clientY < r.top + r.height / 2 ? 'above' : 'below' })
                    } : undefined}
                    onDrop={canDrag && drag ? (e) => {
                      e.preventDefault()
                      const src = rows.find((r) => oname(r.obj) === drag)
                      if (src && drop) moveTo(drag, src.obj, drop.name, drop.where)
                      setDrag(null); setDrop(null)
                    } : undefined}>
                    {canDrag && <td className="sf-handle">
                      {live && <span draggable title="Ziehen zum Verschieben" aria-label={`${name} verschieben`}
                        onDragStart={(e) => { setDrag(name); e.dataTransfer.effectAllowed = 'move'; e.dataTransfer.setData('text/plain', name) }}
                        onDragEnd={() => { setDrag(null); setDrop(null) }}>⠿</span>}</td>}
                    {mayEdit && <td><input type="checkbox" disabled={!selectable({ obj, state })} checked={sel.has(name)} onChange={() => toggle(name)} aria-label={`${name} auswählen`} /></td>}
                    <td className="muted">{live ? idx + 1 : '–'}</td>
                    <td className="name">
                      <button className="link sf-rule-name" onClick={edit} title={desc || undefined}>{name}</button>
                      {!v.enabled && <span className="badge st-Disable" style={{ marginLeft: 6 }}>aus</span>}
                      {v.type === 'waf' && <span className="badge b-info" style={{ marginLeft: 6 }}>WAF</span>}
                      {(pendingBy[name] || draftBy[name]) && <div style={{ marginTop: 3 }}><PendingBadges pending={pendingBy[name]} draftAction={draftBy[name]} /></div>}
                    </td>
                    {activeCols.map((c) => <td key={c.key}>{wafCell(isNat ? null : v, obj, c.key) ?? c.render(v, obj, findings[name])}</td>)}
                    <td className="actions">
                      <RowMenu label={name} items={[
                        mayEdit && live && { label: 'Bearbeiten', icon: 'edit', onClick: () => onEdit(obj) },
                        { label: rest ? 'Details / JSON' : 'Details / XML', icon: 'code', onClick: () => onShow(obj) },
                        mayEdit && live && { label: 'Nach oben', icon: 'up', disabled: idx <= 0, onClick: () => moveTo(name, obj, names[idx - 1], 'above') },
                        mayEdit && live && { label: 'Nach unten', icon: 'down', disabled: idx >= names.length - 1, onClick: () => moveTo(name, obj, names[idx + 1], 'below') },
                        mayEdit && live && { label: v.enabled ? 'Ausschalten' : 'Einschalten', icon: 'power', onClick: () => onOp({ entity, action: 'update', name, data: setEnabled(obj, !v.enabled) }) },
                        mayEdit && live && fw.capabilities.remove && !obj.isInternal && { label: 'Löschen', icon: 'trash', danger: true, onClick: () => onOp({ entity, action: 'remove', name }) },
                      ]} />
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
          {!shown.length && <Empty>Keine Treffer.</Empty>}
        </div>
      )}
      {rows.length > 0 && <Pager total={shown.length} {...paging} />}
      {canDrag && rows.length > 1 && <div className="muted small sf-foot-hint">Reihenfolge ändern: Zeile am Griff ⠿ ziehen – die Verschiebung landet als Änderung im Entwurf.</div>}
      {!fw.capabilities.remove && mayEdit && <div className="muted small sf-foot-hint">
        Löschen ist über den Sophos-Central-Import nicht möglich – Regeln stattdessen ausschalten oder die Firewall per REST-API anbinden.</div>}
    </div>
  )
}
